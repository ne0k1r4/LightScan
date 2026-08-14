// LightScan Go Scanner — high-performance TCP connect scanner companion binary.
//
// The Go engine is deliberately limited to authorized TCP inventory work. It
// uses a bounded queue, host-fair scheduling, explicit rate and retry controls,
// and NDJSON output so the Python CLI can retain one report contract.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result is emitted as one NDJSON object per scanned port when --json is set.
type Result struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Status   string `json:"status"` // open | closed | filtered | skipped | error
	Banner   string `json:"banner,omitempty"`
	Ms       int64  `json:"ms"`
	Attempts int    `json:"attempts"`
}

type Summary struct {
	Type    string      `json:"type"`
	Metrics scanMetrics `json:"metrics"`
	Elapsed float64     `json:"elapsed"`
}

type scanMetrics struct {
	Scheduled int `json:"scheduled"`
	Attempts  int `json:"attempts"`
	Open      int `json:"open"`
	Closed    int `json:"closed"`
	Filtered  int `json:"filtered"`
	Errors    int `json:"errors"`
	Skipped   int `json:"skipped"`
	Retries   int `json:"retries"`
}

func (metrics *scanMetrics) add(result Result) {
	metrics.Scheduled++
	metrics.Attempts += result.Attempts
	if result.Attempts > 1 {
		metrics.Retries += result.Attempts - 1
	}
	switch result.Status {
	case "open":
		metrics.Open++
	case "closed":
		metrics.Closed++
	case "filtered":
		metrics.Filtered++
	case "skipped":
		metrics.Skipped++
	default:
		metrics.Errors++
	}
}

type job struct {
	host string
	port int
}

type config struct {
	timeout            time.Duration
	concurrency        int
	perHostConcurrency int
	maxRate            float64
	retries            int
	hostTimeout        time.Duration
	grabBanners        bool
}

var top100 = []int{
	20, 21, 22, 23, 25, 53, 69, 79, 80, 88, 110, 111, 119, 123, 135, 137,
	138, 139, 143, 161, 389, 443, 445, 465, 514, 587, 636, 873, 990, 993,
	995, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 3000, 3128, 3306, 3389,
	4443, 5000, 5432, 5800, 5900, 6379, 6443, 7001, 7443, 8000, 8080, 8081,
	8443, 8888, 9000, 9090, 9200, 9300, 9443, 10000, 27017,
}

func parsePorts(spec string) ([]int, error) {
	if strings.EqualFold(spec, "top100") || strings.EqualFold(spec, "top-100") {
		return append([]int(nil), top100...), nil
	}
	if strings.TrimSpace(spec) == "" {
		return nil, fmt.Errorf("port specification cannot be empty")
	}

	ports := make([]int, 0)
	seen := map[int]bool{}
	for _, rawPart := range strings.Split(spec, ",") {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			return nil, fmt.Errorf("empty port entry in %q", spec)
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo > hi || !validPort(lo) || !validPort(hi) {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for port := lo; port <= hi; port++ {
				if !seen[port] {
					ports = append(ports, port)
					seen[port] = true
				}
			}
			continue
		}

		port, err := strconv.Atoi(part)
		if err != nil || !validPort(port) {
			return nil, fmt.Errorf("invalid port: %s", part)
		}
		if !seen[port] {
			ports = append(ports, port)
			seen[port] = true
		}
	}
	return ports, nil
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}

// parseTargets accepts IPv4 and IPv6 literals, expands bounded IPv4 CIDRs,
// and accepts IPv6 /128 CIDRs as a literal alias. Broader IPv6 CIDRs remain
// intentionally rejected to prevent accidental massive expansion.
func parseTargets(spec string, maxTargets int) ([]string, error) {
	if maxTargets < 1 {
		return nil, fmt.Errorf("max targets must be at least 1")
	}
	hosts, err := parseTargetSpec(strings.TrimSpace(spec), maxTargets)
	if err != nil {
		return nil, err
	}
	return dedupe(hosts), nil
}

func parseTargetSpec(spec string, maxTargets int) ([]string, error) {
	if strings.HasPrefix(spec, "[") && strings.HasSuffix(spec, "]") {
		spec = strings.TrimSuffix(strings.TrimPrefix(spec, "["), "]")
	} else if strings.HasPrefix(spec, "[") || strings.HasSuffix(spec, "]") {
		return nil, fmt.Errorf("invalid bracketed target: %s", spec)
	}
	if spec == "" {
		return nil, fmt.Errorf("target specification cannot be empty")
	}
	if strings.HasPrefix(spec, "file:") {
		return parseTargetFile(spec[5:], maxTargets)
	}
	if strings.Contains(spec, "/") {
		return parseCIDR(spec, maxTargets)
	}
	if strings.Contains(spec, "-") {
		if hosts, ok, err := parseIPv4Range(spec, maxTargets); ok || err != nil {
			return hosts, err
		}
	}
	return []string{spec}, nil
}

func parseTargetFile(path string, maxTargets int) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hosts []string
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		remaining := maxTargets - len(hosts)
		if remaining < 1 {
			return nil, fmt.Errorf("target limit of %d exceeded while reading %s", maxTargets, path)
		}
		expanded, err := parseTargetSpec(line, remaining)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		hosts = append(hosts, expanded...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(hosts) > maxTargets {
		return nil, fmt.Errorf("target limit of %d exceeded while reading %s", maxTargets, path)
	}
	return hosts, nil
}

func parseCIDR(spec string, maxTargets int) ([]string, error) {
	ip, network, err := net.ParseCIDR(spec)
	if err != nil {
		return nil, err
	}
	ipv4 := ip.To4()
	ones, bits := network.Mask.Size()
	if ipv4 == nil {
		if bits == 128 && ones == 128 {
			return []string{network.IP.String()}, nil
		}
		return nil, fmt.Errorf("Go engine accepts IPv6 CIDR targets only as /128 literals")
	}
	if bits != 32 {
		return nil, fmt.Errorf("invalid IPv4 CIDR: %s", spec)
	}

	total := uint64(1) << uint(32-ones)
	usable := total
	if ones <= 30 {
		usable -= 2
	}
	if usable > uint64(maxTargets) {
		return nil, fmt.Errorf("%q expands to %d targets, above the %d target limit", spec, usable, maxTargets)
	}

	start := binary.BigEndian.Uint32(network.IP.To4())
	end := start + uint32(total-1)
	hosts := make([]string, 0, usable)
	for value := start; ; value++ {
		if ones > 30 || (value != start && value != end) {
			hosts = append(hosts, uint32ToIPv4(value))
		}
		if value == end {
			break
		}
	}
	return hosts, nil
}

func parseIPv4Range(spec string, maxTargets int) ([]string, bool, error) {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return nil, false, nil
	}
	base := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	if base == nil {
		return nil, false, nil
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, true, fmt.Errorf("invalid IPv4 range: %s", spec)
	}
	start := int(base[3])
	if end < start || end > 255 {
		return nil, true, fmt.Errorf("invalid IPv4 range: %s", spec)
	}
	count := end - start + 1
	if count > maxTargets {
		return nil, true, fmt.Errorf("%q expands to %d targets, above the %d target limit", spec, count, maxTargets)
	}
	hosts := make([]string, 0, count)
	for octet := start; octet <= end; octet++ {
		hosts = append(hosts, fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], octet))
	}
	return hosts, true, nil
}

func uint32ToIPv4(value uint32) string {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)).String()
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

var probes = map[int][]byte{
	21:    nil,
	22:    nil,
	25:    []byte("EHLO lightscan.local\r\n"),
	80:    []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	443:   []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	6379:  []byte("*1\r\n$4\r\nINFO\r\n"),
	8080:  []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	8443:  []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	9200:  []byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"),
	27017: {0x3a, 0x00, 0x00, 0x00, 0xd4, 0x07},
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	readTimeout := timeout / 2
	if readTimeout < 50*time.Millisecond {
		readTimeout = 50 * time.Millisecond
	}
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	buffer := make([]byte, 512)
	count, _ := conn.Read(buffer)
	banner := strings.TrimSpace(string(buffer[:count]))
	if banner == "" {
		if probe, ok := probes[port]; ok && len(probe) > 0 {
			conn.SetWriteDeadline(time.Now().Add(readTimeout))
			_, _ = conn.Write(probe)
			conn.SetReadDeadline(time.Now().Add(readTimeout))
			count, _ = conn.Read(buffer)
			banner = strings.TrimSpace(string(buffer[:count]))
		}
	}

	clean := make([]byte, 0, len(banner))
	for _, value := range []byte(banner) {
		if value >= 32 && value < 127 {
			clean = append(clean, value)
		}
	}
	if len(clean) > 200 {
		clean = clean[:200]
	}
	return string(clean)
}

type rateGate struct {
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

func newRateGate(maxRate float64) *rateGate {
	if maxRate <= 0 {
		return &rateGate{}
	}
	return &rateGate{interval: time.Duration(float64(time.Second) / maxRate)}
}

func (gate *rateGate) wait() {
	if gate.interval <= 0 {
		return
	}
	gate.mu.Lock()
	now := time.Now()
	scheduled := now
	if gate.next.After(now) {
		scheduled = gate.next
	}
	gate.next = scheduled.Add(gate.interval)
	gate.mu.Unlock()
	if delay := time.Until(scheduled); delay > 0 {
		time.Sleep(delay)
	}
}

type hostLimiter struct {
	perHost     int
	hostTimeout time.Duration
	mu          sync.Mutex
	states      map[string]*hostState
}

type hostState struct {
	semaphore chan struct{}
	deadline  time.Time
}

func newHostLimiter(perHost int, hostTimeout time.Duration) *hostLimiter {
	return &hostLimiter{
		perHost:     perHost,
		hostTimeout: hostTimeout,
		states:      make(map[string]*hostState),
	}
}

func (limiter *hostLimiter) acquire(host string) (*hostState, bool) {
	limiter.mu.Lock()
	state := limiter.states[host]
	if state == nil {
		state = &hostState{semaphore: make(chan struct{}, limiter.perHost)}
		if limiter.hostTimeout > 0 {
			state.deadline = time.Now().Add(limiter.hostTimeout)
		}
		limiter.states[host] = state
	}
	limiter.mu.Unlock()

	if !state.deadline.IsZero() && time.Now().After(state.deadline) {
		return state, false
	}
	state.semaphore <- struct{}{}
	if !state.deadline.IsZero() && time.Now().After(state.deadline) {
		<-state.semaphore
		return state, false
	}
	return state, true
}

func (limiter *hostLimiter) release(state *hostState) {
	<-state.semaphore
}

func scanPort(host string, port int, cfg config, deadline time.Time, gate *rateGate) Result {
	result := Result{Host: host, Port: port, Status: "error"}
	for attempt := 0; attempt <= cfg.retries; attempt++ {
		if !deadline.IsZero() && time.Now().After(deadline) {
			result.Status = "skipped"
			return result
		}
		if attempt > 0 {
			time.Sleep(minDuration(50*time.Millisecond*time.Duration(1<<(attempt-1)), 500*time.Millisecond))
		}

		gate.wait()
		result.Attempts++
		started := time.Now()
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg.timeout)
		result.Ms = time.Since(started).Milliseconds()
		if err != nil {
			result.Status = classifyError(err)
			if result.Status == "filtered" && attempt < cfg.retries {
				continue
			}
			return result
		}

		if cfg.grabBanners {
			result.Banner = grabBanner(connection, port, cfg.timeout)
		}
		_ = connection.Close()
		result.Status = "open"
		return result
	}
	return result
}

func classifyError(err error) string {
	if errors, ok := err.(*net.OpError); ok && errors.Timeout() {
		return "filtered"
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "connection refused") {
		return "closed"
	}
	if strings.Contains(text, "timed out") || strings.Contains(text, "no route to host") || strings.Contains(text, "network is unreachable") {
		return "filtered"
	}
	return "error"
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func boundedBuffer(concurrency int) int {
	if concurrency < 32 {
		return 64
	}
	if concurrency > 2048 {
		return 4096
	}
	return concurrency * 2
}

func main() {
	target := flag.String("t", "", "Target: IPv4/IPv6 literal, IPv4 CIDR, range, hostname, or file:path")
	portSpec := flag.String("p", "top100", "Ports: 22,80,443 | 1-1024 | top100")
	concurrency := flag.Int("c", 1000, "Maximum concurrent connections")
	perHostConcurrency := flag.Int("per-host-concurrency", 64, "Maximum concurrent connections per host")
	hostGroup := flag.Int("host-group", 256, "Hosts scheduled per fair-scan group")
	timeoutMs := flag.Int("T", 1500, "Connection timeout in milliseconds")
	maxRate := flag.Float64("max-rate", 0, "Maximum connection starts per second; 0 disables the cap")
	retries := flag.Int("retries", 1, "Retries for timeout or filtered outcomes")
	hostTimeout := flag.Duration("host-timeout", 0, "Maximum wall time per host, for example 15s; 0 disables")
	maxTargets := flag.Int("max-targets", 65536, "Maximum expanded target count")
	outputJSON := flag.Bool("json", false, "Output NDJSON (one result per line)")
	summaryJSON := flag.Bool("summary", false, "Emit one NDJSON completion summary after results")
	openOnly := flag.Bool("open", false, "Only print open ports")
	noBanner := flag.Bool("no-banner", false, "Skip banner grabbing")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: -t <target> is required")
		flag.Usage()
		os.Exit(2)
	}
	if *concurrency < 1 || *perHostConcurrency < 1 || *hostGroup < 1 || *timeoutMs < 1 || *retries < 0 || *maxRate < 0 {
		fmt.Fprintln(os.Stderr, "error: concurrency, host group, timeout, retries, and rate controls are invalid")
		os.Exit(2)
	}

	hosts, err := parseTargets(*target, *maxTargets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing targets: %v\n", err)
		os.Exit(2)
	}
	ports, err := parsePorts(*portSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing ports: %v\n", err)
		os.Exit(2)
	}

	cfg := config{
		timeout:            time.Duration(*timeoutMs) * time.Millisecond,
		concurrency:        *concurrency,
		perHostConcurrency: *perHostConcurrency,
		maxRate:            *maxRate,
		retries:            *retries,
		hostTimeout:        *hostTimeout,
		grabBanners:        !*noBanner,
	}
	jobs := make(chan job, boundedBuffer(cfg.concurrency))
	results := make(chan Result, boundedBuffer(cfg.concurrency))
	gate := newRateGate(cfg.maxRate)
	limiter := newHostLimiter(cfg.perHostConcurrency, cfg.hostTimeout)

	scanStarted := time.Now()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		encoder := json.NewEncoder(os.Stdout)
		metrics := scanMetrics{}
		for result := range results {
			metrics.add(result)
			if *openOnly && result.Status != "open" {
				continue
			}
			if *outputJSON {
				_ = encoder.Encode(result)
				continue
			}
			if result.Status == "open" {
				banner := ""
				if result.Banner != "" {
					banner = "  " + result.Banner
				}
				fmt.Printf("OPEN  %s:%-6d%s\n", result.Host, result.Port, banner)
			}
		}
		if *outputJSON && *summaryJSON {
			_ = encoder.Encode(Summary{
				Type:    "summary",
				Metrics: metrics,
				Elapsed: time.Since(scanStarted).Seconds(),
			})
		}
	}()

	var workerGroup sync.WaitGroup
	for worker := 0; worker < cfg.concurrency; worker++ {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			for current := range jobs {
				state, allowed := limiter.acquire(current.host)
				if !allowed {
					results <- Result{Host: current.host, Port: current.port, Status: "skipped"}
					continue
				}
				result := scanPort(current.host, current.port, cfg, state.deadline, gate)
				limiter.release(state)
				results <- result
			}
		}()
	}

	// Port-major ordering spreads early work across hosts rather than exhausting
	// one host's entire port list before moving to the next host.
	for _, port := range ports {
		for start := 0; start < len(hosts); start += *hostGroup {
			end := start + *hostGroup
			if end > len(hosts) {
				end = len(hosts)
			}
			for _, host := range hosts[start:end] {
				jobs <- job{host: host, port: port}
			}
		}
	}
	close(jobs)
	workerGroup.Wait()
	close(results)
	<-writerDone
}
