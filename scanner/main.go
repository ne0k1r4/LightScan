// LightScan Go Scanner — high-performance TCP connect scanner companion binary.
//
// Why Go? Python's async TCP scanner is fast, but Go's goroutine scheduler
// handles 10,000+ concurrent connections more efficiently for large subnet sweeps.
// This binary is called by the Python engine when --raw-go is passed.
//
// Usage (standalone):
//   ./lscan -t 10.0.0.0/24 -p 22,80,443,8080 -c 2000 -T 1500
//   ./lscan -t 192.168.1.1-50 -p top100 --json
//
// Usage (from Python via subprocess):
//   lscan -t <target> -p <ports> -c <concurrency> -T <timeout_ms> --json
//
// Output: one JSON object per line (NDJSON) for easy Python parsing.
//   {"host":"10.0.0.1","port":22,"status":"open","banner":"SSH-2.0-OpenSSH_8.9","ms":4}
package main

import (
	"bufio"
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

// ── Result ───────────────────────────────────────────────────────────────────

type Result struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Status string `json:"status"` // open | closed | filtered
	Banner string `json:"banner,omitempty"`
	Ms     int64  `json:"ms"`
}

// ── Port lists ────────────────────────────────────────────────────────────────

var top100 = []int{
	20, 21, 22, 23, 25, 53, 69, 79, 80, 88, 110, 111, 119, 123, 135, 137,
	138, 139, 143, 161, 389, 443, 445, 465, 514, 587, 636, 873, 990, 993,
	995, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 3000, 3128, 3306, 3389,
	4443, 5000, 5432, 5800, 5900, 6379, 6443, 7001, 7443, 8000, 8080, 8081,
	8443, 8888, 9000, 9090, 9200, 9300, 9443, 10000, 27017,
}

// ── Target parsing ────────────────────────────────────────────────────────────

// parsePorts converts "22,80,443" or "1-1024" or "top100" into a port list.
func parsePorts(spec string) ([]int, error) {
	if strings.EqualFold(spec, "top100") {
		return top100, nil
	}
	ports := make([]int, 0)
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo > hi {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}
	return ports, nil
}

// parseTargets expands a target spec into a list of IP strings.
// Supports: single IP, CIDR (10.0.0.0/24), range (10.0.0.1-10), hostname.
func parseTargets(spec string) ([]string, error) {
	// File input
	if strings.HasPrefix(spec, "file:") {
		f, err := os.Open(spec[5:])
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var hosts []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			h, err := parseTargets(line)
			if err == nil {
				hosts = append(hosts, h...)
			}
		}
		return hosts, nil
	}

	// CIDR
	if strings.Contains(spec, "/") {
		_, ipNet, err := net.ParseCIDR(spec)
		if err != nil {
			return nil, err
		}
		var hosts []string
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
			// Skip network and broadcast
			if ip[len(ip)-1] == 0 || ip[len(ip)-1] == 255 {
				continue
			}
			hosts = append(hosts, ip.String())
		}
		return hosts, nil
	}

	// Range: 10.0.0.1-50
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) == 2 {
		baseIP := net.ParseIP(parts[0])
		if baseIP != nil {
			end, err := strconv.Atoi(parts[1])
			if err == nil {
				ipv4 := baseIP.To4()
				start := int(ipv4[3])
				var hosts []string
				for i := start; i <= end && i <= 255; i++ {
					hosts = append(hosts, fmt.Sprintf("%d.%d.%d.%d",
						ipv4[0], ipv4[1], ipv4[2], i))
				}
				return hosts, nil
			}
		}
	}

	// Single IP or hostname
	return []string{spec}, nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// ── Banner grabbing ───────────────────────────────────────────────────────────

// Quick service-specific probes — send the right bytes, read what comes back.
var probes = map[int][]byte{
	21:    nil,                                    // FTP sends banner on connect
	22:    nil,                                    // SSH sends banner on connect
	25:    []byte("EHLO lightscan.local\r\n"),
	80:    []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	443:   []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	6379:  []byte("*1\r\n$4\r\nINFO\r\n"),
	8080:  []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	8443:  []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	9200:  []byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"),
	27017: {0x3a, 0x00, 0x00, 0x00, 0xd4, 0x07}, // MongoDB ping (truncated for banner)
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Read initial banner (services that push on connect)
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))

	// Send probe if we got nothing and one exists for this port
	if banner == "" {
		if probe, ok := probes[port]; ok && len(probe) > 0 {
			conn.SetWriteDeadline(time.Now().Add(timeout))
			conn.Write(probe)
			conn.SetReadDeadline(time.Now().Add(timeout))
			n, _ = conn.Read(buf)
			banner = strings.TrimSpace(string(buf[:n]))
		}
	}

	// Sanitize: strip non-printable, limit length
	clean := make([]byte, 0, len(banner))
	for _, b := range []byte(banner) {
		if b >= 32 && b < 127 {
			clean = append(clean, b)
		}
	}
	s := string(clean)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ── Scanner core ──────────────────────────────────────────────────────────────

func scanPort(host string, port int, timeoutMs int, grabBanners bool) Result {
	addr := fmt.Sprintf("%s:%d", host, port)
	t0   := time.Now()

	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutMs)*time.Millisecond)
	elapsed := time.Since(t0).Milliseconds()

	if err != nil {
		status := "closed"
		if isFiltered(err) {
			status = "filtered"
		}
		return Result{Host: host, Port: port, Status: status, Ms: elapsed}
	}
	defer conn.Close()

	banner := ""
	if grabBanners {
		banner = grabBanner(conn, port, time.Duration(timeoutMs/2)*time.Millisecond)
	}

	return Result{Host: host, Port: port, Status: "open", Banner: banner, Ms: elapsed}
}

// isFiltered tries to distinguish a hard TCP reset (closed) from a silent
// drop (filtered) — not perfect without raw sockets, but useful heuristic.
func isFiltered(err error) bool {
	s := err.Error()
	return strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "connection timed out") ||
		strings.Contains(s, "no route to host")
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	target      := flag.String("t", "",     "Target: IP, CIDR, range, hostname, or file:path")
	portSpec    := flag.String("p", "top100", "Ports: 22,80,443 | 1-1024 | top100")
	concurrency := flag.Int("c",   1000,    "Max concurrent connections")
	timeoutMs   := flag.Int("T",   1500,    "Connection timeout in milliseconds")
	outputJSON  := flag.Bool("json", false, "Output NDJSON (one result per line)")
	openOnly    := flag.Bool("open", false, "Only print open ports")
	noBanner    := flag.Bool("no-banner", false, "Skip banner grabbing")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: -t <target> is required")
		flag.Usage()
		os.Exit(1)
	}

	hosts, err := parseTargets(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing targets: %v\n", err)
		os.Exit(1)
	}

	ports, err := parsePorts(*portSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing ports: %v\n", err)
		os.Exit(1)
	}

	// Work queue
	type job struct{ host string; port int }
	jobs := make(chan job, *concurrency*2)
	var wg sync.WaitGroup
	sem  := make(chan struct{}, *concurrency)

	// Result writer (single goroutine to avoid interleaved output)
	results := make(chan Result, *concurrency*2)
	go func() {
		enc := json.NewEncoder(os.Stdout)
		for r := range results {
			if *openOnly && r.Status != "open" {
				continue
			}
			if *outputJSON {
				enc.Encode(r)
			} else {
				if r.Status == "open" {
					banner := ""
					if r.Banner != "" {
						banner = "  " + r.Banner
					}
					fmt.Printf("OPEN  %s:%-6d%s\n", r.Host, r.Port, banner)
				}
			}
		}
	}()

	// Workers
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				sem <- struct{}{}
				r := scanPort(j.host, j.port, *timeoutMs, !*noBanner)
				<-sem
				results <- r
			}
		}()
	}

	// Feed jobs
	for _, h := range hosts {
		for _, p := range ports {
			jobs <- job{host: h, port: p}
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
}
