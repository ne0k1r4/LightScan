package main

import (
	"encoding/json"
	"math"
	"os"
	"testing"
	"time"
)

func TestSharedInputFixture(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../tests/fixtures/engine_inputs.json")
	if err != nil {
		t.Fatalf("read shared input fixture: %v", err)
	}
	var fixture struct {
		Target        string   `json:"target"`
		MaxTargets    int      `json:"max_targets"`
		ExpectedHosts []string `json:"expected_hosts"`
		Ports         string   `json:"ports"`
		ExpectedPorts []int    `json:"expected_ports"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode shared input fixture: %v", err)
	}
	hosts, err := parseTargets(fixture.Target, fixture.MaxTargets)
	if err != nil {
		t.Fatalf("parse shared fixture targets: %v", err)
	}
	ports, err := parsePorts(fixture.Ports)
	if err != nil {
		t.Fatalf("parse shared fixture ports: %v", err)
	}
	if len(hosts) != len(fixture.ExpectedHosts) || len(ports) != len(fixture.ExpectedPorts) {
		t.Fatalf("got hosts=%v ports=%v, want hosts=%v ports=%v", hosts, ports, fixture.ExpectedHosts, fixture.ExpectedPorts)
	}
	for index := range hosts {
		if hosts[index] != fixture.ExpectedHosts[index] {
			t.Fatalf("hosts=%v, want %v", hosts, fixture.ExpectedHosts)
		}
	}
	for index := range ports {
		if ports[index] != fixture.ExpectedPorts[index] {
			t.Fatalf("ports=%v, want %v", ports, fixture.ExpectedPorts)
		}
	}
}

func TestParsePortsRejectsInvalidValues(t *testing.T) {
	for _, specification := range []string{"", "0", "65536", "443-80", "80,,443"} {
		if _, err := parsePorts(specification); err == nil {
			t.Fatalf("parsePorts(%q) accepted an invalid specification", specification)
		}
	}
}

func TestParsePortsDeduplicatesAndSorts(t *testing.T) {
	ports, err := parsePorts("443,80,443,22-23")
	if err != nil {
		t.Fatalf("parsePorts returned an unexpected error: %v", err)
	}
	want := []int{22, 23, 80, 443}
	if len(ports) != len(want) {
		t.Fatalf("got %v, want %v", ports, want)
	}
	for index, port := range want {
		if ports[index] != port {
			t.Fatalf("got %v, want %v", ports, want)
		}
	}
}

func TestScanControlsRejectNonFiniteValues(t *testing.T) {
	if validScanControls(1, 1, 1, 1, 0, math.NaN(), 0, 0) {
		t.Fatal("NaN max rate was accepted")
	}
	if validScanControls(1, 1, 1, 1, 0, 0, math.Inf(1), 0) {
		t.Fatal("infinite retry jitter was accepted")
	}
}

func TestParseTargetsEnforcesCIDRLimit(t *testing.T) {
	if _, err := parseTargets("192.0.2.0/24", 10); err == nil {
		t.Fatal("expected CIDR target limit error")
	}
}

func TestParseTargetsHandlesSmallCIDR(t *testing.T) {
	hosts, err := parseTargets("192.0.2.0/30", 8)
	if err != nil {
		t.Fatalf("parseTargets returned an unexpected error: %v", err)
	}
	want := []string{"192.0.2.1", "192.0.2.2"}
	if len(hosts) != len(want) {
		t.Fatalf("got %v, want %v", hosts, want)
	}
	for index, host := range want {
		if hosts[index] != host {
			t.Fatalf("got %v, want %v", hosts, want)
		}
	}
}

func TestBoundedBufferRemainsFiniteForHighConcurrency(t *testing.T) {
	if got := boundedBuffer(1_000_000); got != 4096 {
		t.Fatalf("boundedBuffer did not cap a large worker count: got %d", got)
	}
	if got := boundedBuffer(1); got != 64 {
		t.Fatalf("boundedBuffer did not keep a useful minimum: got %d", got)
	}
}

func TestScanMetricsAggregatesOutcomeAndRetryCounts(t *testing.T) {
	metrics := scanMetrics{}
	metrics.add(Result{Status: "open", Attempts: 1})
	metrics.add(Result{Status: "closed", Attempts: 1})
	metrics.add(Result{Status: "filtered", Attempts: 2})
	metrics.add(Result{Status: "skipped", Attempts: 0})
	metrics.add(Result{Status: "error", Attempts: 1})

	if metrics.Scheduled != 5 || metrics.Attempts != 5 || metrics.Retries != 1 {
		t.Fatalf("unexpected aggregate counters: %+v", metrics)
	}
	if metrics.Open != 1 || metrics.Closed != 1 || metrics.Filtered != 1 || metrics.Skipped != 1 || metrics.Errors != 1 {
		t.Fatalf("unexpected outcome counters: %+v", metrics)
	}
}

func TestIPv6LiteralAndCIDRTargetsStayBounded(t *testing.T) {
	literal, err := parseTargets("[::1]", 4)
	if err != nil {
		t.Fatalf("parse bracketed IPv6 literal: %v", err)
	}
	if len(literal) != 1 || literal[0] != "::1" {
		t.Fatalf("literal=%v", literal)
	}

	cidr, err := parseTargets("2001:db8::1/128", 4)
	if err != nil {
		t.Fatalf("parse IPv6 /128: %v", err)
	}
	if len(cidr) != 1 || cidr[0] != "2001:db8::1" {
		t.Fatalf("cidr=%v", cidr)
	}

	if _, err := parseTargets("2001:db8::/64", 4); err == nil {
		t.Fatal("expected broader IPv6 CIDR to remain rejected")
	}
}

func TestRetryDelayCanDisableJitterForReproducibleRuns(t *testing.T) {
	if got := retryDelay(1, 0); got != 50*time.Millisecond {
		t.Fatalf("retryDelay(1, 0)=%s, want 50ms", got)
	}
	if got := retryDelay(2, 0); got != 100*time.Millisecond {
		t.Fatalf("retryDelay(2, 0)=%s, want 100ms", got)
	}
}

func TestRateGateSpacesConnectionStarts(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../tests/fixtures/engine_inputs.json")
	if err != nil {
		t.Fatalf("read shared rate fixture: %v", err)
	}
	var fixture struct {
		MaxRate                    float64 `json:"max_rate"`
		MinElapsedMsForThreeStarts int     `json:"min_elapsed_ms_for_three_starts"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode shared rate fixture: %v", err)
	}
	gate := newRateGate(fixture.MaxRate)
	started := time.Now()
	gate.wait()
	gate.wait()
	gate.wait()
	if elapsed := time.Since(started); elapsed < time.Duration(fixture.MinElapsedMsForThreeStarts)*time.Millisecond {
		t.Fatalf("three starts at %g/s took %s, want at least %dms", fixture.MaxRate, elapsed, fixture.MinElapsedMsForThreeStarts)
	}
}

func TestScanMetricsRetainsTransientAndRetryEvidence(t *testing.T) {
	metrics := scanMetrics{}
	metrics.add(Result{
		Status:         "transient",
		Attempts:       2,
		RetryTransient: 1,
		RetryDelayMs:   50,
	})
	if metrics.Transient != 1 || metrics.Retries != 1 || metrics.RetryTransient != 1 || metrics.RetryDelayMs != 50 {
		t.Fatalf("unexpected transient metrics: %+v", metrics)
	}
	if captureRuntimeTelemetry().GoRoutines < 1 {
		t.Fatal("expected runtime telemetry to report at least one goroutine")
	}
}
