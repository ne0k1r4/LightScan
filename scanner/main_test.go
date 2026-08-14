package main

import "testing"

func TestParsePortsRejectsInvalidValues(t *testing.T) {
	for _, specification := range []string{"", "0", "65536", "443-80", "80,,443"} {
		if _, err := parsePorts(specification); err == nil {
			t.Fatalf("parsePorts(%q) accepted an invalid specification", specification)
		}
	}
}

func TestParsePortsDeduplicatesAndPreservesInputOrder(t *testing.T) {
	ports, err := parsePorts("443,80,443,22-23")
	if err != nil {
		t.Fatalf("parsePorts returned an unexpected error: %v", err)
	}
	want := []int{443, 80, 22, 23}
	if len(ports) != len(want) {
		t.Fatalf("got %v, want %v", ports, want)
	}
	for index, port := range want {
		if ports[index] != port {
			t.Fatalf("got %v, want %v", ports, want)
		}
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
