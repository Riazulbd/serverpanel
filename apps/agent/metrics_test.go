package main

import (
	"runtime"
	"testing"
)

// These assert plausible ranges rather than exact values — the point is
// that the collectors return real readings instead of the zeros they
// silently reported before (the heartbeat bug found during integration
// testing), and that they never return nonsense a dashboard would render
// as a broken gauge.

func TestUptimeSecsIsPositiveOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uptime is read from /proc/uptime; Linux only")
	}
	if got := uptimeSecs(); got <= 0 {
		t.Errorf("uptimeSecs() = %d, want a positive reading", got)
	}
}

func TestLoadAvg1IsSane(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("load average is read from /proc/loadavg; Linux only")
	}
	got := loadAvg1()
	if got < 0 {
		t.Errorf("loadAvg1() = %v, want >= 0", got)
	}
	// A 1-minute load average above this on any sane host means we parsed
	// the wrong field.
	if got > 10000 {
		t.Errorf("loadAvg1() = %v, implausibly high — likely parsing the wrong field", got)
	}
}

func TestMemUsedPctIsAPercentage(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("memory stats are read from /proc/meminfo; Linux only")
	}
	got := memUsedPct()
	if got <= 0 || got > 100 {
		t.Errorf("memUsedPct() = %v, want a percentage in (0,100]", got)
	}
}

func TestDiskUsedPctIsAPercentage(t *testing.T) {
	got := diskUsedPct()
	if got <= 0 || got > 100 {
		t.Errorf("diskUsedPct() = %v, want a percentage in (0,100]", got)
	}
}

// TestMetricsAreNotAllZero is the direct regression test for the bug where
// the heartbeat shipped a struct of zeros because nothing populated it.
func TestMetricsAreNotAllZero(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("metric collectors are Linux-specific")
	}
	if uptimeSecs() == 0 && loadAvg1() == 0 && memUsedPct() == 0 && diskUsedPct() == 0 {
		t.Error("every metric read back as zero; the heartbeat would carry no real data")
	}
}
