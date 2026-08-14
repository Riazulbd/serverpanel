package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// loadAvg1 returns the 1-minute load average from /proc/loadavg, or 0 if it
// can't be read (e.g. non-Linux dev environment).
func loadAvg1() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

// memUsedPct computes used-memory percentage the same way `free` does:
// used = total - available, where MemAvailable (not MemFree) already
// accounts for reclaimable caches/buffers — MemFree alone would wildly
// overstate memory pressure on a healthy Linux box.
func memUsedPct() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	var total, available float64
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total, _ = strconv.ParseFloat(fields[1], 64)
		case "MemAvailable:":
			available, _ = strconv.ParseFloat(fields[1], 64)
		}
	}
	if total == 0 {
		return 0
	}
	return (total - available) / total * 100
}

// diskUsedPct reports used space on / as a percentage, via a direct statfs
// syscall (no `df` subprocess needed for a number this cheap to get
// natively).
func diskUsedPct() float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0
	}
	total := float64(stat.Blocks) * float64(stat.Bsize)
	free := float64(stat.Bfree) * float64(stat.Bsize)
	if total == 0 {
		return 0
	}
	return (total - free) / total * 100
}
