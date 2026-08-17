package main

import (
	"net"
	"os"
	"runtime"
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

// memInfo is a snapshot of /proc/meminfo's relevant fields, all read in one
// pass (one open/read syscall pair) since heartbeat/hello both need pieces
// of it and re-reading the file per-field would be wasteful.
type memInfo struct {
	totalMB, usedMB, usedPct float64
	swapTotalMB, swapUsedMB  float64
}

// readMemInfo computes used-memory the same way `free` does: used = total -
// available, where MemAvailable (not MemFree) already accounts for
// reclaimable caches/buffers — MemFree alone would wildly overstate memory
// pressure on a healthy Linux box.
func readMemInfo() memInfo {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return memInfo{}
	}
	defer f.Close()

	var totalKB, availableKB, swapTotalKB, swapFreeKB float64
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(fields[1], 64)
		switch fields[0] {
		case "MemTotal:":
			totalKB = v
		case "MemAvailable:":
			availableKB = v
		case "SwapTotal:":
			swapTotalKB = v
		case "SwapFree:":
			swapFreeKB = v
		}
	}

	var mi memInfo
	mi.totalMB = totalKB / 1024
	mi.swapTotalMB = swapTotalKB / 1024
	mi.swapUsedMB = (swapTotalKB - swapFreeKB) / 1024
	if totalKB > 0 {
		usedKB := totalKB - availableKB
		mi.usedMB = usedKB / 1024
		mi.usedPct = usedKB / totalKB * 100
	}
	return mi
}

// diskInfo is a snapshot of / usage via a direct statfs syscall (no `df`
// subprocess needed for numbers this cheap to get natively).
type diskInfo struct {
	totalMB, usedMB, usedPct float64
}

func readDiskInfo() diskInfo {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return diskInfo{}
	}
	total := float64(stat.Blocks) * float64(stat.Bsize)
	free := float64(stat.Bfree) * float64(stat.Bsize)
	var di diskInfo
	di.totalMB = total / (1 << 20)
	if total > 0 {
		used := total - free
		di.usedMB = used / (1 << 20)
		di.usedPct = used / total * 100
	}
	return di
}

// cpuCores reports the number of logical CPUs available to this process —
// on the bare-metal/VPS deployment this agent targets (no cgroup CPU
// quota), that's the host's real core count.
func cpuCores() int {
	return runtime.NumCPU()
}

// primaryIP returns this host's outbound-facing IP address, determined
// without ever sending a packet: dialing UDP only resolves a route and
// binds a local address locally. On a typical VPS with a single public
// interface, this is the server's public IP; behind NAT it would be the
// private address of that interface, which is still the most useful single
// "how do I reach this box" answer available without an external
// IP-lookup service (a paid/third-party dependency this project's core
// features deliberately avoid — see docs/SYSTEM.md §17).
func primaryIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return addr.IP.String()
}
