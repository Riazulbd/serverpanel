package capabilities

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// run executes a fixed argv (never a shell, never caller-built strings) and
// returns combined output. This is the one place every capability in this
// package funnels external process execution through, which is what makes
// "no arbitrary shell exec" an auditable property of the codebase rather
// than a convention every handler has to remember.
func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		// The agent always runs as root; without this, Composer prints a
		// "running as root" warning ahead of its actual output on every
		// invocation, which previously got mistaken for real output (e.g.
		// stack.install's version report captured the warning instead of
		// the version line). Composer itself still refuses to run
		// plugins as root regardless of this flag — it only silences the
		// advisory noise.
		"COMPOSER_ALLOW_SUPERUSER=1",
	)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// runWithStdin is like run, but feeds stdin a fixed string built entirely
// from already-validated values (used by crontab -u <user> - to replace a
// user's crontab in one atomic write, since crontab has no "append one
// line" mode).
func runWithStdin(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// isPackageInstalled reports whether an apt package is already installed,
// which is what makes stack installation idempotent/safely-retryable: a
// re-run skips every step whose target state already holds.
func isPackageInstalled(ctx context.Context, pkg string) bool {
	out, err := run(ctx, "dpkg-query", "-W", "-f", "${Status}", pkg)
	return err == nil && strings.Contains(out, "install ok installed")
}

func aptInstall(ctx context.Context, pkgs ...string) (string, error) {
	args := append([]string{"install", "-y", "--no-install-recommends"}, pkgs...)
	return run(ctx, "apt-get", args...)
}

// osRelease returns the parsed contents of /etc/os-release as a map (ID,
// VERSION_ID, PRETTY_NAME, ...).
func osRelease() (map[string]string, error) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, "=")
		if i < 0 {
			continue
		}
		key := line[:i]
		val := strings.Trim(line[i+1:], `"`)
		out[key] = val
	}
	return out, nil
}

// checkOSSupported re-validates OS compatibility at install time, in
// addition to the check install.sh already ran — defense in depth: the
// agent should never trust that its own preconditions were checked by
// something upstream of it.
func checkOSSupported() error {
	rel, err := osRelease()
	if err != nil {
		return fmt.Errorf("cannot determine OS: %w", err)
	}
	if rel["ID"] != "ubuntu" || rel["VERSION_ID"] != "24.04" {
		return fmt.Errorf("unsupported OS %q %q: this release only supports Ubuntu 24.04 LTS", rel["ID"], rel["VERSION_ID"])
	}
	return nil
}

type resourceReport struct {
	CPUCount    int
	MemTotalMB  int
	DiskAvailMB int
}

func checkResources() (resourceReport, error) {
	var r resourceReport

	cpuOut, err := run(context.Background(), "nproc")
	if err == nil {
		r.CPUCount, _ = strconv.Atoi(cpuOut)
	}

	memFile, err := os.Open("/proc/meminfo")
	if err == nil {
		defer memFile.Close()
		sc := bufio.NewScanner(memFile)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && fields[0] == "MemTotal:" {
				kb, _ := strconv.Atoi(fields[1])
				r.MemTotalMB = kb / 1024
				break
			}
		}
	}

	diskOut, err := run(context.Background(), "df", "-Pm", "/")
	if err == nil {
		lines := strings.Split(diskOut, "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 4 {
				r.DiskAvailMB, _ = strconv.Atoi(fields[3])
			}
		}
	}

	if r.MemTotalMB > 0 && r.MemTotalMB < 512 {
		return r, fmt.Errorf("insufficient RAM: %dMB available, 512MB minimum recommended", r.MemTotalMB)
	}
	if r.DiskAvailMB > 0 && r.DiskAvailMB < 2048 {
		return r, fmt.Errorf("insufficient disk: %dMB free on /, 2048MB minimum recommended", r.DiskAvailMB)
	}
	return r, nil
}

// ipv6Available reports whether this host can actually bind an IPv6 TCP
// socket. Some minimal or containerized Ubuntu images have IPv6 disabled
// entirely (or lack the kernel module), in which case a generated nginx
// vhost that unconditionally includes "listen [::]:80" fails nginx's
// config test outright — breaking every subsequent site.create on that
// host. This is a cheap, side-effect-free runtime probe (bind to an
// ephemeral loopback port, then release it) done once per site.create
// rather than assumed.
func ipv6Available() bool {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// listeningPortOwners reports which processes (if any) already have ports
// 80/443 bound, so stack.install can flag a real conflict (something else
// already serving HTTP/HTTPS) rather than just guessing from package
// presence. Best-effort: absence of `ss` degrades to an empty report
// rather than failing the whole check.
func listeningPortOwners(ctx context.Context) map[string]string {
	out, err := run(ctx, "ss", "-H", "-ltnp")
	result := map[string]string{}
	if err != nil {
		return result
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		for _, port := range []string{":80", ":443"} {
			if strings.HasSuffix(local, port) {
				proc := "unknown process"
				if len(fields) >= 6 {
					proc = fields[len(fields)-1]
				}
				result[port] = proc
			}
		}
	}
	return result
}
