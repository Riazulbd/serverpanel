package capabilities

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// stackReportPath is where the installer records what it installed and
// when, satisfying "record installed package and configuration versions"
// and giving future stack.install calls (upgrades, retries) something to
// read before deciding what to do.
const stackReportPath = "/var/lib/serverpanel-agent/stack-report.json"

// installStep is one idempotent unit of the stack installer. check reports
// whether the step's target state already holds (so a retried
// stack.install skips everything already done rather than re-running it),
// and run performs the step. Steps execute strictly in order — Phase 1
// deliberately does not try to parallelize package installation, since a
// clear, serial failure point is what "safely retry failed steps" and
// "never leave partially configured services" both depend on.
type installStep struct {
	Name  string
	Check func(ctx context.Context) bool
	Run   func(ctx context.Context) error
}

type stackReport struct {
	Profile     string            `json:"profile"`
	InstalledAt time.Time         `json:"installed_at"`
	Versions    map[string]string `json:"versions"`
	Warnings    []string          `json:"warnings,omitempty"`
}

// phase1LEMPSteps is the only installation profile Phase 1 ships (see
// docs/product-plan.md — later profiles like OpenLiteSpeed/Node.js are
// explicitly out of scope for the first release, added as new profiles
// later without touching this one).
func phase1LEMPSteps() []installStep {
	return []installStep{
		{
			Name:  "nginx",
			Check: func(ctx context.Context) bool { return isPackageInstalled(ctx, "nginx") },
			Run:   func(ctx context.Context) error { _, err := aptInstall(ctx, "nginx"); return err },
		},
		{
			Name: "nginx tuning for many managed vhosts",
			// Every site gets both its real domain and a generated
			// sslip.io temp domain in server_name — nginx's default
			// server_names_hash_bucket_size (32-64 depending on distro)
			// runs out of room once enough sites accumulate ("could not
			// build server_names_hash_bucket_size, you should increase
			// server_names_hash_bucket_size"), which then breaks `nginx
			// -t` — and so every subsequent site.create — for the whole
			// server, not just the new site. Set generously up front
			// rather than waiting for a customer to hit it.
			Check: func(ctx context.Context) bool {
				_, err := os.Stat("/etc/nginx/conf.d/serverpanel-tuning.conf")
				return err == nil
			},
			Run: func(ctx context.Context) error {
				content := "# Managed by ServerPanel. server_names_hash_bucket_size is sized for\n" +
					"# many vhosts (each site contributes its real domain plus a generated\n" +
					"# temp domain to server_name).\nserver_names_hash_bucket_size 128;\n"
				return os.WriteFile("/etc/nginx/conf.d/serverpanel-tuning.conf", []byte(content), 0644)
			},
		},
		{
			Name: "disable stock nginx default site",
			// Every real site is served through our own generated vhost
			// (site.create); the package's placeholder "Welcome to nginx"
			// default site is disabled rather than left competing for
			// port 80 as default_server. It also unconditionally listens
			// on IPv6 regardless of whether the host actually has it,
			// which — left enabled — would break `nginx -t` (and so every
			// site.create afterward) on any host with IPv6 disabled.
			Check: func(ctx context.Context) bool {
				_, err := os.Stat("/etc/nginx/sites-enabled/default")
				return os.IsNotExist(err)
			},
			Run: func(ctx context.Context) error {
				if err := os.Remove("/etc/nginx/sites-enabled/default"); err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			},
		},
		{
			Name:  "php8.3-fpm and common extensions",
			Check: func(ctx context.Context) bool { return isPackageInstalled(ctx, "php8.3-fpm") },
			Run: func(ctx context.Context) error {
				_, err := aptInstall(ctx, "php8.3-fpm", "php8.3-mysql", "php8.3-redis",
					"php8.3-curl", "php8.3-mbstring", "php8.3-xml", "php8.3-zip", "php8.3-gd", "php8.3-cli")
				return err
			},
		},
		{
			Name:  "mariadb-server",
			Check: func(ctx context.Context) bool { return isPackageInstalled(ctx, "mariadb-server") },
			Run:   func(ctx context.Context) error { _, err := aptInstall(ctx, "mariadb-server"); return err },
		},
		{
			Name:  "redis-server",
			Check: func(ctx context.Context) bool { return isPackageInstalled(ctx, "redis-server") },
			Run:   func(ctx context.Context) error { _, err := aptInstall(ctx, "redis-server"); return err },
		},
		{
			Name:  "git",
			Check: func(ctx context.Context) bool { return isPackageInstalled(ctx, "git") },
			Run:   func(ctx context.Context) error { _, err := aptInstall(ctx, "git"); return err },
		},
		{
			Name:  "unzip (composer/wp-cli dependency)",
			Check: func(ctx context.Context) bool { return isPackageInstalled(ctx, "unzip") },
			Run:   func(ctx context.Context) error { _, err := aptInstall(ctx, "unzip", "curl"); return err },
		},
		{
			Name:  "composer",
			Check: func(ctx context.Context) bool { _, err := os.Stat("/usr/local/bin/composer"); return err == nil },
			Run:   installComposer,
		},
		{
			Name:  "wp-cli",
			Check: func(ctx context.Context) bool { _, err := os.Stat("/usr/local/bin/wp"); return err == nil },
			Run:   installWPCLI,
		},
		{
			Name:  "certbot (Let's Encrypt ACME client)",
			Check: func(ctx context.Context) bool { return isPackageInstalled(ctx, "certbot") },
			Run: func(ctx context.Context) error {
				_, err := aptInstall(ctx, "certbot", "python3-certbot-nginx")
				return err
			},
		},
		{
			// The certbot Debian/Ubuntu package ships a systemd timer
			// (certbot.timer, running `certbot renew` twice daily) enabled
			// by its postinst script — but relying on that default silently
			// makes SSL auto-renewal an accident of packaging rather than a
			// guaranteed property of this install. Enabling it explicitly
			// here is defense in depth: whatever ssl.issue_letsencrypt
			// issues, this step's job is issued *and will keep renewing*
			// without any further action, verifiable via ssl.status's
			// auto_renewal_active field rather than assumed.
			Name:  "certbot auto-renewal timer",
			Check: func(ctx context.Context) bool { return certbotTimerActive(ctx) },
			Run: func(ctx context.Context) error {
				_, err := run(ctx, "systemctl", "enable", "--now", "certbot.timer")
				return err
			},
		},
		{
			Name:  "ufw",
			Check: func(ctx context.Context) bool { return isPackageInstalled(ctx, "ufw") },
			Run:   func(ctx context.Context) error { _, err := aptInstall(ctx, "ufw"); return err },
		},
		{
			Name: "ufw baseline rules (SSH allowed before enabling)",
			Check: func(ctx context.Context) bool {
				out, _ := run(ctx, "ufw", "status")
				return strings.Contains(out, "Status: active")
			},
			// SSH is explicitly allowed BEFORE the firewall is switched on:
			// enabling UFW with no allow rule for the current SSH session
			// would lock the user out immediately. This is a minimal safe
			// default for the initial install only; the full apply -> hold
			// -> confirm-or-rollback flow (docs/security-trust-model.md §5)
			// governs any *subsequent* firewall rule change made through
			// the dashboard.
			//
			// The actual configured SSH port is allowed directly (rather
			// than the "OpenSSH" app profile) because that profile is only
			// registered when the openssh-server package defines it — on a
			// system where sshd is present but that app definition isn't
			// installed, "ufw allow OpenSSH" fails outright and would
			// abort the whole stack install on this step every time.
			Run: func(ctx context.Context) error {
				sshPort := currentSSHPort()
				if _, err := run(ctx, "ufw", "allow", sshPort+"/tcp"); err != nil {
					return fmt.Errorf("allow SSH port %s: %w", sshPort, err)
				}
				if _, err := run(ctx, "ufw", "allow", "80/tcp"); err != nil {
					return fmt.Errorf("allow 80/tcp: %w", err)
				}
				if _, err := run(ctx, "ufw", "allow", "443/tcp"); err != nil {
					return fmt.Errorf("allow 443/tcp: %w", err)
				}
				_, err := run(ctx, "ufw", "--force", "enable")
				return err
			},
		},
		{
			Name:  "fail2ban",
			Check: func(ctx context.Context) bool { return isPackageInstalled(ctx, "fail2ban") },
			Run:   func(ctx context.Context) error { _, err := aptInstall(ctx, "fail2ban"); return err },
		},
	}
}

// currentSSHPort reads the configured SSH port out of sshd_config,
// defaulting to the standard port 22 when no explicit Port directive is
// present (sshd's own default) or the file can't be read.
func currentSSHPort() string {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "22"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "Port") {
			return fields[1]
		}
	}
	return "22"
}

func handleStackInstall(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	profile, _ := params["profile"].(string)
	if profile != "phase1-lemp" {
		return "", fmt.Errorf("unknown or unsupported stack profile %q (this release only supports \"phase1-lemp\")", profile)
	}

	progress("pre-installation checks: OS compatibility")
	if err := checkOSSupported(); err != nil {
		return "", fmt.Errorf("pre-installation check failed: %w", err)
	}

	progress("pre-installation checks: CPU/memory/disk")
	resources, err := checkResources()
	if err != nil {
		return "", fmt.Errorf("pre-installation check failed: %w", err)
	}

	progress("pre-installation checks: port conflicts")
	owners := listeningPortOwners(ctx)
	if len(owners) > 0 && !isPackageInstalled(ctx, "nginx") {
		// Something is already bound to 80/443 and it isn't the nginx
		// we're about to (re)configure — a real conflict, not just an
		// already-completed install. Abort rather than fight it silently.
		return "", fmt.Errorf("port conflict detected before install: %v (stop the conflicting service first)", owners)
	}

	report := stackReport{Profile: profile, Versions: map[string]string{}}
	steps := phase1LEMPSteps()

	for i, step := range steps {
		if step.Check(ctx) {
			progress(fmt.Sprintf("[%d/%d] %s: already installed, skipping", i+1, len(steps), step.Name))
			continue
		}
		progress(fmt.Sprintf("[%d/%d] installing %s", i+1, len(steps), step.Name))
		if err := step.Run(ctx); err != nil {
			// Safe retry: everything before this step is already in its
			// target state (idempotent checks), so re-dispatching
			// stack.install after the underlying problem is fixed resumes
			// from exactly this step rather than reinstalling from
			// scratch or leaving a half-applied step behind.
			return "", fmt.Errorf("step %q failed: %w (safe to retry stack.install once resolved; prior steps will be skipped)", step.Name, err)
		}
	}

	for _, pkg := range []string{"nginx", "php8.3-fpm", "mariadb-server", "redis-server", "git", "certbot", "ufw", "fail2ban"} {
		report.Versions[pkg] = dpkgVersion(ctx, pkg)
	}
	report.Versions["composer"] = commandVersion(ctx, "/usr/local/bin/composer", "--version")
	report.Versions["wp-cli"] = commandVersion(ctx, "/usr/local/bin/wp", "--version", "--allow-root")
	report.InstalledAt = time.Now().UTC()
	report.Versions["cpu_count"] = fmt.Sprintf("%d", resources.CPUCount)
	report.Versions["mem_total_mb"] = fmt.Sprintf("%d", resources.MemTotalMB)
	report.Versions["disk_avail_mb_at_install"] = fmt.Sprintf("%d", resources.DiskAvailMB)

	if err := writeStackReport(report); err != nil {
		progress(fmt.Sprintf("warning: could not persist install report: %v", err))
	}

	reportJSON, _ := json.Marshal(report)
	return string(reportJSON), nil
}

func dpkgVersion(ctx context.Context, pkg string) string {
	out, err := run(ctx, "dpkg-query", "-W", "-f", "${Version}", pkg)
	if err != nil {
		return "unknown"
	}
	return out
}

func commandVersion(ctx context.Context, path string, args ...string) string {
	out, err := run(ctx, path, args...)
	if err != nil {
		return "unknown"
	}
	lines := strings.SplitN(out, "\n", 2)
	return lines[0]
}

func writeStackReport(r stackReport) error {
	if err := os.MkdirAll("/var/lib/serverpanel-agent", 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stackReportPath, data, 0600)
}

// installComposer follows Composer's documented signature-verified install
// procedure rather than piping a downloaded script straight into PHP: fetch
// the installer, fetch its published SHA-384 signature, verify, then run.
// This is the supply-chain-integrity posture docs/product-plan.md calls for
// applied to the one third-party installer this profile pulls in over the
// network at install time.
func installComposer(ctx context.Context) error {
	sigResp, err := httpGet(ctx, "https://composer.github.io/installer.sig")
	if err != nil {
		return fmt.Errorf("fetch composer installer signature: %w", err)
	}
	expectedSig := strings.TrimSpace(sigResp)

	installerResp, err := httpGetBytes(ctx, "https://getcomposer.org/installer")
	if err != nil {
		return fmt.Errorf("fetch composer installer: %w", err)
	}
	sum := sha512.Sum384(installerResp)
	actualSig := hex.EncodeToString(sum[:])
	if actualSig != expectedSig {
		return fmt.Errorf("composer installer signature mismatch (expected %s, got %s) — refusing to run it", expectedSig, actualSig)
	}

	tmpFile, err := os.CreateTemp("", "composer-setup-*.php")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(installerResp); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	_, err = run(ctx, "php", tmpFile.Name(), "--install-dir=/usr/local/bin", "--filename=composer")
	return err
}

// installWPCLI installs a pinned wp-cli release verified against its
// published SHA-512 checksum, rather than tracking a "latest" nightly phar,
// so a stack install is reproducible and each agent reports a real,
// specific version in its report.
func installWPCLI(ctx context.Context) error {
	const version = "2.10.0"
	pharURL := fmt.Sprintf("https://github.com/wp-cli/wp-cli/releases/download/v%s/wp-cli-%s.phar", version, version)
	sumURL := pharURL + ".sha512"

	pharBytes, err := httpGetBytes(ctx, pharURL)
	if err != nil {
		return fmt.Errorf("fetch wp-cli phar: %w", err)
	}
	sumResp, err := httpGet(ctx, sumURL)
	if err != nil {
		return fmt.Errorf("fetch wp-cli checksum: %w", err)
	}
	expected := strings.Fields(strings.TrimSpace(sumResp))[0]

	sum := sha512Hex(pharBytes)
	if sum != expected {
		return fmt.Errorf("wp-cli checksum mismatch (expected %s, got %s) — refusing to install it", expected, sum)
	}

	if err := os.WriteFile("/usr/local/bin/wp", pharBytes, 0755); err != nil {
		return err
	}
	return nil
}

func sha512Hex(b []byte) string {
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:])
}

func httpGet(ctx context.Context, url string) (string, error) {
	b, err := httpGetBytes(ctx, url)
	return string(b), err
}

func httpGetBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
