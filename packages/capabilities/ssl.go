package capabilities

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// letsEncryptLiveDir is where certbot stores issued certificates
// (<domain>/cert.pem, .../privkey.pem, ...) — a var, not a const, so tests
// can point it at a temp directory instead of the real system path.
var letsEncryptLiveDir = "/etc/letsencrypt/live"

// handleSSLIssueLetsEncrypt issues (or renews) a Let's Encrypt certificate
// for a domain using certbot's nginx plugin with a fixed, non-interactive
// argv — the domain is the only caller-supplied value, and it's the same
// domain already validated and vhost-configured by site.create, so this
// only ever points certbot at a site the control plane already knows
// about.
func handleSSLIssueLetsEncrypt(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	email, _ := params["email"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if email == "" {
		return "", fmt.Errorf("email is required (Let's Encrypt expiry/urgent notices)")
	}
	if _, err := os.Stat("/usr/bin/certbot"); err != nil {
		return "", fmt.Errorf("certbot is not installed on this server; run stack.install first")
	}

	progress("requesting certificate from Let's Encrypt for " + domain)
	out, err := run(ctx, "certbot", "--nginx", "-d", domain, "--non-interactive", "--agree-tos",
		"--email", email, "--redirect")
	if err != nil {
		return "", fmt.Errorf("certbot: %w: %s", err, out)
	}
	return "certificate issued for " + domain, nil
}

// handleSSLInstallCustom installs a user-supplied certificate/key pair for
// a domain. Both PEM blobs are written with restrictive permissions and
// wired into the site's existing nginx vhost rather than parsed/executed
// in any way — the agent trusts nginx's own `nginx -t` to reject anything
// malformed, and never applies a config that fails that test.
func handleSSLInstallCustom(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	certPEM, _ := params["cert_pem"].(string)
	keyPEM, _ := params["key_pem"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if certPEM == "" || keyPEM == "" {
		return "", fmt.Errorf("cert_pem and key_pem are required")
	}

	certDir := "/etc/serverpanel-agent/ssl/" + domain
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", err
	}
	certPath := certDir + "/fullchain.pem"
	keyPath := certDir + "/privkey.pem"
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return "", fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	progress("verifying nginx config with the new certificate")
	if out, err := run(ctx, "nginx", "-t"); err != nil {
		return "", fmt.Errorf("nginx config test failed, custom cert not activated: %w: %s", err, out)
	}
	run(ctx, "systemctl", "reload", "nginx")
	return "custom certificate installed for " + domain, nil
}

// handleSSLRenewalStatus reports whether Let's Encrypt certificates on this
// server will actually renew themselves before they expire: whether
// certbot's own systemd renewal timer (enabled by stack.install, see
// stack.go) is present and active, plus every issued certificate's
// expiry. This gives the control plane real renewal-monitoring data
// (docs/SYSTEM.md's "Automatic SSL renewal" gap) instead of only knowing a
// certificate was issued once and never checking on it again.
//
// Certificate expiry is read directly from each cert.pem's parsed X.509
// NotAfter field rather than by scraping `certbot certificates`' text
// output, which is not a stable machine-readable format across certbot
// versions.
func handleSSLRenewalStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	var lines []string

	timerOut, timerErr := run(ctx, "systemctl", "is-enabled", "certbot.timer")
	activeOut, activeErr := run(ctx, "systemctl", "is-active", "certbot.timer")
	switch {
	case timerErr != nil && activeErr != nil:
		lines = append(lines, "certbot.timer: not installed (run stack.install)")
	default:
		lines = append(lines, fmt.Sprintf("certbot.timer: %s, %s", strings.TrimSpace(timerOut), strings.TrimSpace(activeOut)))
	}

	domains, err := certificateDomains(letsEncryptLiveDir)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("list issued certificates: %w", err)
	}
	if len(domains) == 0 {
		lines = append(lines, "no Let's Encrypt certificates issued yet")
		return strings.Join(lines, "\n"), nil
	}

	now := time.Now()
	for _, domain := range domains {
		notAfter, err := certificateExpiry(filepath.Join(letsEncryptLiveDir, domain, "cert.pem"))
		if err != nil {
			lines = append(lines, fmt.Sprintf("%s: %v", domain, err))
			continue
		}
		daysLeft := int(notAfter.Sub(now).Hours() / 24)
		warn := ""
		if daysLeft < 0 {
			warn = " — EXPIRED"
		} else if daysLeft < 15 {
			warn = " — renewal due soon"
		}
		lines = append(lines, fmt.Sprintf("%s: expires %s (%d days)%s", domain, notAfter.Format("2006-01-02"), daysLeft, warn))
	}
	return strings.Join(lines, "\n"), nil
}

// certificateDomains lists the domain directories certbot has created
// under liveDir, sorted for stable, deterministic output.
func certificateDomains(liveDir string) ([]string, error) {
	entries, err := os.ReadDir(liveDir)
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, e := range entries {
		// certbot also writes a non-directory README into the live dir;
		// only real per-domain directories are certificates.
		if e.IsDir() {
			domains = append(domains, e.Name())
		}
	}
	sort.Strings(domains)
	return domains, nil
}

// certificateExpiry parses a PEM certificate file and returns its NotAfter
// time, without ever shelling out to `openssl` or `certbot`.
func certificateExpiry(certPath string) (time.Time, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("read certificate: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM data found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}
