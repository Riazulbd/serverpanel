package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// letsEncryptLiveDir and customSSLBaseDir are vars (not consts), matching
// backupBaseDir's pattern, so tests can point them at a temp directory
// instead of the real system paths.
var (
	letsEncryptLiveDir = "/etc/letsencrypt/live"
	customSSLBaseDir   = "/etc/serverpanel-agent/ssl"
)

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

	certDir := filepath.Join(customSSLBaseDir, domain)
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

// sslStatusResult is handleSSLStatus's JSON-encoded Detail payload — real,
// freshly-observed state (the certificate actually on disk, the renewal
// timer's actual systemd state), never a value the control plane assumed or
// cached, so the dashboard's SSL status can't drift from reality.
type sslStatusResult struct {
	Domain            string    `json:"domain"`
	Present           bool      `json:"present"`
	Issuer            string    `json:"issuer,omitempty"` // "letsencrypt" | "custom"
	NotAfter          time.Time `json:"not_after,omitempty"`
	DaysRemaining     int       `json:"days_remaining,omitempty"`
	AutoRenewalActive bool      `json:"auto_renewal_active"`
}

// handleSSLStatus reports a domain's actual on-disk certificate expiry (Let's
// Encrypt or custom-installed, whichever is present) and whether certbot's
// systemd renewal timer is active — the two facts needed to answer "is this
// certificate actually going to renew itself." It never issues, renews, or
// modifies anything; it's a read-only diagnostic capability.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}

	result := sslStatusResult{Domain: domain, AutoRenewalActive: certbotTimerActive(ctx)}

	lePath := filepath.Join(letsEncryptLiveDir, domain, "fullchain.pem")
	customPath := filepath.Join(customSSLBaseDir, domain, "fullchain.pem")

	certPath, issuer := "", ""
	if _, err := os.Stat(lePath); err == nil {
		certPath, issuer = lePath, "letsencrypt"
	} else if _, err := os.Stat(customPath); err == nil {
		certPath, issuer = customPath, "custom"
	}

	if certPath != "" {
		progress("reading certificate expiry for " + domain)
		notAfter, err := certExpiryFromFile(ctx, certPath)
		if err != nil {
			return "", fmt.Errorf("read certificate expiry: %w", err)
		}
		result.Present = true
		result.Issuer = issuer
		result.NotAfter = notAfter
		result.DaysRemaining = int(time.Until(notAfter).Hours() / 24)
	}

	data, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// certbotTimerActive reports whether certbot's systemd renewal timer is
// currently active. Used both by ssl.status (to surface real state to the
// dashboard) and by stack.install's idempotent "enable the timer" step.
func certbotTimerActive(ctx context.Context) bool {
	out, _ := run(ctx, "systemctl", "is-active", "certbot.timer")
	return strings.TrimSpace(out) == "active"
}

// certExpiryFromFile shells out to openssl (never parses X.509 DER/PEM by
// hand here — openssl's own parser is what's authoritative for whatever
// certbot or a custom upload actually wrote to disk) to read a certificate
// file's expiry.
func certExpiryFromFile(ctx context.Context, path string) (time.Time, error) {
	out, err := run(ctx, "openssl", "x509", "-enddate", "-noout", "-in", path)
	if err != nil {
		return time.Time{}, fmt.Errorf("openssl: %w: %s", err, out)
	}
	return parseOpenSSLEndDate(out)
}

// parseOpenSSLEndDate parses `openssl x509 -enddate -noout`'s output, e.g.
// "notAfter=Aug 17 12:00:00 2026 GMT".
func parseOpenSSLEndDate(output string) (time.Time, error) {
	line := strings.TrimSpace(output)
	const prefix = "notAfter="
	if !strings.HasPrefix(line, prefix) {
		return time.Time{}, fmt.Errorf("unexpected openssl output: %q", line)
	}
	return time.Parse("Jan 2 15:04:05 2006 MST", strings.TrimPrefix(line, prefix))
}
