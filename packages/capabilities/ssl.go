package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
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

// certbotCert is one certificate entry as reported by `certbot certificates`.
type certbotCert struct {
	Name       string   `json:"name"`
	Domains    []string `json:"domains"`
	ExpiryRaw  string   `json:"expiry_raw"`
	ExpiresAt  string   `json:"expires_at,omitempty"` // RFC3339, empty if unparseable
	DaysLeft   int      `json:"days_left"`
	DaysLeftOK bool     `json:"days_left_known"`
}

// sslRenewalStatusResult is the JSON detail handleSSLRenewalStatus returns.
type sslRenewalStatusResult struct {
	TimerInstalled bool          `json:"timer_installed"`
	TimerEnabled   bool          `json:"timer_enabled"`
	TimerActive    bool          `json:"timer_active"`
	Certificates   []certbotCert `json:"certificates"`
	CheckedAt      string        `json:"checked_at"`
}

// handleSSLRenewalStatus reports whether Let's Encrypt certificates on this
// server will actually renew themselves: certbot ships a systemd timer
// (certbot.timer) that runs its renewal check twice a day, but installing
// the certbot package does not always leave that timer enabled (and nothing
// re-checks it afterward) — this was the documented "no SSL auto-renewal"
// gap. stack.install now enables the timer as an idempotent step; this
// capability is the read-only way to verify that on an existing server and
// to see, per certificate, how many days remain before expiry, all without
// mutating anything.
func handleSSLRenewalStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	if _, err := os.Stat("/usr/bin/certbot"); err != nil {
		return "", fmt.Errorf("certbot is not installed on this server; run stack.install first")
	}

	progress("checking certbot auto-renewal timer")
	result := sslRenewalStatusResult{TimerInstalled: true, CheckedAt: time.Now().UTC().Format(time.RFC3339)}

	if enabledOut, err := run(ctx, "systemctl", "is-enabled", "certbot.timer"); err == nil {
		result.TimerEnabled = strings.TrimSpace(enabledOut) == "enabled"
	}
	if activeOut, err := run(ctx, "systemctl", "is-active", "certbot.timer"); err == nil {
		result.TimerActive = strings.TrimSpace(activeOut) == "active"
	}

	progress("listing certificates known to certbot")
	certsOut, err := run(ctx, "certbot", "certificates")
	if err != nil {
		return "", fmt.Errorf("certbot certificates: %w: %s", err, certsOut)
	}
	result.Certificates = parseCertbotCertificates(certsOut, time.Now().UTC())

	out, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// parseCertbotCertificates parses the human-readable output of
// `certbot certificates` into structured records. certbot has no stable
// machine-readable output format, so this is deliberately tolerant: any
// line it doesn't recognize is ignored rather than treated as a parse
// error, and a certificate whose expiry date fails to parse is still
// returned (with DaysLeftOK false) instead of being dropped, so a format
// change degrades to "days left unknown" rather than an empty result.
func parseCertbotCertificates(output string, now time.Time) []certbotCert {
	var certs []certbotCert
	var cur *certbotCert

	flush := func() {
		if cur != nil {
			certs = append(certs, *cur)
			cur = nil
		}
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Certificate Name:"):
			flush()
			cur = &certbotCert{Name: strings.TrimSpace(strings.TrimPrefix(trimmed, "Certificate Name:"))}
		case cur == nil:
			continue
		case strings.HasPrefix(trimmed, "Domains:"):
			cur.Domains = strings.Fields(strings.TrimPrefix(trimmed, "Domains:"))
		case strings.HasPrefix(trimmed, "Expiry Date:"):
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "Expiry Date:"))
			// e.g. "2026-11-10 12:00:00+00:00 (VALID: 83 days)" — take
			// everything before the trailing " (...)" annotation.
			datePart := rest
			if i := strings.Index(rest, " ("); i >= 0 {
				datePart = rest[:i]
			}
			cur.ExpiryRaw = rest
			if t, err := time.Parse("2006-01-02 15:04:05-07:00", datePart); err == nil {
				cur.ExpiresAt = t.Format(time.RFC3339)
				cur.DaysLeft = int(t.Sub(now).Hours() / 24)
				cur.DaysLeftOK = true
			}
		}
	}
	flush()
	return certs
}
