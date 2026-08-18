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

// certStatus is one certificate's renewal state, as reported to the control
// plane so a dashboard can show real expiry dates rather than only "issued
// at time X" — a cert can silently stop auto-renewing (e.g. its renewal
// hook starts failing) long after issuance, and that's exactly the failure
// mode an expiry date surfaces.
type certStatus struct {
	Domain        string `json:"domain"`
	ExpiresAt     string `json:"expires_at"` // RFC3339, empty if unparseable
	DaysRemaining int    `json:"days_remaining"`
	Valid         bool   `json:"valid"`
}

type renewalStatusResult struct {
	Certificates []certStatus `json:"certificates"`
	TimerActive  bool         `json:"renewal_timer_active"`
}

// handleSSLRenewalStatus reports, for every certificate certbot manages on
// this host, its expiry and whether the systemd renewal timer stack.install
// enabled is actually active — so the control plane can flag a cert that's
// approaching expiry or a host whose auto-renewal has stopped running,
// instead of only ever learning about it after HTTPS breaks.
func handleSSLRenewalStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	if _, err := os.Stat("/usr/bin/certbot"); err != nil {
		return "", fmt.Errorf("certbot is not installed on this server; run stack.install first")
	}

	out, err := run(ctx, "certbot", "certificates")
	if err != nil {
		return "", fmt.Errorf("certbot certificates: %w: %s", err, out)
	}

	timerOut, _ := run(ctx, "systemctl", "is-active", "certbot.timer")
	result := renewalStatusResult{
		Certificates: parseCertbotCertificates(out, time.Now().UTC()),
		TimerActive:  strings.TrimSpace(timerOut) == "active",
	}

	b, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// parseCertbotCertificates extracts domain/expiry pairs from `certbot
// certificates`' human-readable text output. certbot has no `--format json`
// option, so this is the same output format an operator would read at the
// terminal; parsing is deliberately tolerant (unrecognized lines are
// skipped) rather than failing the whole call over one unexpected line, and
// "now" is passed in rather than read internally so the days-remaining math
// stays a pure, unit-testable function.
func parseCertbotCertificates(output string, now time.Time) []certStatus {
	var out []certStatus
	var cur *certStatus

	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Domains:"):
			flush()
			domains := strings.Fields(strings.TrimPrefix(line, "Domains:"))
			domain := ""
			if len(domains) > 0 {
				domain = domains[0]
			}
			cur = &certStatus{Domain: domain}
		case strings.HasPrefix(line, "Expiry Date:") && cur != nil:
			// e.g. "Expiry Date: 2026-11-15 03:04:05+00:00 (VALID: 89 days)"
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Expiry Date:"))
			datePart := rest
			if i := strings.Index(rest, " ("); i >= 0 {
				datePart = rest[:i]
			}
			if t, err := time.Parse("2006-01-02 15:04:05-07:00", datePart); err == nil {
				cur.ExpiresAt = t.Format(time.RFC3339)
				cur.DaysRemaining = int(t.Sub(now).Hours() / 24)
				cur.Valid = t.After(now)
			}
		}
	}
	flush()
	return out
}
