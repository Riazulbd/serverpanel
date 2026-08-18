package capabilities

import (
	"context"
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

// certbotCert is one certificate lease as reported by `certbot certificates`.
type certbotCert struct {
	Name       string
	ExpiryDate time.Time
}

// parseCertbotCertificates parses the human-readable output of `certbot
// certificates` into structured records. It's a pure function (no process
// execution) specifically so the parsing logic can be unit-tested against
// fixed sample output without a real certbot install.
func parseCertbotCertificates(output string) []certbotCert {
	var certs []certbotCert
	var cur certbotCert
	have := false

	flush := func() {
		if have {
			certs = append(certs, cur)
		}
	}

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Certificate Name:"):
			flush()
			cur = certbotCert{Name: strings.TrimSpace(strings.TrimPrefix(line, "Certificate Name:"))}
			have = true
		case strings.HasPrefix(line, "Expiry Date:"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Expiry Date:"))
			if idx := strings.Index(rest, " ("); idx >= 0 {
				rest = rest[:idx]
			}
			if t, err := time.Parse("2006-01-02 15:04:05-07:00", rest); err == nil {
				cur.ExpiryDate = t
			}
		}
	}
	flush()
	return certs
}

// handleSSLStatus reports a domain's Let's Encrypt certificate expiry and
// whether certbot's automatic-renewal timer is enabled/running, closing the
// "renewal monitoring" gap: stack.install enables certbot.timer, but nothing
// short of checking here would surface a renewal that silently stopped
// working (revoked API access, DNS changed, disk full, etc.) before the
// certificate actually expired.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if _, err := os.Stat("/usr/bin/certbot"); err != nil {
		return "", fmt.Errorf("certbot is not installed on this server; run stack.install first")
	}

	progress("checking certbot auto-renewal timer")
	timerActive, _ := run(ctx, "systemctl", "is-active", "certbot.timer")
	timerEnabled, _ := run(ctx, "systemctl", "is-enabled", "certbot.timer")

	progress("checking certificate for " + domain)
	out, err := run(ctx, "certbot", "certificates", "-d", domain)
	if err != nil {
		return "", fmt.Errorf("certbot certificates: %w: %s", err, out)
	}

	certs := parseCertbotCertificates(out)
	if len(certs) == 0 || certs[0].ExpiryDate.IsZero() {
		return "", fmt.Errorf("no certificate found for %s (issue one with ssl.issue_letsencrypt first)", domain)
	}
	c := certs[0]

	daysLeft := int(time.Until(c.ExpiryDate).Hours() / 24)
	warning := ""
	if strings.TrimSpace(timerActive) != "active" || strings.TrimSpace(timerEnabled) != "enabled" {
		warning = " — WARNING: auto-renewal timer is not active, this certificate will not renew automatically"
	} else if daysLeft < 14 {
		warning = " — WARNING: expires soon; if this persists past today's renewal window, renewal may be failing"
	}

	return fmt.Sprintf("domain=%s expires=%s days_remaining=%d renewal_timer_enabled=%s renewal_timer_active=%s%s",
		domain, c.ExpiryDate.Format("2006-01-02"), daysLeft,
		strings.TrimSpace(timerEnabled), strings.TrimSpace(timerActive), warning), nil
}
