package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
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

// certInfo is one Let's Encrypt certificate as reported by `certbot
// certificates`, plus whether the automatic renewal timer that's supposed
// to keep it current is actually enabled — the two things an operator or
// an alerting rule actually needs to know: "is this about to expire" and
// "will it renew itself before then."
type certInfo struct {
	Domains    []string `json:"domains"`
	ExpiryDate string   `json:"expiry_date"`
	DaysLeft   int      `json:"days_left"`
}

type sslStatusReport struct {
	RenewalTimerActive bool       `json:"renewal_timer_active"`
	Certificates       []certInfo `json:"certificates"`
}

// handleSSLStatus reports every Let's Encrypt certificate certbot knows
// about on this server plus renewal-timer health, so the control plane can
// surface "certificate expires in N days" without the dashboard having to
// SSH in or duplicate certbot's own bookkeeping.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	report := sslStatusReport{RenewalTimerActive: certbotTimerActive(ctx)}

	if _, err := os.Stat("/usr/bin/certbot"); err == nil {
		out, _ := run(ctx, "certbot", "certificates")
		report.Certificates = parseCertbotCertificates(out)
	}

	data, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

var (
	certDomainsRe = regexp.MustCompile(`(?m)^\s*Domains:\s*(.+)$`)
	certExpiryRe  = regexp.MustCompile(`(?m)^\s*Expiry Date:\s*(\S+ \S+).*VALID:\s*(-?\d+)\s*days?\)`)
)

// parseCertbotCertificates extracts domain/expiry/days-remaining from the
// human-readable output of `certbot certificates`. It's a pure function
// (no exec, no filesystem) specifically so this parsing logic — which is
// the part most likely to break across certbot versions — is unit-testable
// without root or a real certbot install.
func parseCertbotCertificates(output string) []certInfo {
	domainMatches := certDomainsRe.FindAllStringSubmatch(output, -1)
	expiryMatches := certExpiryRe.FindAllStringSubmatch(output, -1)

	var certs []certInfo
	for i := range domainMatches {
		c := certInfo{Domains: strings.Fields(domainMatches[i][1])}
		if i < len(expiryMatches) {
			c.ExpiryDate = expiryMatches[i][1]
			if days, err := strconv.Atoi(expiryMatches[i][2]); err == nil {
				c.DaysLeft = days
			}
		}
		certs = append(certs, c)
	}
	return certs
}
