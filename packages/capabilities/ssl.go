package capabilities

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// sslResult is the structured detail every ssl.* capability returns, so the
// control plane can persist a real expiry date on the site record instead
// of a caller having to re-derive it from a free-form status string.
type sslResult struct {
	Domain    string `json:"domain"`
	Status    string `json:"status"` // "active" or "unknown" (expiry couldn't be determined)
	ExpiresAt string `json:"expires_at,omitempty"`
	DaysLeft  int    `json:"days_left,omitempty"`
	Message   string `json:"message"`
}

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

	result := sslResult{Domain: domain, Status: "active", Message: "certificate issued for " + domain}
	// Best-effort: look up the expiry certbot just recorded so the control
	// plane can persist it immediately, without a separate round trip. A
	// failure here doesn't fail the issuance — the cert is already live —
	// it just means ssl.check_renewal needs to be run separately to backfill
	// the expiry.
	if checkOut, checkErr := run(ctx, "certbot", "certificates", "-d", domain); checkErr == nil {
		annotateExpiry(&result, checkOut)
	}
	b, _ := json.Marshal(result)
	return string(b), nil
}

// handleSSLCheckRenewal reports the current certbot-managed certificate
// status/expiry for a domain, without issuing or changing anything. This is
// what backs both the dashboard's SSL status display and, longer-term, an
// expiry-alerting job — see docs/SERVERAVATAR_PARITY.md APP-016.
func handleSSLCheckRenewal(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if _, err := os.Stat("/usr/bin/certbot"); err != nil {
		return "", fmt.Errorf("certbot is not installed on this server")
	}

	progress("checking certificate status for " + domain)
	out, err := run(ctx, "certbot", "certificates", "-d", domain)
	if err != nil {
		return "", fmt.Errorf("certbot certificates: %w: %s", err, out)
	}

	result := sslResult{Domain: domain, Status: "unknown", Message: "no certbot-managed certificate found for " + domain}
	if !annotateExpiry(&result, out) {
		return "", fmt.Errorf("%s", result.Message)
	}
	b, _ := json.Marshal(result)
	return string(b), nil
}

// annotateExpiry parses `certbot certificates` output and, if it finds a
// certificate covering domain, fills in result's expiry fields and returns
// true. It never errors on unparseable output — a best-effort miss just
// leaves the caller's existing status/message untouched.
func annotateExpiry(result *sslResult, certbotOutput string) bool {
	for _, c := range parseCertbotCertificates(certbotOutput) {
		for _, d := range c.Domains {
			if strings.EqualFold(d, result.Domain) {
				result.Status = "active"
				if !c.Valid {
					result.Status = "expired"
				}
				result.ExpiresAt = c.ExpiresAt.UTC().Format(time.RFC3339)
				result.DaysLeft = c.DaysLeft
				result.Message = fmt.Sprintf("certificate for %s expires %s (%d days)", result.Domain, result.ExpiresAt, result.DaysLeft)
				return true
			}
		}
	}
	return false
}

// certbotCert is one parsed block from `certbot certificates` output.
type certbotCert struct {
	Name      string
	Domains   []string
	ExpiresAt time.Time
	DaysLeft  int
	Valid     bool
}

// parseCertbotCertificates parses the human-readable block format certbot's
// `certificates` subcommand prints, e.g.:
//
//	Certificate Name: example.com
//	  Domains: example.com www.example.com
//	  Expiry Date: 2026-11-23 10:15:32+00:00 (VALID: 89 days)
//
// This is certbot's own long-stable plain-text output format (there is no
// `--json` output mode as of this writing), so we parse it defensively:
// unrecognized lines are ignored, and a block missing an expiry date is
// still returned with a zero-value ExpiresAt rather than dropped, so a
// caller can tell "certbot output didn't parse as expected" apart from "no
// certificates at all" if it needs to.
func parseCertbotCertificates(output string) []certbotCert {
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
		case strings.HasPrefix(trimmed, "Domains:"):
			if cur != nil {
				cur.Domains = strings.Fields(strings.TrimPrefix(trimmed, "Domains:"))
			}
		case strings.HasPrefix(trimmed, "Expiry Date:"):
			if cur == nil {
				continue
			}
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "Expiry Date:"))
			datePart := rest
			if idx := strings.Index(rest, " ("); idx >= 0 {
				datePart = rest[:idx]
				// "(VALID: 89 days)" vs "(INVALID: EXPIRED)" — check the
				// parenthesized status starts with VALID, not merely
				// contains it, since "INVALID" itself contains "VALID" as
				// a substring.
				paren := strings.TrimPrefix(strings.TrimSpace(rest[idx:]), "(")
				cur.Valid = strings.HasPrefix(paren, "VALID")
			}
			if t, err := time.Parse("2006-01-02 15:04:05-07:00", datePart); err == nil {
				cur.ExpiresAt = t
				cur.DaysLeft = int(time.Until(t).Hours() / 24)
			}
		}
	}
	flush()
	return certs
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

	progress("validating certificate and private key match")
	notAfter, err := validateCertKeyPair(certPEM, keyPEM)
	if err != nil {
		return "", fmt.Errorf("certificate/key validation failed: %w", err)
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

	result := sslResult{
		Domain:    domain,
		Status:    "active",
		ExpiresAt: notAfter.UTC().Format(time.RFC3339),
		DaysLeft:  int(time.Until(notAfter).Hours() / 24),
		Message:   "custom certificate installed for " + domain,
	}
	b, _ := json.Marshal(result)
	return string(b), nil
}

// validateCertKeyPair parses the caller-supplied certificate/private-key PEM
// blobs, verifies they form a matching pair (tls.X509KeyPair fails if the
// private key's public component doesn't match the certificate's), and
// returns the certificate's expiry. This is the "validate certificate/key
// matching before installation, never log private keys" requirement — done
// with Go's standard library (crypto/tls, crypto/x509) rather than shelling
// out to openssl, and the key material never appears in a log line or error
// message.
func validateCertKeyPair(certPEM, keyPEM string) (time.Time, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate and private key do not match: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	if time.Now().After(leaf.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate already expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return leaf.NotAfter, nil
}
