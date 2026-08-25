package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// sslResult is the JSON shape every ssl.* capability returns as its
// TaskEvent detail, so the control plane always has a structured expiry
// to persist (sites.ssl_issuer/ssl_expires_at) instead of having to
// separately dispatch ssl.status after every issue/renew/install just to
// find out when the new certificate expires.
type sslResult struct {
	Domain        string `json:"domain"`
	Status        string `json:"status"` // "active" or "none"
	Issuer        string `json:"issuer,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"` // RFC3339, UTC
	DaysRemaining int    `json:"days_remaining,omitempty"`
}

// letsEncryptDir and customSSLDir are vars (not consts) so tests can point
// them at a temp directory instead of writing into the real
// /etc/letsencrypt and /etc/serverpanel-agent/ssl on the machine running
// `go test`, matching the backupBaseDir pattern in backup.go.
var (
	letsEncryptDir = "/etc/letsencrypt/live"
	customSSLDir   = "/etc/serverpanel-agent/ssl"
)

// certLocations is the fixed, ordered set of places this agent ever writes
// a certificate for a domain — certbot's own layout for Let's Encrypt
// certs, and the path handleSSLInstallCustom writes custom certs to. There
// is no caller-supplied path here, so certExpiry can never be pointed at
// an arbitrary file.
func certLocations(domain string) []struct{ issuer, path string } {
	return []struct{ issuer, path string }{
		{"letsencrypt", letsEncryptDir + "/" + domain + "/fullchain.pem"},
		{"custom", customSSLDir + "/" + domain + "/fullchain.pem"},
	}
}

// certExpiry reports the current certificate status for domain by reading
// whichever known certificate path exists first (Let's Encrypt takes
// precedence, matching nginx's own vhost preference once ssl.issue_letsencrypt
// has run) and asking openssl for its expiry — never parsing the
// certificate's ASN.1 by hand.
func certExpiry(ctx context.Context, domain string) (sslResult, error) {
	res := sslResult{Domain: domain, Status: "none"}
	for _, loc := range certLocations(domain) {
		if _, err := os.Stat(loc.path); err != nil {
			continue
		}
		out, err := run(ctx, "openssl", "x509", "-enddate", "-noout", "-in", loc.path)
		if err != nil {
			return res, fmt.Errorf("openssl: %w: %s", err, out)
		}
		const prefix = "notAfter="
		idx := strings.Index(out, prefix)
		if idx < 0 {
			return res, fmt.Errorf("unexpected openssl output for %s: %s", domain, out)
		}
		// openssl prints e.g. "notAfter=Jan  2 15:04:05 2026 GMT" — the
		// double space before a single-digit day isn't matched reliably
		// by every Go layout element, so collapse whitespace first rather
		// than depend on that quirk.
		raw := strings.Join(strings.Fields(out[idx+len(prefix):]), " ")
		expiresAt, err := time.Parse("Jan 2 15:04:05 2006 MST", raw)
		if err != nil {
			return res, fmt.Errorf("parse certificate expiry for %s: %w", domain, err)
		}
		res.Status = "active"
		res.Issuer = loc.issuer
		res.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
		res.DaysRemaining = int(time.Until(expiresAt).Hours() / 24)
		return res, nil
	}
	return res, nil
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

	res, err := certExpiry(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("certificate was issued but its expiry could not be verified: %w", err)
	}
	if res.Status != "active" {
		return "", fmt.Errorf("certbot reported success but no certificate was found on disk for %s", domain)
	}
	b, _ := json.Marshal(res)
	return string(b), nil
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

	certDir := customSSLDir + "/" + domain
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

	res, err := certExpiry(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("certificate was installed but its expiry could not be verified: %w", err)
	}
	b, _ := json.Marshal(res)
	return string(b), nil
}

// handleSSLStatus reports the current certificate status for a domain
// without changing anything — used both for on-demand refresh from the
// dashboard and by the control plane's renewal scheduler to record expiry
// drift even when no renewal was due.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	res, err := certExpiry(ctx, domain)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(res)
	return string(b), nil
}

// handleSSLRenew renews an already-issued Let's Encrypt certificate via
// `certbot renew`, which is itself due-date-aware (a no-op unless the
// certificate is within its renewal window) — the control plane's renewal
// scheduler calls this unconditionally on a timer rather than trying to
// duplicate certbot's own renewal-window logic in Go.
func handleSSLRenew(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if _, err := os.Stat("/usr/bin/certbot"); err != nil {
		return "", fmt.Errorf("certbot is not installed on this server")
	}
	if _, err := os.Stat(letsEncryptDir + "/" + domain + "/fullchain.pem"); err != nil {
		return "", fmt.Errorf("no existing Let's Encrypt certificate for %s to renew; issue one first", domain)
	}

	progress("checking renewal window for " + domain)
	out, err := run(ctx, "certbot", "renew", "--cert-name", domain, "--non-interactive", "--agree-tos")
	if err != nil {
		return "", fmt.Errorf("certbot renew: %w: %s", err, out)
	}

	res, err := certExpiry(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("renew ran but expiry could not be verified: %w", err)
	}
	b, _ := json.Marshal(res)
	return string(b), nil
}
