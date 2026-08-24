package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// sslLetsEncryptBaseDir and sslCustomBaseDir are where certbot (respectively
// handleSSLInstallCustom) place a domain's live certificate. They're package
// vars, not inline literals, purely so tests can point them at a temp
// directory instead of the real `/etc` paths.
var (
	sslLetsEncryptBaseDir = "/etc/letsencrypt/live"
	sslCustomBaseDir      = "/etc/serverpanel-agent/ssl"
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

	certDir := sslCustomBaseDir + "/" + domain
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

// sslStatusResult is handleSSLStatus's JSON detail — the control plane
// unmarshals this to persist a site's SSL state and, later, to drive
// expiry-based alerting (docs/SYSTEM.md §20's still-open "no SSL-expiration
// alerts" gap).
type sslStatusResult struct {
	Domain    string `json:"domain"`
	Status    string `json:"status"`               // "none" | "valid" | "expiring_soon" | "expired"
	Issuer    string `json:"issuer,omitempty"`     // "letsencrypt" | "custom"
	ExpiresAt string `json:"expires_at,omitempty"` // RFC 3339, empty if Status is "none"
}

// sslExpirySoonWindow is how far ahead of a certificate's actual expiry
// handleSSLStatus starts reporting "expiring_soon" instead of "valid" — long
// enough that a daily/weekly dashboard check (or, once built, a scheduled
// alert) has more than one chance to catch it before it lapses.
const sslExpirySoonWindow = 14 * 24 * time.Hour

// handleSSLStatus is a read-only check of a domain's currently installed
// certificate: whether one exists, who issued it (Let's Encrypt vs a
// custom upload), and when it expires. It never issues, renews, or
// modifies anything — see handleSSLIssueLetsEncrypt/handleSSLInstallCustom
// for that — which is what makes it safe to call as often as the control
// plane wants (e.g. every time a site's detail view is opened).
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}

	leCertPath := sslLetsEncryptBaseDir + "/" + domain + "/cert.pem"
	customCertPath := sslCustomBaseDir + "/" + domain + "/fullchain.pem"

	var certPath, issuer string
	switch {
	case fileExists(leCertPath):
		certPath, issuer = leCertPath, "letsencrypt"
	case fileExists(customCertPath):
		certPath, issuer = customCertPath, "custom"
	default:
		return marshalSSLStatus(sslStatusResult{Domain: domain, Status: "none"})
	}

	progress("reading certificate expiry for " + domain)
	out, err := run(ctx, "openssl", "x509", "-in", certPath, "-noout", "-enddate")
	if err != nil {
		return "", fmt.Errorf("read certificate expiry: %w: %s", err, out)
	}
	const prefix = "notAfter="
	idx := strings.Index(out, prefix)
	if idx == -1 {
		return "", fmt.Errorf("unexpected `openssl x509 -enddate` output: %s", out)
	}
	// openssl's -enddate format, e.g. "Jan  2 15:04:05 2027 GMT" — "_2" is
	// Go's space-padded-day layout verb, matching openssl's own padding of
	// single-digit days.
	expiresAt, err := time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimSpace(out[idx+len(prefix):]))
	if err != nil {
		return "", fmt.Errorf("parse certificate expiry %q: %w", out, err)
	}

	status := "valid"
	switch {
	case time.Now().After(expiresAt):
		status = "expired"
	case time.Until(expiresAt) < sslExpirySoonWindow:
		status = "expiring_soon"
	}

	return marshalSSLStatus(sslStatusResult{
		Domain: domain, Status: status, Issuer: issuer,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}

func marshalSSLStatus(r sslStatusResult) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
