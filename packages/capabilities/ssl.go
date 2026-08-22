package capabilities

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// customSSLDir and letsEncryptLiveDir are vars (not consts) so tests can
// point them at a temp directory, matching the backupBaseDir pattern in
// backup.go.
var (
	customSSLDir       = "/etc/serverpanel-agent/ssl"
	letsEncryptLiveDir = "/etc/letsencrypt/live"
)

// sslResult is what ssl.issue_letsencrypt, ssl.install_custom and
// ssl.status all return as their TaskEvent detail (JSON) — the control
// plane parses this to persist the site's current certificate type and
// expiry (apps/controlplane/ssl.go), the same "agent is the source of
// truth for what actually happened" pattern backupResult/restoreResult
// use.
type sslResult struct {
	Domain    string `json:"domain"`
	Type      string `json:"type"` // "letsencrypt", "custom", or "none"
	Issuer    string `json:"issuer,omitempty"`
	IssuedAt  string `json:"issued_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// handleSSLIssueLetsEncrypt issues (or renews) a Let's Encrypt certificate
// for a domain using certbot's nginx plugin with a fixed, non-interactive
// argv — the domain is the only caller-supplied value, and it's the same
// domain already validated and vhost-configured by site.create, so this
// only ever points certbot at a site the control plane already knows
// about. certbot's nginx plugin edits the vhost file in place (adding the
// listen 443/ssl_certificate directives and an HTTP->HTTPS redirect)
// rather than this agent reimplementing that — certbot is the
// battle-tested tool for exactly that job, and stack.install's "certbot
// renewal timer" step (stack.go) keeps the resulting certificate renewing
// itself afterward.
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

	res := sslResult{Domain: domain, Type: "letsencrypt"}
	if cert, err := loadCertFile(filepath.Join(letsEncryptLiveDir, domain, "fullchain.pem")); err == nil {
		res.Issuer = cert.Issuer.CommonName
		res.IssuedAt = cert.NotBefore.UTC().Format(time.RFC3339)
		res.ExpiresAt = cert.NotAfter.UTC().Format(time.RFC3339)
	} else {
		progress(fmt.Sprintf("certificate issued but its expiry could not be read back (%v)", err))
	}
	detail, _ := json.Marshal(res)
	return string(detail), nil
}

// handleSSLInstallCustom installs a user-supplied certificate/key pair for
// a domain. The certificate and key are validated as a matching, currently
// valid pair for this exact domain BEFORE anything is written to disk —
// installing a cert that doesn't match its key, or that was issued for a
// different domain, would otherwise silently leave HTTPS visitors with a
// browser trust error indistinguishable from a real misconfiguration. Both
// PEM blobs are written with restrictive permissions and the site's vhost
// is regenerated with a real HTTPS server block referencing them (not just
// dropped on disk with nothing pointing at them) — the previous vhost
// content is restored automatically if the new config fails `nginx -t`, so
// a bad upload can never take a working site offline.
func handleSSLInstallCustom(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	sysUser, _ := params["system_user"].(string)
	docroot, _ := params["docroot"].(string)
	appType, _ := params["app_type"].(string)
	phpVersion, _ := params["php_version"].(string)
	tempDomain, _ := params["temp_domain"].(string)
	certPEM, _ := params["cert_pem"].(string)
	keyPEM, _ := params["key_pem"].(string)

	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return "", fmt.Errorf("invalid system_user")
	}
	if docroot == "" || !strings.HasPrefix(filepath.Clean(docroot), "/home/sites/") {
		return "", fmt.Errorf("invalid docroot")
	}
	if appType != "static" && appType != "php" && appType != "wordpress" {
		return "", fmt.Errorf("unsupported app_type %q", appType)
	}
	if certPEM == "" || keyPEM == "" {
		return "", fmt.Errorf("cert_pem and key_pem are required")
	}

	progress("validating certificate/key pair for " + domain)
	cert, err := validateCertKeyPair(domain, certPEM, keyPEM)
	if err != nil {
		return "", err
	}

	certDir := filepath.Join(customSSLDir, domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", err
	}
	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return "", fmt.Errorf("write certificate: %w", err)
	}
	// Never log key material: keyPEM itself is never passed to progress()
	// or included in any returned error/detail, only the fixed file path.
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	progress("updating nginx vhost with the new certificate")
	locationBlock := vhostLocationBlock(sysUser, appType, phpVersion)
	newVhost := sslVhostContent(domain, tempDomain, docroot, sysUser, locationBlock, certPath, keyPath)
	if err := writeVhostAtomic(ctx, nginxVhostPath(sysUser), newVhost); err != nil {
		return "", err
	}
	run(ctx, "systemctl", "reload", "nginx")

	res := sslResult{
		Domain: domain, Type: "custom", Issuer: cert.Issuer.CommonName,
		IssuedAt: cert.NotBefore.UTC().Format(time.RFC3339), ExpiresAt: cert.NotAfter.UTC().Format(time.RFC3339),
	}
	detail, _ := json.Marshal(res)
	return string(detail), nil
}

// handleSSLStatus reports the certificate currently active for a domain,
// reading straight off disk (the same source of truth nginx itself
// serves from) rather than trusting whatever the control plane last
// recorded — a certificate could have been renewed, replaced, or removed
// outside of this agent's own last observation.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}

	if cert, err := loadCertFile(filepath.Join(letsEncryptLiveDir, domain, "fullchain.pem")); err == nil {
		return marshalSSLStatus(domain, "letsencrypt", cert), nil
	}
	if cert, err := loadCertFile(filepath.Join(customSSLDir, domain, "fullchain.pem")); err == nil {
		return marshalSSLStatus(domain, "custom", cert), nil
	}

	detail, _ := json.Marshal(sslResult{Domain: domain, Type: "none"})
	return string(detail), nil
}

func marshalSSLStatus(domain, sslType string, cert *x509.Certificate) string {
	res := sslResult{
		Domain: domain, Type: sslType, Issuer: cert.Issuer.CommonName,
		IssuedAt: cert.NotBefore.UTC().Format(time.RFC3339), ExpiresAt: cert.NotAfter.UTC().Format(time.RFC3339),
	}
	detail, _ := json.Marshal(res)
	return string(detail)
}

// validateCertKeyPair parses certPEM/keyPEM as a matching pair (via the
// standard library's own PEM+key-match validation, rather than reimplementing
// certificate cryptography here) and confirms the certificate is currently
// valid (not expired, not-yet-valid) and issued for domain.
func validateCertKeyPair(domain, certPEM, keyPEM string) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate and private key do not form a valid pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate found in cert_pem")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("certificate is not valid yet (starts %s)", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate expired %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	if err := cert.VerifyHostname(domain); err != nil {
		return nil, fmt.Errorf("certificate is not valid for %q: %w", domain, err)
	}
	return cert, nil
}

// loadCertFile reads and parses the leaf certificate at path, used by both
// ssl.status and the post-issuance expiry readback in
// handleSSLIssueLetsEncrypt/handleSSLInstallCustom.
func loadCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate block found in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// sslVhostContent builds an HTTPS-enabled vhost: an HTTP server block that
// keeps ACME HTTP-01 challenges reachable (so a later ssl.issue_letsencrypt
// call, or certbot's own renewal, still works) and redirects everything
// else to HTTPS, plus the HTTPS server block itself referencing the
// installed certificate.
func sslVhostContent(domain, tempDomain, docroot, sysUser, locationBlock, certPath, keyPath string) string {
	ipv6Listen80, ipv6Listen443 := "", ""
	if ipv6Available() {
		ipv6Listen80 = "\n    listen [::]:80;"
		ipv6Listen443 = "\n    listen [::]:443 ssl;"
	}

	return fmt.Sprintf(`# Managed by ServerPanel for %[1]s (temp domain: %[2]s). Do not edit by
# hand; changes made through the dashboard regenerate this file.
server {
    listen 80;%[8]s
    server_name %[1]s %[2]s;
    root %[3]s;

    location /.well-known/acme-challenge/ {
        root %[3]s;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;%[9]s
    server_name %[1]s %[2]s;
    root %[3]s;

    ssl_certificate %[6]s;
    ssl_certificate_key %[7]s;

%[4]s

    access_log /var/log/nginx/%[5]s.access.log;
    error_log  /var/log/nginx/%[5]s.error.log;
}
`, domain, tempDomain, docroot, locationBlock, sysUser, certPath, keyPath, ipv6Listen80, ipv6Listen443)
}

// writeVhostAtomic overwrites path with newContent, verifies the result
// with `nginx -t`, and — if that fails — restores the file to exactly
// what it contained before (or removes it, if it didn't exist yet) rather
// than leaving a syntactically broken vhost sitting in sites-enabled,
// which would break nginx -t (and so every other site's next config
// change) until someone notices and fixes it by hand.
func writeVhostAtomic(ctx context.Context, path, newContent string) error {
	previous, readErr := os.ReadFile(path)
	existed := readErr == nil
	rollback := func() {
		if existed {
			os.WriteFile(path, previous, 0644)
		} else {
			os.Remove(path)
		}
	}

	if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("write vhost: %w", err)
	}
	if out, err := run(ctx, "nginx", "-t"); err != nil {
		rollback()
		return fmt.Errorf("nginx config test failed, previous vhost restored, certificate not activated: %w: %s", err, out)
	}
	return nil
}
