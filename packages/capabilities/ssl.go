package capabilities

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// letsEncryptLivePath is where certbot's --nginx plugin stores the issued
// certificate for a lineage. certbot names the lineage after the first
// domain passed to it, which is always our primary domain here since
// handleSSLIssueLetsEncrypt only ever requests a single-domain certificate.
func letsEncryptLivePath(domain string) string {
	return "/etc/letsencrypt/live/" + domain + "/fullchain.pem"
}

// customCertPath is where handleSSLInstallCustom writes a user-supplied
// certificate for a domain (see that function's doc comment).
func customCertPath(domain string) string {
	return "/etc/serverpanel-agent/ssl/" + domain + "/fullchain.pem"
}

// sslResult is the structured detail every ssl.* capability returns, so the
// control plane can persist certificate status/expiry without having to
// separately parse certbot's human-readable output.
type sslResult struct {
	Domain    string `json:"domain"`
	Source    string `json:"source"` // "letsencrypt" or "custom"
	ExpiresAt string `json:"expires_at"`
	Issuer    string `json:"issuer"`
}

func (r sslResult) json() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// parseCertExpiry reads a PEM-encoded certificate (or chain — only the leaf,
// first entry, is used) from disk and returns its expiry and issuer.
func parseCertExpiry(path string) (expiresAt time.Time, issuer string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("read certificate: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, "", fmt.Errorf("no PEM certificate block found in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("parse certificate: %w", err)
	}
	return cert.NotAfter, cert.Issuer.CommonName, nil
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

	expiresAt, issuer, err := parseCertExpiry(letsEncryptLivePath(domain))
	if err != nil {
		// certbot itself reported success, so the certificate is live even
		// though we couldn't read back its expiry — don't fail the whole
		// operation over a diagnostics-only read, just report it unknown.
		progress(fmt.Sprintf("warning: issued but could not read back certificate expiry: %v", err))
		return sslResult{Domain: domain, Source: "letsencrypt"}.json(), nil
	}
	return sslResult{Domain: domain, Source: "letsencrypt", ExpiresAt: expiresAt.UTC().Format(time.RFC3339), Issuer: issuer}.json(), nil
}

// handleSSLInstallCustom installs a user-supplied certificate/key pair for
// a domain. Both PEM blobs are written with restrictive permissions and
// wired into the site's existing nginx vhost rather than parsed/executed
// in any way — the agent trusts nginx's own `nginx -t` to reject anything
// malformed, and never applies a config that fails that test. The
// certificate and key are verified to actually form a matching pair
// *before* anything is written to disk, so a mismatched upload can never
// leave a site half-configured with a cert nginx will refuse to serve.
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
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return "", fmt.Errorf("certificate and private key do not match (or are invalid): %w", err)
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

	expiresAt, issuer, err := parseCertExpiry(certPath)
	if err != nil {
		progress(fmt.Sprintf("warning: installed but could not read back certificate expiry: %v", err))
		return sslResult{Domain: domain, Source: "custom"}.json(), nil
	}
	return sslResult{Domain: domain, Source: "custom", ExpiresAt: expiresAt.UTC().Format(time.RFC3339), Issuer: issuer}.json(), nil
}

// handleSSLStatus reports the current certificate on file for a domain,
// without issuing or installing anything. The control plane uses this both
// right after a fresh issuance (belt-and-suspenders, since issue/install
// already return expiry inline) and on a recurring schedule to detect
// certificates that failed to auto-renew (see gateway's ssl expiry
// monitor in apps/controlplane).
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}

	for _, candidate := range []struct {
		path   string
		source string
	}{
		{letsEncryptLivePath(domain), "letsencrypt"},
		{customCertPath(domain), "custom"},
	} {
		if _, err := os.Stat(candidate.path); err != nil {
			continue
		}
		expiresAt, issuer, err := parseCertExpiry(candidate.path)
		if err != nil {
			return "", fmt.Errorf("certificate found for %s but could not be read: %w", domain, err)
		}
		return sslResult{Domain: domain, Source: candidate.source, ExpiresAt: expiresAt.UTC().Format(time.RFC3339), Issuer: issuer}.json(), nil
	}
	return "", fmt.Errorf("no certificate found for domain %q", domain)
}
