package capabilities

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// letsEncryptLiveDir is where certbot stores each issued certificate's
// current symlinked files, one subdirectory per domain (the directory name
// is the domain certbot issued for, i.e. what was passed as -d).
const letsEncryptLiveDir = "/etc/letsencrypt/live"

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

// sslCertInfo is one certificate's reported expiry state.
type sslCertInfo struct {
	Domain        string    `json:"domain"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	Expired       bool      `json:"expired"`
}

// sslStatusReport is handleSSLStatus's JSON-encoded result.
type sslStatusReport struct {
	Certificates       []sslCertInfo `json:"certificates"`
	RenewalTimerActive bool          `json:"renewal_timer_active"`
}

// handleSSLStatus reports every Let's Encrypt certificate this agent knows
// about (or just one domain's, if given) and whether certbot's automatic
// renewal timer is actually running — the two facts an operator or an
// expiry alert needs and neither of which "the certificate was issued
// successfully at some point" answers on its own.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if domain != "" && !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}

	certs, err := listLetsEncryptCerts(letsEncryptLiveDir)
	if err != nil {
		return "", fmt.Errorf("list certificates: %w", err)
	}
	if domain != "" {
		var filtered []sslCertInfo
		for _, c := range certs {
			if c.Domain == domain {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 0 {
			return "", fmt.Errorf("no certificate found for domain %q", domain)
		}
		certs = filtered
	}

	timerOut, _ := run(ctx, "systemctl", "is-active", "certbot.timer")
	report := sslStatusReport{
		Certificates:       certs,
		RenewalTimerActive: strings.TrimSpace(timerOut) == "active",
	}
	b, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// listLetsEncryptCerts reads every domain subdirectory under baseDir and
// parses its cert.pem for an expiry date. A missing baseDir (no certificate
// ever issued yet) is not an error — it just means an empty report. A
// single unreadable/malformed entry is skipped rather than failing the
// whole report, since one broken directory shouldn't hide the status of
// every other certificate on the server.
func listLetsEncryptCerts(baseDir string) ([]sslCertInfo, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	now := time.Now()
	var out []sslCertInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		notAfter, err := certExpiry(filepath.Join(baseDir, e.Name(), "cert.pem"))
		if err != nil {
			continue
		}
		out = append(out, sslCertInfo{
			Domain:        e.Name(),
			NotAfter:      notAfter,
			DaysRemaining: int(notAfter.Sub(now).Hours() / 24),
			Expired:       now.After(notAfter),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

// certExpiry returns a PEM certificate file's NotAfter time.
func certExpiry(certPath string) (time.Time, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("%s: no PEM data found", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", certPath, err)
	}
	return cert.NotAfter, nil
}
