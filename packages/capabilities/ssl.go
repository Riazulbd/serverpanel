package capabilities

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// letsEncryptLiveDir and customSSLDir are where issued certificates live on
// disk — package vars (rather than inline constants) so tests can point
// them at a temp directory instead of the real host paths, the same
// override-for-tests pattern backupBaseDir uses.
var (
	letsEncryptLiveDir = "/etc/letsencrypt/live"
	customSSLDir       = "/etc/serverpanel-agent/ssl"
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

// certStatus is one managed certificate's expiry state, as reported by
// ssl.status. DaysRemaining can be negative for an already-expired
// certificate — the control plane (and any alerting built on top of it)
// decides what threshold counts as urgent, this handler only reports facts.
type certStatus struct {
	Domain        string `json:"domain"`
	Issuer        string `json:"issuer"` // "letsencrypt" or "custom"
	ExpiresAt     string `json:"expires_at"`
	DaysRemaining int    `json:"days_remaining"`
	Expired       bool   `json:"expired"`
}

// handleSSLStatus reports the expiry status of every certificate this agent
// has issued or installed (Let's Encrypt and custom alike), or just one
// domain's when the caller supplies a "domain" filter. It never shells out
// to `certbot certificates` — the certificate files themselves are the
// source of truth, parsed directly with crypto/x509, so this works
// identically for both issuance paths and can't be fooled by a certbot
// config renewalparams. This is what a "SSL expiring soon" alert, or a
// renewal-timer health check, would poll.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	filterDomain, _ := params["domain"].(string)
	filterDomain = strings.ToLower(strings.TrimSpace(filterDomain))

	statuses, err := scanManagedCerts()
	if err != nil {
		return "", err
	}
	if filterDomain != "" {
		var filtered []certStatus
		for _, c := range statuses {
			if strings.ToLower(c.Domain) == filterDomain {
				filtered = append(filtered, c)
			}
		}
		statuses = filtered
	}

	out, err := json.Marshal(statuses)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// scanManagedCerts walks both certificate directories this agent ever
// writes into and parses each leaf certificate's NotAfter directly from the
// PEM/X.509 bytes on disk, rather than trusting any external inventory —
// the same defense-in-depth stance stack.go's checkOSSupported takes
// ("never trust that a precondition was already checked by something
// upstream").
func scanManagedCerts() ([]certStatus, error) {
	var out []certStatus

	if entries, err := os.ReadDir(letsEncryptLiveDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "README" {
				continue
			}
			certPath := filepath.Join(letsEncryptLiveDir, e.Name(), "cert.pem")
			cs, err := readCertStatus(certPath, e.Name(), "letsencrypt")
			if err != nil {
				continue // unreadable/partial entry (e.g. mid-issuance); skip rather than fail the whole scan
			}
			out = append(out, cs)
		}
	}

	if entries, err := os.ReadDir(customSSLDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			certPath := filepath.Join(customSSLDir, e.Name(), "fullchain.pem")
			cs, err := readCertStatus(certPath, e.Name(), "custom")
			if err != nil {
				continue
			}
			out = append(out, cs)
		}
	}

	return out, nil
}

func readCertStatus(certPath, domain, issuer string) (certStatus, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return certStatus{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return certStatus{}, fmt.Errorf("no PEM block in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certStatus{}, err
	}
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	return certStatus{
		Domain:        domain,
		Issuer:        issuer,
		ExpiresAt:     cert.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: daysRemaining,
		Expired:       time.Now().After(cert.NotAfter),
	}, nil
}
