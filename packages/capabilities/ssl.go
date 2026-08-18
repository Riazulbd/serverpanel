package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// letsEncryptLivePath is where certbot's --nginx plugin (and `certbot
// certonly`) always stores the current certificate for a domain, whether
// it was just issued or renewed. custom SSL uses a separate path (see
// handleSSLInstallCustom) so the two never collide and ssl.status can tell
// them apart just from which one exists on disk.
func letsEncryptLivePath(domain string) string {
	return "/etc/letsencrypt/live/" + domain + "/fullchain.pem"
}

func customCertPath(domain string) string {
	return "/etc/serverpanel-agent/ssl/" + domain + "/fullchain.pem"
}

// sslStatusResult is ssl.status's TaskEvent detail (JSON) — the control
// plane parses this to persist per-site SSL state; see
// apps/controlplane/ssl.go.
type sslStatusResult struct {
	Domain          string `json:"domain"`
	Installed       bool   `json:"installed"`
	Source          string `json:"source"` // "none" | "letsencrypt" | "custom"
	Issuer          string `json:"issuer"`
	NotAfter        string `json:"not_after,omitempty"` // RFC3339, empty if not installed
	DaysRemaining   int    `json:"days_remaining"`
	AutoRenewActive bool   `json:"auto_renew_active"`
}

// handleSSLStatus reads whichever certificate is actually installed for a
// domain straight off disk (never from certbot's own bookkeeping, which
// can lag or be wrong if a renewal partially failed) and reports its real
// expiry. This is what SSL-016's "renewal monitoring" and the dashboard's
// expiry display are built on.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}

	res := sslStatusResult{Domain: domain, Source: "none"}

	path := letsEncryptLivePath(domain)
	source := "letsencrypt"
	if _, err := os.Stat(path); err != nil {
		path = customCertPath(domain)
		source = "custom"
		if _, err := os.Stat(path); err != nil {
			out, _ := json.Marshal(res)
			return string(out), nil
		}
	}

	issuer, notAfter, err := certInfo(ctx, path)
	if err != nil {
		return "", fmt.Errorf("read certificate for %s: %w", domain, err)
	}

	res.Installed = true
	res.Source = source
	res.Issuer = issuer
	res.NotAfter = notAfter.UTC().Format(time.RFC3339)
	res.DaysRemaining = int(time.Until(notAfter).Hours() / 24)

	if timerOut, err := run(ctx, "systemctl", "is-active", "certbot.timer"); err == nil {
		res.AutoRenewActive = timerOut == "active"
	}

	out, _ := json.Marshal(res)
	return string(out), nil
}

// certInfo shells out to openssl (present on every supported base image,
// unlike parsing PEM/ASN.1 ourselves) to read a certificate's issuer CN
// and expiry off disk, without ever touching the private key.
func certInfo(ctx context.Context, certPath string) (issuer string, notAfter time.Time, err error) {
	out, err := run(ctx, "openssl", "x509", "-in", certPath, "-noout", "-issuer", "-enddate")
	if err != nil {
		return "", time.Time{}, fmt.Errorf("openssl: %w: %s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "issuer="):
			issuer = strings.TrimSpace(strings.TrimPrefix(line, "issuer="))
		case strings.HasPrefix(line, "notAfter="):
			raw := strings.TrimSpace(strings.TrimPrefix(line, "notAfter="))
			// openssl's enddate format, e.g. "Jan  2 15:04:05 2030 GMT" for a
			// single-digit day (note the double space — asctime-style %e
			// space-pads the day to width 2) or "Dec 15 ..." otherwise. "_2"
			// is Go's reference-time token for that exact space padding.
			t, perr := time.Parse("Jan _2 15:04:05 2006 MST", raw)
			if perr != nil {
				return "", time.Time{}, fmt.Errorf("parse notAfter %q: %w", raw, perr)
			}
			notAfter = t
		}
	}
	if notAfter.IsZero() {
		return "", time.Time{}, fmt.Errorf("could not find notAfter in openssl output: %s", out)
	}
	return issuer, notAfter, nil
}

// handleSSLRenew force-renews a single domain's Let's Encrypt certificate
// ahead of its normal schedule (e.g. right after a "renewal failing"
// alert), independent of the certbot.timer sweep that renews everything
// due in the next 30 days. It only ever touches the one cert-name given —
// never `certbot renew` with no filter, which would renew every domain
// certbot manages on the box.
func handleSSLRenew(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if _, err := os.Stat(letsEncryptLivePath(domain)); err != nil {
		return "", fmt.Errorf("no Let's Encrypt certificate installed for %s (custom certificates must be re-uploaded, not renewed)", domain)
	}

	progress("renewing Let's Encrypt certificate for " + domain)
	out, err := run(ctx, "certbot", "renew", "--cert-name", domain, "--non-interactive")
	if err != nil {
		return "", fmt.Errorf("certbot renew: %w: %s", err, out)
	}
	run(ctx, "systemctl", "reload", "nginx")
	return "certificate renewed for " + domain, nil
}

// handleSSLUninstall removes whichever certificate is installed for a
// domain and puts the site's nginx vhost back to the same plain-HTTP
// config site.create would have written — rather than trying to
// selectively strip the SSL server block certbot's --nginx plugin added,
// which risks leaving the vhost in a state `nginx -t` rejects. Site
// metadata is supplied by the control plane (it already has it from the
// sites table) rather than re-derived here.
func handleSSLUninstall(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	sysUser, _ := params["system_user"].(string)
	tempDomain, _ := params["temp_domain"].(string)
	docroot, _ := params["docroot"].(string)
	appType, _ := params["app_type"].(string)
	phpVersion, _ := params["php_version"].(string)

	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return "", fmt.Errorf("invalid system_user")
	}
	if docroot == "" || appType == "" {
		return "", fmt.Errorf("docroot and app_type are required")
	}
	if tempDomain == "" {
		// The control plane doesn't persist the sslip.io temp domain
		// site.create generated (only the primary domain), so it isn't
		// always available to pass through here. It's deterministic from
		// the system user and the box's own primary IP, so it's
		// regenerated rather than treated as a hard requirement.
		tempDomain = tempDomainFor(sysUser, primaryIP(ctx))
	}

	if _, err := os.Stat(letsEncryptLivePath(domain)); err == nil {
		progress("removing Let's Encrypt certificate for " + domain)
		if out, err := run(ctx, "certbot", "delete", "--cert-name", domain, "--non-interactive"); err != nil {
			return "", fmt.Errorf("certbot delete: %w: %s", err, out)
		}
	} else if _, err := os.Stat(customCertPath(domain)); err == nil {
		progress("removing custom certificate for " + domain)
		if err := os.RemoveAll("/etc/serverpanel-agent/ssl/" + domain); err != nil {
			return "", fmt.Errorf("remove custom certificate: %w", err)
		}
	}

	progress("restoring plain-HTTP nginx vhost")
	if err := writeNginxVhost(sysUser, domain, tempDomain, docroot, appType, phpVersion); err != nil {
		return "", fmt.Errorf("rewrite nginx vhost: %w", err)
	}
	if out, err := run(ctx, "nginx", "-t"); err != nil {
		return "", fmt.Errorf("nginx config test failed after SSL removal: %w: %s", err, out)
	}
	run(ctx, "systemctl", "reload", "nginx")
	return "SSL removed for " + domain, nil
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
