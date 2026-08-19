package capabilities

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"
)

// sslConfPath is the nginx config holding a site's TLS server block. It is
// deliberately a *separate* file from the site's port-80 vhost
// (nginxVhostPath) so that regenerating the vhost — which site.create and
// site.set_php_version both do — cannot silently drop a site's TLS
// configuration on the floor.
func sslConfPath(sysUser string) string {
	return "/etc/nginx/sites-available/" + sysUser + "-ssl.conf"
}

func sslEnabledPath(sysUser string) string {
	return "/etc/nginx/sites-enabled/" + sysUser + "-ssl.conf"
}

func sslMaterialDir(sysUser string) string {
	return "/etc/serverpanel-agent/ssl/" + sysUser
}

// handleSSLIssueLetsEncrypt issues (or renews) a Let's Encrypt certificate
// for a domain using certbot's nginx plugin with a fixed, non-interactive
// argv — the domain is the only caller-supplied value, and it's the same
// domain already validated and vhost-configured by site.create, so this
// only ever points certbot at a site the control plane already knows
// about.
//
// certbot edits the site's nginx config itself and installs a systemd timer
// that renews unattended; ensureCertbotRenewalTimer below makes sure that
// timer is actually enabled rather than assuming the package did it, since
// a certificate that issues but never renews is a 90-day outage with a
// delayed fuse.
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

	progress("verifying unattended renewal is enabled")
	renewal := ensureCertbotRenewalTimer(ctx)

	return fmt.Sprintf("certificate issued for %s; %s", domain, renewal), nil
}

// ensureCertbotRenewalTimer enables and starts certbot's renewal timer and
// reports what it found, rather than returning an error: a certificate that
// was just issued successfully should not be reported as a failure because
// the renewal timer could not be inspected. The returned string is surfaced
// to the operator so "issued but renewal could not be confirmed" is visible
// instead of silent.
func ensureCertbotRenewalTimer(ctx context.Context) string {
	if _, err := run(ctx, "systemctl", "enable", "--now", "certbot.timer"); err != nil {
		return "WARNING: could not enable certbot.timer, so this certificate may not renew automatically — check `systemctl status certbot.timer` on the server"
	}
	out, err := run(ctx, "systemctl", "is-active", "certbot.timer")
	if err != nil || strings.TrimSpace(out) != "active" {
		return "WARNING: certbot.timer is not active, so this certificate may not renew automatically"
	}
	return "unattended renewal is active (certbot.timer)"
}

// handleSSLInstallCustom installs a user-supplied certificate/key pair for
// a site and actually activates it: it validates the material, writes it,
// generates the site's TLS server block, and only keeps the change if nginx
// accepts the resulting configuration.
//
// Validation happens before anything is written, and is real parsing rather
// than a well-formedness guess: tls.X509KeyPair proves the private key
// actually belongs to the certificate (installing a mismatched pair is the
// single most common way this operation goes wrong, and nginx only reports
// it at reload time, by which point the site is already down), and the leaf
// is checked to cover the domain and to not already be expired.
//
// If nginx rejects the resulting config, the TLS block is removed and the
// previous state restored before returning — a rejected config left in
// sites-enabled would break every *subsequent* reload on the server, not
// just this site's.
func handleSSLInstallCustom(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	sysUser, _ := params["system_user"].(string)
	docroot, _ := params["docroot"].(string)
	appType, _ := params["app_type"].(string)
	phpVersion, _ := params["php_version"].(string)
	certPEM, _ := params["cert_pem"].(string)
	keyPEM, _ := params["key_pem"].(string)

	domain = strings.ToLower(domain)
	if !domainRe.MatchString(domain) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if !validSystemUser(sysUser) {
		return "", fmt.Errorf("invalid system_user %q", sysUser)
	}
	if docroot == "" {
		return "", fmt.Errorf("docroot is required")
	}
	if certPEM == "" || keyPEM == "" {
		return "", fmt.Errorf("cert_pem and key_pem are required")
	}

	progress("validating certificate and key")
	leaf, err := validateCertificateMaterial(certPEM, keyPEM, domain)
	if err != nil {
		return "", err
	}

	dir := sslMaterialDir(sysUser)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	certPath := dir + "/fullchain.pem"
	keyPath := dir + "/privkey.pem"

	// Snapshot whatever is currently in place so a failed activation can be
	// undone rather than leaving the site half-configured.
	prevCert, hadCert := readFileIfExists(certPath)
	prevKey, hadKey := readFileIfExists(keyPath)
	prevConf, hadConf := readFileIfExists(sslConfPath(sysUser))

	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return "", fmt.Errorf("write certificate: %w", err)
	}
	// 0600: the private key must never be readable by the site's own PHP
	// process or any other local user.
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	progress("writing TLS server block")
	if err := writeSSLServerBlock(sysUser, domain, docroot, appType, phpVersion, certPath, keyPath); err != nil {
		return "", fmt.Errorf("write TLS server block: %w", err)
	}

	progress("validating nginx configuration")
	if out, err := run(ctx, "nginx", "-t"); err != nil {
		rollbackSSL(sysUser, certPath, keyPath, prevCert, hadCert, prevKey, hadKey, prevConf, hadConf)
		// The nginx output is included because it names the offending
		// directive; it never contains key material (nginx reads the key
		// file, it does not echo it).
		return "", fmt.Errorf("nginx rejected the configuration, so the certificate was not activated and the previous state was restored: %w: %s", err, out)
	}
	if _, err := run(ctx, "systemctl", "reload", "nginx"); err != nil {
		progress(fmt.Sprintf("warning: nginx accepted the config but could not be reloaded (%v) — the certificate is installed and will take effect on the next reload", err))
	}

	return fmt.Sprintf("custom certificate installed and activated for %s (expires %s)",
		domain, leaf.NotAfter.UTC().Format(time.RFC3339)), nil
}

// validateCertificateMaterial parses and cross-checks a certificate/key
// pair. Errors deliberately describe the problem without ever echoing the
// supplied PEM, so a malformed private key can't end up in a task result or
// audit log.
func validateCertificateMaterial(certPEM, keyPEM, domain string) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate and private key are not a valid, matching pair")
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate found in cert_pem")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("could not parse the leaf certificate: %w", err)
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, fmt.Errorf("certificate does not cover %s (subject: %q, SANs: %v)",
			domain, leaf.Subject.CommonName, leaf.DNSNames)
	}
	return leaf, nil
}

func readFileIfExists(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return b, true
}

// rollbackSSL restores the pre-install state after nginx rejected the new
// configuration. Restoring the *config* is what matters most: a bad file
// left in sites-enabled breaks every later reload on this server, turning
// one site's failed certificate install into a server-wide outage the next
// time anything else changes.
func rollbackSSL(sysUser, certPath, keyPath string, prevCert []byte, hadCert bool, prevKey []byte, hadKey bool, prevConf []byte, hadConf bool) {
	if hadConf {
		os.WriteFile(sslConfPath(sysUser), prevConf, 0644)
	} else {
		os.Remove(sslEnabledPath(sysUser))
		os.Remove(sslConfPath(sysUser))
	}
	if hadCert {
		os.WriteFile(certPath, prevCert, 0644)
	} else {
		os.Remove(certPath)
	}
	if hadKey {
		os.WriteFile(keyPath, prevKey, 0600)
	} else {
		os.Remove(keyPath)
	}
}

// writeSSLServerBlock generates the site's port-443 server block, mirroring
// the port-80 vhost's location handling so a site behaves identically over
// TLS. Every interpolated value has already been validated by the caller
// (domain, system user) or comes from the site record (docroot).
func writeSSLServerBlock(sysUser, domain, docroot, appType, phpVersion, certPath, keyPath string) error {
	var locationBlock string
	switch appType {
	case "static":
		locationBlock = `    location / {
        try_files $uri $uri/ =404;
    }`
	default:
		locationBlock = fmt.Sprintf(`    index index.php index.html;
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:%s;
    }
    location ~ /\.ht {
        deny all;
    }`, phpFPMSocketPath(sysUser, phpVersion))
	}

	ipv6Listen := ""
	if ipv6Available() {
		ipv6Listen = "\n    listen [::]:443 ssl;"
	}

	content := fmt.Sprintf(`# Managed by ServerPanel: TLS server block for %[1]s. Do not edit by hand;
# changes made through the dashboard regenerate this file.
server {
    listen 443 ssl;%[7]s
    http2 on;
    server_name %[1]s;
    root %[2]s;

    ssl_certificate     %[5]s;
    ssl_certificate_key %[6]s;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

%[3]s

    access_log /var/log/nginx/%[4]s.ssl.access.log;
    error_log  /var/log/nginx/%[4]s.ssl.error.log;
}
`, domain, docroot, locationBlock, sysUser, certPath, keyPath, ipv6Listen)

	if err := os.WriteFile(sslConfPath(sysUser), []byte(content), 0644); err != nil {
		return err
	}
	os.Remove(sslEnabledPath(sysUser))
	if err := os.Symlink(sslConfPath(sysUser), sslEnabledPath(sysUser)); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}
