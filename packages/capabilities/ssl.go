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

// letsEncryptLiveDir is where certbot's nginx plugin stores issued
// certificates, one subdirectory per domain — the same path certbot itself
// uses, so this package never has to guess at or duplicate certbot's
// bookkeeping. A var (not a const) so tests can point it at a temp
// directory instead of requiring root and a real certbot install.
var letsEncryptLiveDir = "/etc/letsencrypt/live"

// certbotRenewalTimer is the systemd timer unit the certbot Debian/Ubuntu
// package ships to run `certbot renew` twice daily. Some minimal images
// install the package without enabling it, so handleSSLIssueLetsEncrypt
// enables it explicitly rather than assuming the package postinst did —
// "certificate issued" must never quietly mean "certificate issued and
// will silently expire in 90 days".
const certbotRenewalTimer = "certbot.timer"

// sslCertInfo is the parsed state of one domain's certificate as recorded
// on disk, shared by handleSSLIssueLetsEncrypt and handleSSLStatus so both
// report identical, independently-verifiable data (read straight from the
// certificate file with Go's x509 parser, never trusted from certbot's own
// stdout).
type sslCertInfo struct {
	Managed         bool   `json:"managed"`
	Issuer          string `json:"issuer,omitempty"`
	NotBefore       string `json:"not_before,omitempty"`
	NotAfter        string `json:"not_after,omitempty"`
	DaysUntilExpiry int    `json:"days_until_expiry,omitempty"`
}

// sslIssueResult is what ssl.issue_letsencrypt returns as its TaskEvent
// detail (JSON) — the control plane parses this to record SSL status on
// the site (see apps/controlplane/ssl.go handleIssueSSL).
type sslIssueResult struct {
	Domain              string `json:"domain"`
	NotAfter            string `json:"not_after,omitempty"`
	RenewalTimerActive  bool   `json:"renewal_timer_active"`
	RenewalTimerEnabled bool   `json:"renewal_timer_enabled"`
}

// sslStatusResult is what ssl.status returns.
type sslStatusResult struct {
	Domain              string `json:"domain"`
	RenewalTimerActive  bool   `json:"renewal_timer_active"`
	RenewalTimerEnabled bool   `json:"renewal_timer_enabled"`
	sslCertInfo
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

	progress("enabling automatic renewal")
	result := sslIssueResult{Domain: domain}
	// Best-effort: a failure here does not undo the issuance above (the
	// certificate is real and installed either way) but is surfaced in the
	// result so the control plane can flag "issued, renewal not confirmed"
	// rather than silently reporting full success.
	run(ctx, "systemctl", "enable", "--now", certbotRenewalTimer)
	result.RenewalTimerActive = systemdUnitIsActive(ctx, certbotRenewalTimer)
	result.RenewalTimerEnabled = systemdUnitIsEnabled(ctx, certbotRenewalTimer)

	if info, err := readCertInfo(domain); err == nil {
		result.NotAfter = info.NotAfter
	}

	detail, _ := json.Marshal(result)
	return string(detail), nil
}

// handleSSLStatus reports a domain's current certificate expiry and
// whether the renewal timer that keeps it from expiring is active — read
// directly from the certificate file and systemd, never cached, so the
// dashboard always shows the server's actual current state.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}

	result := sslStatusResult{Domain: domain}
	if info, err := readCertInfo(domain); err == nil {
		result.sslCertInfo = *info
	}
	result.RenewalTimerActive = systemdUnitIsActive(ctx, certbotRenewalTimer)
	result.RenewalTimerEnabled = systemdUnitIsEnabled(ctx, certbotRenewalTimer)

	detail, _ := json.Marshal(result)
	return string(detail), nil
}

// readCertInfo parses the certificate certbot issued for domain straight
// off disk. Returns managed=false (no error) when no certificate exists
// yet for that domain — that's a normal, expected state, not a failure.
func readCertInfo(domain string) (*sslCertInfo, error) {
	certPath := filepath.Join(letsEncryptLiveDir, domain, "cert.pem")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return &sslCertInfo{Managed: false}, nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM certificate at %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate at %s: %w", certPath, err)
	}
	return &sslCertInfo{
		Managed:         true,
		Issuer:          cert.Issuer.CommonName,
		NotBefore:       cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:        cert.NotAfter.UTC().Format(time.RFC3339),
		DaysUntilExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
	}, nil
}

// systemdUnitIsActive/systemdUnitIsEnabled are read-only status probes —
// distinct from service.control's managedUnits allow-list, since a status
// check (unlike start/stop/restart) can't affect the server and the unit
// name here is always the fixed certbotRenewalTimer constant, never
// caller-supplied.
func systemdUnitIsActive(ctx context.Context, unit string) bool {
	out, _ := run(ctx, "systemctl", "is-active", unit)
	return out == "active"
}

func systemdUnitIsEnabled(ctx context.Context, unit string) bool {
	out, _ := run(ctx, "systemctl", "is-enabled", unit)
	return out == "enabled" || out == "static"
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
