package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// letsEncryptLiveDir is where certbot maintains one directory per
// certificate lineage (named after the first domain it was issued for),
// each containing symlinks to the current fullchain/privkey. A var (not a
// const) so tests can point it at a fixture directory instead of the real
// system path.
var letsEncryptLiveDir = "/etc/letsencrypt/live"

// sslDeployHookPath is where stack.install writes a certbot deploy hook
// (see installSSLRenewalHook in stack.go). Certbot runs every executable
// script under renewal-hooks/deploy/ after ANY certificate on the host
// renews — see handleSSLIssueLetsEncrypt / handleSSLStatus for the read
// side of this. A var (like letsEncryptLiveDir above), not a const, so
// tests can point it at a fixture path instead of the real system path.
var sslDeployHookPath = "/etc/letsencrypt/renewal-hooks/deploy/serverpanel-reload-nginx.sh"

// sslDeployHookScript reloads nginx after a successful renewal. certbot's
// own --nginx authenticator already reloads nginx as part of *issuing* a
// cert, but a scheduled `certbot renew` run (via certbot.timer) uses
// whichever authenticator/installer was recorded for that lineage at issue
// time — this hook is a second, unconditional safety net so a renewed
// certificate is never left unserved because some other renewal path
// skipped the reload. `nginx -t` gates the reload so a renewal never
// reloads a config that's currently broken for unrelated reasons.
const sslDeployHookScript = `#!/bin/sh
# Managed by ServerPanel (stack.install). Do not edit by hand — this file is
# rewritten idempotently on every stack.install run.
set -e
if nginx -t >/dev/null 2>&1; then
	systemctl reload nginx
fi
`

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

// certStatus is one Let's Encrypt certificate lineage's renewal status.
type certStatus struct {
	Domain      string `json:"domain"`
	ExpiresAt   string `json:"expires_at"` // RFC3339, empty if unreadable
	DaysLeft    int    `json:"days_left"`
	NeedsAction bool   `json:"needs_action"` // true if expiring within 30 days and can't be auto-renewed
}

type sslStatusReport struct {
	TimerActive bool         `json:"renewal_timer_active"`
	HookActive  bool         `json:"renewal_hook_active"`
	Certs       []certStatus `json:"certs"`
}

// handleSSLStatus is a read-only capability: it never issues, renews, or
// modifies anything. It reports what handleSSLIssueLetsEncrypt has already
// issued plus whether the unattended-renewal machinery installStep in
// stack.go set up (certbot.timer + the deploy hook) is actually active, so
// the control plane can surface real renewal state instead of assuming
// "issued once" means "will keep renewing."
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	report := sslStatusReport{}

	timerOut, _ := run(ctx, "systemctl", "is-active", "certbot.timer")
	report.TimerActive = strings.TrimSpace(timerOut) == "active"

	if info, err := os.Stat(sslDeployHookPath); err == nil {
		report.HookActive = info.Mode()&0111 != 0 // executable
	}

	domains, err := listLiveCertDomains(letsEncryptLiveDir)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("list certificates: %w", err)
	}
	for _, domain := range domains {
		certPath := filepath.Join(letsEncryptLiveDir, domain, "cert.pem")
		cs := certStatus{Domain: domain}
		out, err := run(ctx, "openssl", "x509", "-enddate", "-noout", "-in", certPath)
		if err != nil {
			progress(fmt.Sprintf("could not read expiry for %s: %v", domain, err))
			cs.NeedsAction = true
			report.Certs = append(report.Certs, cs)
			continue
		}
		expiry, perr := parseOpenSSLEndDate(out)
		if perr != nil {
			progress(fmt.Sprintf("could not parse expiry for %s: %v", domain, perr))
			cs.NeedsAction = true
			report.Certs = append(report.Certs, cs)
			continue
		}
		cs.ExpiresAt = expiry.Format(time.RFC3339)
		cs.DaysLeft = daysUntil(expiry, time.Now())
		cs.NeedsAction = cs.DaysLeft < 30 && !(report.TimerActive && report.HookActive)
		report.Certs = append(report.Certs, cs)
	}

	out, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// listLiveCertDomains lists certbot certificate-lineage directory names
// under root (normally /etc/letsencrypt/live), skipping certbot's own
// README file. A separate function (rather than inlined in the handler) so
// it can be unit-tested against a throwaway fixture directory instead of
// requiring real certbot state.
func listLiveCertDomains(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, e := range entries {
		if !e.IsDir() {
			continue // skips README and any stray files
		}
		domains = append(domains, e.Name())
	}
	return domains, nil
}

// parseOpenSSLEndDate parses the output of `openssl x509 -enddate -noout`,
// e.g. "notAfter=Jan 15 12:00:00 2027 GMT".
func parseOpenSSLEndDate(output string) (time.Time, error) {
	const prefix = "notAfter="
	line := strings.TrimSpace(output)
	if !strings.HasPrefix(line, prefix) {
		return time.Time{}, fmt.Errorf("unexpected openssl output: %q", output)
	}
	return time.Parse("Jan 2 15:04:05 2006 MST", strings.TrimPrefix(line, prefix))
}

// daysUntil returns the number of whole days between now and t (negative if
// t is in the past). A separate function from handleSSLStatus's "now" so
// tests can pin both sides instead of racing the real clock.
func daysUntil(t, now time.Time) int {
	return int(t.Sub(now).Hours() / 24)
}
