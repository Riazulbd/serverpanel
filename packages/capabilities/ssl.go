package capabilities

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// sslStatusResult is what ssl.issue_letsencrypt, ssl.install_custom and
// ssl.status all return as their TaskEvent detail (JSON) — a single shape
// the control plane parses once (apps/controlplane/ssl.go) regardless of
// which of the three capabilities produced it, because in every case what
// the control plane actually wants recorded is "what certificate is
// installed for this domain right now", read back from the agent's own
// filesystem rather than trusted from whichever handler happened to run.
type sslStatusResult struct {
	Domain        string `json:"domain"`
	Source        string `json:"source"` // "letsencrypt", "custom", or "none"
	NotAfter      string `json:"not_after,omitempty"`
	DaysRemaining int    `json:"days_remaining,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
}

func customCertPath(domain string) string {
	return "/etc/serverpanel-agent/ssl/" + domain + "/fullchain.pem"
}
func customKeyPath(domain string) string {
	return "/etc/serverpanel-agent/ssl/" + domain + "/privkey.pem"
}
func letsEncryptCertPath(domain string) string {
	return "/etc/letsencrypt/live/" + domain + "/fullchain.pem"
}

// readCertStatus reports what certificate, if any, is actually installed
// for domain by reading the certificate files themselves rather than any
// record of what was last requested — a certbot renewal or a manual
// `certbot delete` changes what's on disk without this package's own code
// ever running, so the filesystem is the only source of truth.
func readCertStatus(domain string) sslStatusResult {
	res := sslStatusResult{Domain: domain, Source: "none"}

	candidates := []struct{ path, source string }{
		{letsEncryptCertPath(domain), "letsencrypt"},
		{customCertPath(domain), "custom"},
	}
	for _, c := range candidates {
		data, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		leaf, err := parseLeafCertPEM(data)
		if err != nil {
			continue
		}
		res.Source = c.source
		res.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		res.DaysRemaining = int(time.Until(leaf.NotAfter).Hours() / 24)
		res.Issuer = leaf.Issuer.CommonName
		return res
	}
	return res
}

func parseLeafCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// handleSSLStatus reports the certificate actually installed for a domain
// — used both as a user-facing "check SSL status" action and by the
// control plane to confirm what ssl.issue_letsencrypt/ssl.install_custom
// actually left on disk before recording it.
func handleSSLStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	out, _ := json.Marshal(readCertStatus(domain))
	return string(out), nil
}

// handleSSLIssueLetsEncrypt issues (or renews) a Let's Encrypt certificate
// for a domain using certbot's nginx plugin with a fixed, non-interactive
// argv — the domain is the only caller-supplied value, and it's the same
// domain already validated and vhost-configured by site.create, so this
// only ever points certbot at a site the control plane already knows
// about. certbot's nginx plugin edits the site's existing vhost in place
// (adding its own "listen 443 ssl" block and a deploy hook that reloads
// nginx), so no separate nginx edit is needed here the way
// handleSSLInstallCustom needs one.
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

	status := readCertStatus(domain)
	if status.Source != "letsencrypt" {
		return "", fmt.Errorf("certbot reported success but no certificate was found at %s afterward", letsEncryptCertPath(domain))
	}
	detail, _ := json.Marshal(status)
	return string(detail), nil
}

// sslCertLineRe/sslKeyLineRe match a previously-injected ssl_certificate(_key)
// directive so a re-install (e.g. a replaced/renewed custom certificate)
// updates the existing directive in place instead of appending a duplicate
// one, which would fail nginx's config test.
var sslCertLineRe = regexp.MustCompile(`(?m)^[ \t]*ssl_certificate[ \t]+\S+;[ \t]*$`)
var sslKeyLineRe = regexp.MustCompile(`(?m)^[ \t]*ssl_certificate_key[ \t]+\S+;[ \t]*$`)

// injectHTTPSListen adds (or, on a re-install, updates in place) the
// "listen ... ssl" and certificate directives a custom SSL install needs,
// operating purely on the vhost file's text — this is what
// handleSiteCreate's generated vhost (site.go writeNginxVhost) looks like,
// so this only ever has to handle that one known shape. It never rewrites
// anything else in the file (the location/proxy block, access/error log
// paths, ...), only adds or updates the SSL-specific lines, so an existing
// working site config is never at risk of being regenerated incorrectly.
// changed is false when the file already has the requested cert/key paths
// (a no-op retry) or when the file doesn't match the expected shape at all
// (caller should treat that as "nothing to do" rather than guessing).
func injectHTTPSListen(vhost, certPath, keyPath string) (updated string, changed bool) {
	certLine := "    ssl_certificate     " + certPath + ";"
	keyLine := "    ssl_certificate_key " + keyPath + ";"

	if sslCertLineRe.MatchString(vhost) {
		out := sslCertLineRe.ReplaceAllString(vhost, certLine)
		out = sslKeyLineRe.ReplaceAllString(out, keyLine)
		return out, out != vhost
	}

	lines := strings.Split(vhost, "\n")
	idx := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "listen 80;" {
			idx = i
			break
		}
	}
	if idx == -1 {
		return vhost, false
	}
	insertAt := idx + 1
	if insertAt < len(lines) && strings.Contains(lines[insertAt], "listen [::]:80;") {
		insertAt++
	}

	newLines := make([]string, 0, len(lines)+4)
	newLines = append(newLines, lines[:insertAt]...)
	newLines = append(newLines, "    listen 443 ssl;")
	if strings.Contains(vhost, "listen [::]:80;") {
		newLines = append(newLines, "    listen [::]:443 ssl;")
	}
	newLines = append(newLines, certLine, keyLine)
	newLines = append(newLines, lines[insertAt:]...)
	return strings.Join(newLines, "\n"), true
}

// handleSSLInstallCustom installs a user-supplied certificate/key pair for
// a domain and wires it into the site's existing nginx vhost. The
// certificate and key are verified to actually match (crypto/tls's own
// parser, the same one nginx effectively re-does at startup) and to cover
// the domain being installed for *before* anything is written to disk —
// installing a cert that doesn't match its key, or doesn't cover the
// domain, would otherwise silently fail nginx's config test far later or,
// worse, apply a cert nginx accepts but browsers reject.
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

	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return "", fmt.Errorf("certificate and private key do not match: %w", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("could not parse certificate: %w", err)
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return "", fmt.Errorf("certificate is not valid for %q: %w", domain, err)
	}
	if time.Now().After(leaf.NotAfter) {
		return "", fmt.Errorf("certificate already expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}

	certDir := "/etc/serverpanel-agent/ssl/" + domain
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", err
	}
	certPath := customCertPath(domain)
	keyPath := customKeyPath(domain)
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return "", fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	sysUser := systemUserForDomain(domain)
	vhostPath := nginxVhostPath(sysUser)
	original, err := os.ReadFile(vhostPath)
	if err != nil {
		return "", fmt.Errorf("no nginx vhost found for %q — create the site first: %w", domain, err)
	}

	if updated, changed := injectHTTPSListen(string(original), certPath, keyPath); changed {
		progress("wiring certificate into the nginx vhost")
		if err := os.WriteFile(vhostPath, []byte(updated), 0644); err != nil {
			return "", fmt.Errorf("write nginx vhost: %w", err)
		}
		progress("verifying nginx config with the new certificate")
		if out, err := run(ctx, "nginx", "-t"); err != nil {
			// Revert to the last-known-good config rather than leaving
			// nginx in a state that fails every future `nginx -t` (which
			// would also block every other site's next config change).
			os.WriteFile(vhostPath, original, 0644)
			return "", fmt.Errorf("nginx config test failed, reverted and custom certificate not activated: %w: %s", err, out)
		}
		run(ctx, "systemctl", "reload", "nginx")
	}

	status := readCertStatus(domain)
	detail, _ := json.Marshal(status)
	return string(detail), nil
}
