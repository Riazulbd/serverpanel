package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// newTestCertDirs points letsEncryptDir and customSSLDir at fresh temp
// directories for the duration of one test, restoring the real paths
// afterward — the same pattern newTestBackupBaseDir uses in backup_test.go,
// so tests never write into the real /etc/letsencrypt or
// /etc/serverpanel-agent/ssl on the machine running `go test`.
func newTestCertDirs(t *testing.T) {
	t.Helper()
	origLE, origCustom := letsEncryptDir, customSSLDir
	letsEncryptDir = filepath.Join(t.TempDir(), "letsencrypt-live")
	customSSLDir = filepath.Join(t.TempDir(), "custom-ssl")
	t.Cleanup(func() { letsEncryptDir, customSSLDir = origLE, origCustom })
}

// writeSelfSignedCert generates a real self-signed certificate/key pair via
// openssl (skipping the test if openssl isn't available) and writes
// fullchain.pem/privkey.pem into baseDir/domain, matching the on-disk
// layout certLocations expects for both certbot and handleSSLInstallCustom.
func writeSelfSignedCert(t *testing.T, baseDir, domain string, days int) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("openssl not available in this environment: %v", err)
	}
	dir := filepath.Join(baseDir, domain)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath, "-out", certPath, "-days", strconv.Itoa(days), "-subj", "/CN="+domain).CombinedOutput()
	if err != nil {
		t.Fatalf("generate self-signed cert: %v: %s", err, out)
	}
}

func TestCertExpiryReportsNoneWhenNothingIsInstalled(t *testing.T) {
	newTestCertDirs(t)
	res, err := certExpiry(context.Background(), "never-issued.example.com")
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if res.Status != "none" {
		t.Fatalf("Status = %q, want none", res.Status)
	}
	if res.Issuer != "" || res.ExpiresAt != "" {
		t.Fatalf("expected empty issuer/expiry for a domain with no certificate, got %+v", res)
	}
}

func TestCertExpiryReadsLetsEncryptCert(t *testing.T) {
	newTestCertDirs(t)
	writeSelfSignedCert(t, letsEncryptDir, "le.example.com", 60)

	res, err := certExpiry(context.Background(), "le.example.com")
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if res.Status != "active" || res.Issuer != "letsencrypt" {
		t.Fatalf("got status=%q issuer=%q, want active/letsencrypt", res.Status, res.Issuer)
	}
	if res.ExpiresAt == "" {
		t.Fatal("ExpiresAt is empty")
	}
	if res.DaysRemaining < 55 || res.DaysRemaining > 60 {
		t.Fatalf("DaysRemaining = %d, want roughly 60", res.DaysRemaining)
	}
}

func TestCertExpiryPrefersLetsEncryptOverCustom(t *testing.T) {
	newTestCertDirs(t)
	writeSelfSignedCert(t, letsEncryptDir, "both.example.com", 30)
	writeSelfSignedCert(t, customSSLDir, "both.example.com", 400)

	res, err := certExpiry(context.Background(), "both.example.com")
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if res.Issuer != "letsencrypt" {
		t.Fatalf("Issuer = %q, want letsencrypt to take precedence when both exist", res.Issuer)
	}
}

func TestCertExpiryReadsCustomCert(t *testing.T) {
	newTestCertDirs(t)
	writeSelfSignedCert(t, customSSLDir, "custom.example.com", 365)

	res, err := certExpiry(context.Background(), "custom.example.com")
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if res.Status != "active" || res.Issuer != "custom" {
		t.Fatalf("got status=%q issuer=%q, want active/custom", res.Status, res.Issuer)
	}
}

func TestHandleSSLStatusRejectsInvalidDomain(t *testing.T) {
	newTestCertDirs(t)
	if _, err := handleSSLStatus(context.Background(), map[string]any{"domain": "not a domain"}, nil); err == nil {
		t.Fatal("expected invalid domain to be rejected")
	}
}

func TestHandleSSLStatusRoundTripsJSON(t *testing.T) {
	newTestCertDirs(t)
	writeSelfSignedCert(t, letsEncryptDir, "status.example.com", 45)

	detail, err := handleSSLStatus(context.Background(), map[string]any{"domain": "status.example.com"}, nil)
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var res sslResult
	if err := json.Unmarshal([]byte(detail), &res); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if res.Domain != "status.example.com" || res.Status != "active" || res.Issuer != "letsencrypt" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestHandleSSLIssueLetsEncryptRejectsInvalidInput(t *testing.T) {
	newTestCertDirs(t)
	if _, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{"domain": "bad domain", "email": "a@b.com"}, nil); err == nil {
		t.Fatal("expected invalid domain to be rejected")
	}
	if _, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{"domain": "ok.example.com"}, nil); err == nil {
		t.Fatal("expected missing email to be rejected")
	}
}

// This environment has no certbot installed, which is exactly the
// production precondition handleSSLIssueLetsEncrypt itself checks for
// (stack.install must have run first) — so the real "certbot not
// installed" error path is what's exercised here, not a mock.
func TestHandleSSLIssueLetsEncryptFailsCleanlyWithoutCertbot(t *testing.T) {
	newTestCertDirs(t)
	if _, err := exec.LookPath("certbot"); err == nil {
		t.Skip("certbot is installed in this environment; this test only covers the not-installed path")
	}
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{"domain": "issue.example.com", "email": "ops@example.com"}, nil)
	if err == nil {
		t.Fatal("expected an error when certbot isn't installed")
	}
}

func TestHandleSSLRenewRejectsInvalidDomainAndMissingCert(t *testing.T) {
	newTestCertDirs(t)
	if _, err := handleSSLRenew(context.Background(), map[string]any{"domain": "bad domain"}, nil); err == nil {
		t.Fatal("expected invalid domain to be rejected")
	}
	if _, err := exec.LookPath("certbot"); err != nil {
		_, err := handleSSLRenew(context.Background(), map[string]any{"domain": "never-issued.example.com"}, nil)
		if err == nil {
			t.Fatal("expected an error when certbot isn't installed")
		}
		return
	}
	// certbot is installed but no certificate for this domain exists yet.
	_, err := handleSSLRenew(context.Background(), map[string]any{"domain": "never-issued.example.com"}, nil)
	if err == nil {
		t.Fatal("expected renew to fail for a domain with no existing certificate")
	}
}

func TestHandleSSLInstallCustomRejectsInvalidInput(t *testing.T) {
	newTestCertDirs(t)
	if _, err := handleSSLInstallCustom(context.Background(), map[string]any{"domain": "bad domain", "cert_pem": "x", "key_pem": "y"}, nil); err == nil {
		t.Fatal("expected invalid domain to be rejected")
	}
	if _, err := handleSSLInstallCustom(context.Background(), map[string]any{"domain": "ok.example.com", "cert_pem": "", "key_pem": "y"}, nil); err == nil {
		t.Fatal("expected missing cert_pem to be rejected")
	}
}

// handleSSLInstallCustom writes the cert/key to disk before validating the
// new nginx config, so a missing nginx binary (as in this test
// environment) must still fail the overall call rather than silently
// "succeed" with an unverified config — this is the real, unmocked
// behavior exercised, not a stand-in for it.
func TestHandleSSLInstallCustomFailsCleanlyWithoutNginx(t *testing.T) {
	newTestCertDirs(t)
	if _, err := exec.LookPath("nginx"); err == nil {
		t.Skip("nginx is installed in this environment; this test only covers the not-installed path")
	}
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "custominstall.example.com", "cert_pem": "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n",
		"key_pem": "-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----\n",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error when nginx isn't installed to validate the new config")
	}
}
