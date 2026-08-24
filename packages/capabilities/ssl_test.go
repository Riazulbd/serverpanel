package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// newTestSSLBaseDirs points the Let's-Encrypt and custom-cert base
// directories at temp dirs for one test, restoring the real values
// afterward — the same pattern newTestBackupBaseDir uses in backup_test.go.
func newTestSSLBaseDirs(t *testing.T) (leDir, customDir string) {
	t.Helper()
	leDir, customDir = t.TempDir(), t.TempDir()
	origLE, origCustom := sslLetsEncryptBaseDir, sslCustomBaseDir
	sslLetsEncryptBaseDir, sslCustomBaseDir = leDir, customDir
	t.Cleanup(func() { sslLetsEncryptBaseDir, sslCustomBaseDir = origLE, origCustom })
	return leDir, customDir
}

// writeTestCert generates a throwaway self-signed certificate expiring
// notAfter from now, using the real openssl binary (skipping the test if
// it isn't available) so handleSSLStatus's own `openssl x509 -enddate`
// parsing is exercised against real output, not a hand-crafted PEM.
func writeTestCert(t *testing.T, path string, notAfter time.Duration) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("openssl not available in this environment: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	days := int(notAfter.Hours()/24) + 1
	keyPath := path + ".key"
	out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath, "-out", path, "-days", strconv.Itoa(days),
		"-subj", "/CN=example.test").CombinedOutput()
	if err != nil {
		t.Fatalf("generate test cert: %v: %s", err, out)
	}
}

func TestHandleSSLStatusRejectsInvalidDomain(t *testing.T) {
	newTestSSLBaseDirs(t)
	if _, err := handleSSLStatus(context.Background(), map[string]any{"domain": "not a domain"}, nil); err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLStatusNoneWhenNoCertExists(t *testing.T) {
	newTestSSLBaseDirs(t)
	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "example.test"}, func(string) {})
	if err != nil {
		t.Fatalf("ssl.status: %v", err)
	}
	var result sslStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Status != "none" {
		t.Fatalf("status = %q, want %q", result.Status, "none")
	}
	if result.ExpiresAt != "" {
		t.Fatalf("expected no expiry for a nonexistent cert, got %q", result.ExpiresAt)
	}
}

func TestHandleSSLStatusValidLetsEncryptCert(t *testing.T) {
	leDir, _ := newTestSSLBaseDirs(t)
	writeTestCert(t, filepath.Join(leDir, "example.test", "cert.pem"), 90*24*time.Hour)

	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "example.test"}, func(string) {})
	if err != nil {
		t.Fatalf("ssl.status: %v", err)
	}
	var result sslStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Status != "valid" {
		t.Fatalf("status = %q, want %q", result.Status, "valid")
	}
	if result.Issuer != "letsencrypt" {
		t.Fatalf("issuer = %q, want %q", result.Issuer, "letsencrypt")
	}
	if result.ExpiresAt == "" {
		t.Fatal("expected a non-empty expiry for a valid cert")
	}
}

func TestHandleSSLStatusExpiringSoonCustomCert(t *testing.T) {
	_, customDir := newTestSSLBaseDirs(t)
	writeTestCert(t, filepath.Join(customDir, "example.test", "fullchain.pem"), 3*24*time.Hour)

	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "example.test"}, func(string) {})
	if err != nil {
		t.Fatalf("ssl.status: %v", err)
	}
	var result sslStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Status != "expiring_soon" {
		t.Fatalf("status = %q, want %q", result.Status, "expiring_soon")
	}
	if result.Issuer != "custom" {
		t.Fatalf("issuer = %q, want %q", result.Issuer, "custom")
	}
}

func TestHandleSSLStatusPrefersLetsEncryptOverCustom(t *testing.T) {
	leDir, customDir := newTestSSLBaseDirs(t)
	writeTestCert(t, filepath.Join(leDir, "example.test", "cert.pem"), 90*24*time.Hour)
	writeTestCert(t, filepath.Join(customDir, "example.test", "fullchain.pem"), 90*24*time.Hour)

	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "example.test"}, func(string) {})
	if err != nil {
		t.Fatalf("ssl.status: %v", err)
	}
	var result sslStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Issuer != "letsencrypt" {
		t.Fatalf("issuer = %q, want %q (Let's Encrypt should take priority)", result.Issuer, "letsencrypt")
	}
}
