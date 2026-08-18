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

// newTestSSLDirs points letsEncryptLiveDir/customSSLBaseDir at fresh temp
// directories for the duration of one test, restoring the real values
// afterward — same pattern as newTestBackupBaseDir in backup_test.go.
func newTestSSLDirs(t *testing.T) (leDir, customDir string) {
	t.Helper()
	leDir, customDir = t.TempDir(), t.TempDir()
	origLE, origCustom := letsEncryptLiveDir, customSSLBaseDir
	letsEncryptLiveDir, customSSLBaseDir = leDir, customDir
	t.Cleanup(func() { letsEncryptLiveDir, customSSLBaseDir = origLE, origCustom })
	return leDir, customDir
}

// writeTestCert generates a real self-signed certificate expiring in ttl and
// writes it (PEM, no key needed for status purposes) to path, so
// certExpiryFromFile exercises the real openssl binary against a real file
// rather than a hand-crafted fixture.
func writeTestCert(t *testing.T, path string, ttl time.Duration) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("openssl not available in this environment: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	days := int(ttl.Hours()/24) + 1
	keyPath := path + ".key.tmp"
	out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath, "-out", path, "-days", strconv.Itoa(days), "-nodes",
		"-subj", "/CN=test.example.com").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl req: %v: %s", err, out)
	}
	t.Cleanup(func() { os.Remove(keyPath) })
}

func TestHandleSSLStatusRejectsInvalidDomain(t *testing.T) {
	newTestSSLDirs(t)
	if _, err := handleSSLStatus(context.Background(), map[string]any{"domain": "not a domain!"}, nil); err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLStatusReportsNoCertificate(t *testing.T) {
	newTestSSLDirs(t)
	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "nocert.example.com"}, func(string) {})
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var res sslStatusResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if res.Present {
		t.Fatal("expected Present=false when no certificate file exists at either location")
	}
	if res.Issuer != "" {
		t.Fatalf("Issuer = %q, want empty when no certificate is present", res.Issuer)
	}
}

func TestHandleSSLStatusFindsLetsEncryptCertificate(t *testing.T) {
	leDir, _ := newTestSSLDirs(t)
	domain := "le.example.com"
	writeTestCert(t, filepath.Join(leDir, domain, "fullchain.pem"), 60*24*time.Hour)

	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": domain}, func(string) {})
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var res sslStatusResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !res.Present {
		t.Fatal("expected Present=true for a certificate that exists on disk")
	}
	if res.Issuer != "letsencrypt" {
		t.Fatalf("Issuer = %q, want %q", res.Issuer, "letsencrypt")
	}
	if res.DaysRemaining < 55 || res.DaysRemaining > 61 {
		t.Fatalf("DaysRemaining = %d, want roughly 60", res.DaysRemaining)
	}
}

func TestHandleSSLStatusPrefersLetsEncryptOverCustom(t *testing.T) {
	leDir, customDir := newTestSSLDirs(t)
	domain := "both.example.com"
	writeTestCert(t, filepath.Join(leDir, domain, "fullchain.pem"), 10*24*time.Hour)
	writeTestCert(t, filepath.Join(customDir, domain, "fullchain.pem"), 300*24*time.Hour)

	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": domain}, func(string) {})
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var res sslStatusResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if res.Issuer != "letsencrypt" {
		t.Fatalf("Issuer = %q, want %q (a Let's Encrypt cert should take priority over a custom one)", res.Issuer, "letsencrypt")
	}
}

func TestHandleSSLStatusFindsCustomCertificateWhenNoLetsEncryptOneExists(t *testing.T) {
	_, customDir := newTestSSLDirs(t)
	domain := "custom.example.com"
	writeTestCert(t, filepath.Join(customDir, domain, "fullchain.pem"), 90*24*time.Hour)

	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": domain}, func(string) {})
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var res sslStatusResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if res.Issuer != "custom" {
		t.Fatalf("Issuer = %q, want %q", res.Issuer, "custom")
	}
}

func TestParseOpenSSLEndDate(t *testing.T) {
	cases := []struct {
		in   string
		want time.Time
	}{
		{"notAfter=Aug 17 12:00:00 2026 GMT", time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)},
		{"notAfter=Jan  2 03:04:05 2030 GMT", time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)},
	}
	for _, tc := range cases {
		got, err := parseOpenSSLEndDate(tc.in)
		if err != nil {
			t.Fatalf("parseOpenSSLEndDate(%q): %v", tc.in, err)
		}
		if !got.Equal(tc.want) {
			t.Fatalf("parseOpenSSLEndDate(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestParseOpenSSLEndDateRejectsUnexpectedFormat(t *testing.T) {
	if _, err := parseOpenSSLEndDate("something unexpected"); err == nil {
		t.Fatal("expected an error for output without the notAfter= prefix")
	}
}
