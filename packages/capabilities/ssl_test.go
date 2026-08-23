package capabilities

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestLetsEncryptDir points letsEncryptLiveDir at a temp directory for
// the duration of one test, restoring the real value afterward — the same
// pattern newTestBackupBaseDir uses for backupBaseDir.
func newTestLetsEncryptDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := letsEncryptLiveDir
	letsEncryptLiveDir = dir
	t.Cleanup(func() { letsEncryptLiveDir = orig })
	return dir
}

// writeTestCert generates a minimal self-signed certificate for domain,
// valid from notBefore to notAfter, and writes it at
// <letsEncryptLiveDir>/<domain>/cert.pem — exactly where certbot's nginx
// plugin would put a real one, so readCertInfo/handleSSLStatus exercise
// the real file layout without needing certbot or root.
func writeTestCert(t *testing.T, dir, domain string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		Issuer:       pkix.Name{CommonName: "Fake LE Intermediate X1"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certDir := filepath.Join(dir, domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), pemBytes, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}

func TestSSLIssueRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{
		"domain": "not a domain", "email": "ops@example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestSSLIssueRejectsMissingEmail(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{
		"domain": "example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected a missing email to be rejected")
	}
}

func TestSSLStatusRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLStatus(context.Background(), map[string]any{
		"domain": "; rm -rf /",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestSSLStatusReportsUnmanagedDomainWithoutError(t *testing.T) {
	newTestLetsEncryptDir(t)
	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "nocert.example.com"}, nil)
	if err != nil {
		t.Fatalf("handleSSLStatus for a domain with no certificate: %v", err)
	}
	var result sslStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Managed {
		t.Fatalf("expected Managed = false for a domain with no certificate, got %+v", result)
	}
}

func TestSSLStatusParsesRealCertificateExpiry(t *testing.T) {
	dir := newTestLetsEncryptDir(t)
	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(60 * 24 * time.Hour)
	writeTestCert(t, dir, "example.com", notBefore, notAfter)

	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "example.com"}, nil)
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var result sslStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !result.Managed {
		t.Fatal("expected Managed = true once a certificate exists on disk")
	}
	parsedExpiry, err := time.Parse(time.RFC3339, result.NotAfter)
	if err != nil {
		t.Fatalf("NotAfter %q did not parse as RFC3339: %v", result.NotAfter, err)
	}
	if diff := parsedExpiry.Sub(notAfter); diff > time.Minute || diff < -time.Minute {
		t.Fatalf("NotAfter = %v, want approximately %v", parsedExpiry, notAfter)
	}
	if result.DaysUntilExpiry < 58 || result.DaysUntilExpiry > 60 {
		t.Fatalf("DaysUntilExpiry = %d, want approximately 60", result.DaysUntilExpiry)
	}
}

func TestSSLStatusRejectsCorruptCertificateFile(t *testing.T) {
	dir := newTestLetsEncryptDir(t)
	certDir := filepath.Join(dir, "broken.example.com")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// handleSSLStatus never fails outright on a corrupt certificate file —
	// it degrades gracefully by omitting the parsed fields, since a status
	// read must never error the dashboard out over on-disk corruption it
	// didn't cause.
	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "broken.example.com"}, nil)
	if err != nil {
		t.Fatalf("handleSSLStatus with a corrupt cert file: %v", err)
	}
	var result sslStatusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Managed {
		t.Fatalf("expected Managed = false for an unparseable certificate, got %+v", result)
	}
}
