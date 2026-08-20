package capabilities

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert generates a self-signed certificate with the given NotAfter
// and writes it as cert.pem under dir/domain/, mimicking the layout
// certbot leaves under /etc/letsencrypt/live.
func writeTestCert(t *testing.T, dir, domain string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
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
		t.Fatalf("write cert.pem: %v", err)
	}
}

func TestCertExpiryReadsNotAfter(t *testing.T) {
	dir := t.TempDir()
	want := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	writeTestCert(t, dir, "example.com", want)

	got, err := certExpiry(filepath.Join(dir, "example.com", "cert.pem"))
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("certExpiry = %v, want %v", got, want)
	}
}

func TestCertExpiryRejectsMalformedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := certExpiry(path); err == nil {
		t.Fatal("certExpiry accepted a non-PEM file")
	}
}

func TestCertExpiryRejectsMissingFile(t *testing.T) {
	if _, err := certExpiry(filepath.Join(t.TempDir(), "missing", "cert.pem")); err == nil {
		t.Fatal("certExpiry accepted a nonexistent file")
	}
}

func TestListLetsEncryptCertsReportsExpiredAndValid(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, "expired.example.com", time.Now().Add(-5*24*time.Hour))
	writeTestCert(t, dir, "valid.example.com", time.Now().Add(45*24*time.Hour))
	// A file (not a directory) alongside the real entries — certbot itself
	// leaves a README here — must not be treated as a domain.
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("test"), 0644); err != nil {
		t.Fatalf("write README: %v", err)
	}

	got, err := listLetsEncryptCerts(dir)
	if err != nil {
		t.Fatalf("listLetsEncryptCerts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d certs, want 2 (got: %+v)", len(got), got)
	}
	// Sorted by domain: "expired..." sorts before "valid...".
	if got[0].Domain != "expired.example.com" || !got[0].Expired {
		t.Errorf("expired.example.com not reported as expired: %+v", got[0])
	}
	if got[1].Domain != "valid.example.com" || got[1].Expired {
		t.Errorf("valid.example.com incorrectly reported as expired: %+v", got[1])
	}
	if got[1].DaysRemaining < 43 || got[1].DaysRemaining > 45 {
		t.Errorf("valid.example.com DaysRemaining = %d, want ~45", got[1].DaysRemaining)
	}
}

func TestListLetsEncryptCertsMissingBaseDirIsNotAnError(t *testing.T) {
	got, err := listLetsEncryptCerts(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("listLetsEncryptCerts on a missing dir returned an error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d certs from a missing dir, want 0", len(got))
	}
}

func TestListLetsEncryptCertsSkipsUnreadableEntry(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, "good.example.com", time.Now().Add(30*24*time.Hour))
	// A domain directory with no cert.pem in it at all (e.g. a partially
	// cleaned-up or mid-issuance directory) must not fail the whole report.
	if err := os.MkdirAll(filepath.Join(dir, "broken.example.com"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	got, err := listLetsEncryptCerts(dir)
	if err != nil {
		t.Fatalf("listLetsEncryptCerts: %v", err)
	}
	if len(got) != 1 || got[0].Domain != "good.example.com" {
		t.Fatalf("got %+v, want only good.example.com", got)
	}
}

func TestHandleSSLStatusRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLStatus(context.Background(), map[string]any{"domain": "; rm -rf /"}, func(string) {})
	if err == nil {
		t.Fatal("handleSSLStatus accepted an invalid domain")
	}
}

func TestHandleSSLStatusUnknownDomainErrors(t *testing.T) {
	// letsEncryptLiveDir won't exist in the test environment, so
	// listLetsEncryptCerts returns an empty (not error) result, and asking
	// for a specific domain within that empty set should error clearly
	// rather than silently returning an empty report.
	_, err := handleSSLStatus(context.Background(), map[string]any{"domain": "example.com"}, func(string) {})
	if err == nil {
		t.Fatal("handleSSLStatus should error when the requested domain has no certificate on this host")
	}
}
