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
	"strings"
	"testing"
	"time"
)

// writeTestCert writes a minimal self-signed certificate for domain under
// liveDir/domain/cert.pem, expiring in ttl from now — enough to exercise
// certificateExpiry/handleSSLRenewalStatus's parsing without needing a real
// certbot install.
func writeTestCert(t *testing.T, liveDir, domain string, ttl time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	domainDir := filepath.Join(liveDir, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(domainDir, "cert.pem"), pemBytes, 0644); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}
}

func TestCertificateExpiryParsesRealCertificate(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, "example.com", 60*24*time.Hour)

	got, err := certificateExpiry(filepath.Join(dir, "example.com", "cert.pem"))
	if err != nil {
		t.Fatalf("certificateExpiry: %v", err)
	}
	wantAround := time.Now().Add(60 * 24 * time.Hour)
	if got.Sub(wantAround).Abs() > time.Hour {
		t.Errorf("NotAfter = %v, want close to %v", got, wantAround)
	}
}

func TestCertificateExpiryRejectsMissingFile(t *testing.T) {
	if _, err := certificateExpiry(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Fatal("expected error for missing certificate file")
	}
}

func TestCertificateExpiryRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := certificateExpiry(path); err == nil {
		t.Fatal("expected error for non-PEM content")
	}
}

func TestCertificateDomainsSortedAndSkipsNonDirs(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, "zzz.example.com", 30*24*time.Hour)
	writeTestCert(t, dir, "aaa.example.com", 30*24*time.Hour)
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("this directory contains..."), 0644); err != nil {
		t.Fatal(err)
	}

	domains, err := certificateDomains(dir)
	if err != nil {
		t.Fatalf("certificateDomains: %v", err)
	}
	want := []string{"aaa.example.com", "zzz.example.com"}
	if len(domains) != len(want) || domains[0] != want[0] || domains[1] != want[1] {
		t.Errorf("certificateDomains = %v, want %v", domains, want)
	}
}

func TestHandleSSLRenewalStatusReportsNoCertificates(t *testing.T) {
	orig := letsEncryptLiveDir
	defer func() { letsEncryptLiveDir = orig }()
	letsEncryptLiveDir = filepath.Join(t.TempDir(), "does-not-exist")

	detail, err := handleSSLRenewalStatus(context.Background(), nil, func(string) {})
	if err != nil {
		t.Fatalf("handleSSLRenewalStatus: %v", err)
	}
	if !strings.Contains(detail, "no Let's Encrypt certificates issued yet") {
		t.Errorf("detail = %q, want mention of no certificates issued", detail)
	}
}

func TestHandleSSLRenewalStatusReportsExpiryAndWarnsWhenDueSoon(t *testing.T) {
	orig := letsEncryptLiveDir
	defer func() { letsEncryptLiveDir = orig }()
	dir := t.TempDir()
	letsEncryptLiveDir = dir

	writeTestCert(t, dir, "healthy.example.com", 60*24*time.Hour)
	writeTestCert(t, dir, "expiring-soon.example.com", 5*24*time.Hour)
	writeTestCert(t, dir, "expired.example.com", -5*24*time.Hour)

	detail, err := handleSSLRenewalStatus(context.Background(), nil, func(string) {})
	if err != nil {
		t.Fatalf("handleSSLRenewalStatus: %v", err)
	}
	if !strings.Contains(detail, "healthy.example.com: expires") || strings.Contains(strings.SplitN(detail, "healthy.example.com", 2)[1], "EXPIRED") {
		t.Errorf("expected healthy.example.com to be reported without a warning, got: %q", detail)
	}
	if !strings.Contains(detail, "expiring-soon.example.com") || !strings.Contains(detail, "renewal due soon") {
		t.Errorf("expected a 'renewal due soon' warning for a cert expiring in 5 days, got: %q", detail)
	}
	if !strings.Contains(detail, "expired.example.com") || !strings.Contains(detail, "EXPIRED") {
		t.Errorf("expected an EXPIRED marker for an already-expired cert, got: %q", detail)
	}
}
