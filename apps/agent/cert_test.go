package main

import (
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

// selfSignedCertPEM builds a minimal self-signed certificate with the given
// validity window, enough for certValidity to parse — it doesn't need a
// real CA chain since certValidity only reads NotBefore/NotAfter.
func selfSignedCertPEM(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertValidityParsesNotBeforeAndNotAfter(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(30 * 24 * time.Hour)
	certPEM := selfSignedCertPEM(t, notBefore, notAfter)

	gotBefore, gotAfter, err := certValidity(certPEM)
	if err != nil {
		t.Fatalf("certValidity: %v", err)
	}
	if !gotBefore.Equal(notBefore) {
		t.Fatalf("NotBefore = %v, want %v", gotBefore, notBefore)
	}
	if !gotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter = %v, want %v", gotAfter, notAfter)
	}
}

func TestCertValidityRejectsGarbage(t *testing.T) {
	if _, _, err := certValidity([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for non-PEM input")
	}
	if _, _, err := certValidity([]byte("-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n")); err == nil {
		t.Fatal("expected an error for PEM that doesn't parse as a certificate")
	}
}

// TestNextRenewalAtIsWellBeforeExpiry pins down the renewal policy: renewal
// must happen with a comfortable margin before expiry (not last-minute),
// and must not be scheduled before the certificate is even valid.
func TestNextRenewalAtIsWellBeforeExpiry(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(30 * 24 * time.Hour)

	renewAt := nextRenewalAt(notBefore, notAfter)

	if !renewAt.After(notBefore) {
		t.Fatalf("renewAt = %v must be after notBefore = %v", renewAt, notBefore)
	}
	if !renewAt.Before(notAfter) {
		t.Fatalf("renewAt = %v must be before notAfter = %v", renewAt, notAfter)
	}
	marginBeforeExpiry := notAfter.Sub(renewAt)
	wantMargin := 10 * 24 * time.Hour // two-thirds through a 30-day cert = 10 days left
	if marginBeforeExpiry != wantMargin {
		t.Fatalf("margin before expiry = %v, want %v", marginBeforeExpiry, wantMargin)
	}
}

func TestNewKeyAndCSRProducesAVerifiableCSR(t *testing.T) {
	_, csrPEM, err := newKeyAndCSR("some-name")
	if err != nil {
		t.Fatalf("newKeyAndCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("csrPEM did not decode to a CERTIFICATE REQUEST block: %+v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify: %v", err)
	}
}

func TestPemEncodeECKeyRoundTrips(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM, err := pemEncodeECKey(key)
	if err != nil {
		t.Fatalf("pemEncodeECKey: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("keyPEM did not decode")
	}
	parsed, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse EC key: %v", err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Fatal("round-tripped key does not match the original")
	}
}

func TestPersistRenewedCertOverwritesExistingFiles(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := os.WriteFile(certPath, []byte("old-cert"), 0600); err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}

	if err := persistRenewedCert(dataDir, []byte("new-cert"), []byte("new-key")); err != nil {
		t.Fatalf("persistRenewedCert: %v", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil || string(gotCert) != "new-cert" {
		t.Fatalf("cert file = %q, err=%v, want %q", gotCert, err, "new-cert")
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil || string(gotKey) != "new-key" {
		t.Fatalf("key file = %q, err=%v, want %q", gotKey, err, "new-key")
	}

	// No leftover .tmp files from the atomic-write-then-rename.
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover temp file after persistRenewedCert: %s", e.Name())
		}
	}
}
