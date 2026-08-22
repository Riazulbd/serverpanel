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

func TestShouldRenewCert(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	threshold := 7 * 24 * time.Hour

	cases := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"well before expiry", now.Add(30 * 24 * time.Hour), false},
		{"just outside the window", now.Add(threshold + time.Minute), false},
		{"exactly at the threshold", now.Add(threshold), true},
		{"inside the window", now.Add(3 * 24 * time.Hour), true},
		{"already expired", now.Add(-time.Hour), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldRenewCert(c.notAfter, now, threshold); got != c.want {
				t.Errorf("shouldRenewCert(notAfter=%s) = %v, want %v", c.notAfter, got, c.want)
			}
		})
	}
}

// selfSignedTestCert builds a minimal self-signed certificate with a known
// NotAfter, for exercising certExpiry without depending on the control
// plane's CA package.
func selfSignedTestCert(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertExpiryRoundTrip(t *testing.T) {
	want := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	certPEM := selfSignedTestCert(t, want)

	got, err := certExpiry(certPEM)
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	// x509 certificates only have second-granularity timestamps.
	if !got.Truncate(time.Second).Equal(want.Truncate(time.Second)) {
		t.Fatalf("certExpiry() = %s, want %s", got, want)
	}
}

func TestCertExpiryRejectsInvalidPEM(t *testing.T) {
	if _, err := certExpiry([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM")
	}
}

func TestGenerateRenewalCSR(t *testing.T) {
	csrPEM, keyPEM, err := generateRenewalCSR("srv_abc123")
	if err != nil {
		t.Fatalf("generateRenewalCSR: %v", err)
	}

	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		t.Fatal("CSR PEM did not decode")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "srv_abc123" {
		t.Fatalf("CSR CommonName = %q, want %q", csr.Subject.CommonName, "srv_abc123")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("key PEM did not decode")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse EC private key: %v", err)
	}
	csrPubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CSR public key type = %T, want *ecdsa.PublicKey", csr.PublicKey)
	}
	if !key.PublicKey.Equal(csrPubKey) {
		t.Fatal("returned private key does not match the CSR's public key")
	}
}

func TestGenerateRenewalCSRProducesFreshKeysEachCall(t *testing.T) {
	_, key1, err := generateRenewalCSR("srv_1")
	if err != nil {
		t.Fatalf("generateRenewalCSR: %v", err)
	}
	_, key2, err := generateRenewalCSR("srv_1")
	if err != nil {
		t.Fatalf("generateRenewalCSR: %v", err)
	}
	if string(key1) == string(key2) {
		t.Fatal("expected a fresh keypair on every renewal, got identical key material")
	}
}

func TestPersistRenewedCert(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dataDir)

	// Simulate a pre-existing identity (as if from a prior registration).
	if err := os.WriteFile(certPath, []byte("old-cert"), 0600); err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}

	newCert := []byte("new-cert-pem")
	newKey := []byte("new-key-pem")
	if err := persistRenewedCert(dataDir, newCert, newKey); err != nil {
		t.Fatalf("persistRenewedCert: %v", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(gotCert) != string(newCert) {
		t.Fatalf("cert file = %q, want %q", gotCert, newCert)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(gotKey) != string(newKey) {
		t.Fatalf("key file = %q, want %q", gotKey, newKey)
	}

	// No leftover .tmp files.
	if _, err := os.Stat(certPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected cert .tmp file to be gone, stat err = %v", err)
	}
	if _, err := os.Stat(keyPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected key .tmp file to be gone, stat err = %v", err)
	}

	// File permissions should stay owner-only.
	info, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("cert file mode = %v, want 0600", perm)
	}
}

func TestPersistRenewedCertFailsCleanlyOnUnwritableDir(t *testing.T) {
	if err := persistRenewedCert(filepath.Join(t.TempDir(), "does-not-exist"), []byte("c"), []byte("k")); err == nil {
		t.Fatal("expected an error writing into a nonexistent directory")
	}
}
