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

func selfSignedCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "srv_test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertNotAfterParsesExpiry(t *testing.T) {
	want := time.Now().Add(15 * 24 * time.Hour).Truncate(time.Second)
	certPEM := selfSignedCertPEM(t, want)

	got, err := certNotAfter(certPEM)
	if err != nil {
		t.Fatalf("certNotAfter: %v", err)
	}
	if !got.Truncate(time.Second).Equal(want) {
		t.Fatalf("NotAfter = %v, want %v", got, want)
	}
}

func TestCertNotAfterRejectsGarbage(t *testing.T) {
	if _, err := certNotAfter([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM, got nil")
	}
}

// TestRenewBeforeExpiryBoundary pins the renewal decision's actual
// threshold in a test, so a future change to renewBeforeExpiry or to the
// CA's issuance TTL (apps/controlplane/http.go, apps/controlplane/gateway.go
// both use 30*24*time.Hour) is forced to consider the other side rather
// than drifting out of sync silently.
func TestRenewBeforeExpiryBoundary(t *testing.T) {
	issuanceTTL := 30 * 24 * time.Hour
	if renewBeforeExpiry >= issuanceTTL {
		t.Fatalf("renewBeforeExpiry (%s) must be well under the certificate issuance TTL (%s), or a freshly issued cert would trigger immediate renewal", renewBeforeExpiry, issuanceTTL)
	}

	freshCert := selfSignedCertPEM(t, time.Now().Add(issuanceTTL))
	notAfter, err := certNotAfter(freshCert)
	if err != nil {
		t.Fatalf("certNotAfter: %v", err)
	}
	if time.Until(notAfter) <= renewBeforeExpiry {
		t.Fatal("a freshly issued certificate should not already be inside the renewal window")
	}

	expiringSoon := selfSignedCertPEM(t, time.Now().Add(renewBeforeExpiry-time.Hour))
	notAfter, err = certNotAfter(expiringSoon)
	if err != nil {
		t.Fatalf("certNotAfter: %v", err)
	}
	if time.Until(notAfter) > renewBeforeExpiry {
		t.Fatal("a certificate expiring within the renewal window should be due for renewal")
	}
}

func TestWriteFileAtomicReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.pem")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := writeFileAtomic(path, []byte("new"), 0600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("file contents = %q, want %q", got, "new")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should not be left behind after a successful atomic write")
	}
}
