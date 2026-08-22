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

func TestNewCSRProducesAVerifiableRequest(t *testing.T) {
	key, csrPEM, err := newCSR()
	if err != nil {
		t.Fatalf("newCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("newCSR did not return a PEM-encoded CSR: %+v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify against its own key: %v", err)
	}
	if key == nil {
		t.Fatal("newCSR returned a nil private key")
	}
}

// selfSignedTestCert builds a minimal self-signed certificate with the
// given NotAfter, standing in for a cert the control plane would have
// issued, so certNotAfter can be tested without spinning up a real CA.
func selfSignedTestCert(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertNotAfterMatchesIssuedExpiry(t *testing.T) {
	want := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	certPEM := selfSignedTestCert(t, want)

	got, err := certNotAfter(certPEM)
	if err != nil {
		t.Fatalf("certNotAfter: %v", err)
	}
	if diff := got.Sub(want); diff < -time.Second || diff > time.Second {
		t.Fatalf("certNotAfter = %s, want ~%s", got, want)
	}
}

func TestCertNotAfterRejectsGarbage(t *testing.T) {
	if _, err := certNotAfter([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for non-PEM input")
	}
}

func TestPersistRenewedIdentityReplacesFilesAtomically(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dataDir)

	if err := os.WriteFile(certPath, []byte("old-cert"), 0600); err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}

	if err := persistRenewedIdentity(dataDir, []byte("new-cert"), []byte("new-key")); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(gotCert) != "new-cert" {
		t.Fatalf("cert file = %q, want %q", gotCert, "new-cert")
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(gotKey) != "new-key" {
		t.Fatalf("key file = %q, want %q", gotKey, "new-key")
	}

	// No leftover temp files after a successful renewal.
	for _, tmp := range []string{certPath + ".tmp", keyPath + ".tmp"} {
		if _, err := os.Stat(tmp); !os.IsNotExist(err) {
			t.Fatalf("leftover temp file %s after successful persist", tmp)
		}
	}
}

func TestPersistRenewedIdentityFailsCleanlyOnUnwritableDir(t *testing.T) {
	// A data dir that doesn't exist at all: the initial temp-file write
	// fails before any rename, so the pre-existing identity (there is none
	// here, but in production there always is one) is left completely
	// untouched rather than partially replaced.
	err := persistRenewedIdentity(filepath.Join(t.TempDir(), "does-not-exist"), []byte("c"), []byte("k"))
	if err == nil {
		t.Fatal("expected an error writing into a nonexistent directory")
	}
}
