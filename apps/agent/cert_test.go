package main

import (
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

func TestGenerateKeyAndCSRProducesAValidSelfSignedCSR(t *testing.T) {
	key, csrPEM, err := generateKeyAndCSR("test-cn")
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected a CERTIFICATE REQUEST PEM block, got %+v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	// This is exactly what the control plane's CA does before signing
	// (ca.go signAgentCSR) — a CSR that doesn't verify here would be
	// rejected by every registration/renewal attempt.
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify: %v", err)
	}
	if csr.Subject.CommonName != "test-cn" {
		t.Fatalf("CSR CommonName = %q, want %q", csr.Subject.CommonName, "test-cn")
	}
	if key == nil {
		t.Fatal("expected a non-nil private key")
	}
}

// selfSignedCert builds a minimal self-signed certificate PEM with the
// given validity window, for exercising certValidity without needing a
// real CA round trip.
func selfSignedCert(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, _, err := generateKeyAndCSR("irrelevant")
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
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
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	certPEM := selfSignedCert(t, notBefore, notAfter)

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
		t.Fatal("expected an error for invalid certificate PEM")
	}
}

func TestPersistRenewedCertReplacesCertAndKeyAtomically(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dir)
	oldCert := []byte("-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n")
	oldKey := []byte("-----BEGIN EC PRIVATE KEY-----\nold\n-----END EC PRIVATE KEY-----\n")
	if err := os.WriteFile(certPath, oldCert, 0600); err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, oldKey, 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}

	newCert := []byte("-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n")
	newKey := []byte("-----BEGIN EC PRIVATE KEY-----\nnew\n-----END EC PRIVATE KEY-----\n")
	if err := persistRenewedCert(dir, newCert, newKey); err != nil {
		t.Fatalf("persistRenewedCert: %v", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil || string(gotCert) != string(newCert) {
		t.Fatalf("cert on disk = %q, %v; want %q", gotCert, err, newCert)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil || string(gotKey) != string(newKey) {
		t.Fatalf("key on disk = %q, %v; want %q", gotKey, err, newKey)
	}

	// No leftover temp/backup files should survive a successful renewal.
	for _, leftover := range []string{certPath + ".tmp", keyPath + ".tmp", certPath + ".bak"} {
		if _, err := os.Stat(leftover); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be cleaned up, stat err = %v", leftover, err)
		}
	}
}

func TestPersistRenewedCertFailsCleanlyWhenNoExistingIdentity(t *testing.T) {
	dir := t.TempDir() // empty: no cert/key ever written here
	err := persistRenewedCert(dir, []byte("new-cert"), []byte("new-key"))
	if err == nil {
		t.Fatal("expected an error when there is no existing certificate to renew")
	}

	certPath, keyPath, _, _ := identityPaths(dir)
	if _, statErr := os.Stat(certPath); !os.IsNotExist(statErr) {
		t.Fatal("a failed renewal must not create a cert file out of nowhere")
	}
	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatal("a failed renewal must not create a key file out of nowhere")
	}
}

func TestPersistRenewedCertLeavesNoTempFilesOnKeyWriteFailure(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dir)
	if err := os.WriteFile(certPath, []byte("old-cert"), 0600); err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}

	// Make the key path itself a directory so writing the new key file
	// fails partway through — the old cert must remain exactly as it was.
	badKeyPath := filepath.Join(dir, "agent-key.pem")
	os.Remove(badKeyPath)
	if err := os.Mkdir(badKeyPath, 0700); err != nil {
		t.Fatalf("seed conflicting directory: %v", err)
	}

	err := persistRenewedCert(dir, []byte("new-cert"), []byte("new-key"))
	if err == nil {
		t.Fatal("expected an error when the key file can't be written")
	}

	gotCert, readErr := os.ReadFile(certPath)
	if readErr != nil || string(gotCert) != "old-cert" {
		t.Fatalf("original cert should be untouched after a failed renewal, got %q, %v", gotCert, readErr)
	}
	if _, statErr := os.Stat(certPath + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatal("temp cert file should be cleaned up after failure")
	}
	// The temp key file holds a private key that never got installed —
	// leaving it behind would mean an unused, unmanaged copy of key
	// material sitting permanently on disk.
	if _, statErr := os.Stat(keyPath + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatal("temp key file should be cleaned up after failure")
	}
	if _, statErr := os.Stat(certPath + ".bak"); !os.IsNotExist(statErr) {
		t.Fatal("cert backup file should be cleaned up after a failure that already rolled back")
	}
}
