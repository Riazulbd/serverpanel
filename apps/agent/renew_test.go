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

func selfSignedTestCert(t *testing.T, notAfter time.Time) []byte {
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

func TestCertNotAfterParsesRealExpiry(t *testing.T) {
	want := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	certPEM := selfSignedTestCert(t, want)

	got, err := certNotAfter(certPEM)
	if err != nil {
		t.Fatalf("certNotAfter: %v", err)
	}
	if got.Sub(want).Abs() > time.Second {
		t.Fatalf("certNotAfter = %v, want ~%v", got, want)
	}
}

func TestCertNotAfterRejectsGarbage(t *testing.T) {
	if _, err := certNotAfter([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM, got nil")
	}
}

func TestPersistRenewedIdentityWritesAtomicallyAndUpdatesInMemory(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dataDir)

	oldCert := []byte("old-cert-placeholder")
	if err := os.WriteFile(certPath, oldCert, 0600); err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key-placeholder"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}

	id := &identity{ServerID: "srv_test", CertPEM: oldCert, KeyPEM: []byte("old-key-placeholder"), DataDir: dataDir}

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	newCertPEM := selfSignedTestCert(t, time.Now().Add(30*24*time.Hour))

	if err := persistRenewedIdentity(id, newKey, newCertPEM); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	if string(id.CertPEM) != string(newCertPEM) {
		t.Fatal("in-memory identity.CertPEM was not updated")
	}

	onDiskCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read persisted cert: %v", err)
	}
	if string(onDiskCert) != string(newCertPEM) {
		t.Fatal("persisted certificate on disk does not match the renewed certificate")
	}

	// No leftover .tmp file from the atomic rename.
	if _, err := os.Stat(certPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no leftover temp file, stat err = %v", err)
	}

	// The new key must actually parse as a valid EC private key.
	onDiskKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	block, _ := pem.Decode(onDiskKey)
	if block == nil {
		t.Fatal("persisted key is not valid PEM")
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
		t.Fatalf("persisted key does not parse: %v", err)
	}
}

func TestAtomicWriteFileLeavesNoTempFileAndSetsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := atomicWriteFile(path, []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions = %v, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no leftover temp file, stat err = %v", err)
	}
}
