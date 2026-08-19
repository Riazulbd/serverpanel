package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertExpiryParsesNotAfter(t *testing.T) {
	key, csrPEM, err := newKeyAndCSR()
	if err != nil {
		t.Fatalf("newKeyAndCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("generated CSR is not valid PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	wantExpiry := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     wantExpiry,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	got, err := certExpiry(certPEM)
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if !got.Equal(wantExpiry) {
		t.Fatalf("certExpiry = %v, want %v", got, wantExpiry)
	}
}

func TestCertExpiryRejectsInvalidPEM(t *testing.T) {
	if _, err := certExpiry([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM")
	}
}

func TestPendingRenewalFinishPersistsAndUpdatesIdentity(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := os.WriteFile(certPath, []byte("old-cert"), 0600); err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}

	p, csrPEM, err := startRenewal()
	if err != nil {
		t.Fatalf("startRenewal: %v", err)
	}
	if len(csrPEM) == 0 {
		t.Fatal("expected a non-empty CSR")
	}

	id := &identity{ServerID: "srv_test", CertPEM: []byte("old-cert"), KeyPEM: []byte("old-key")}
	const newCertPEM = "new-cert-pem"
	if err := p.finish(dataDir, id, newCertPEM); err != nil {
		t.Fatalf("finish: %v", err)
	}

	if string(id.CertPEM) != newCertPEM {
		t.Fatalf("id.CertPEM = %q, want %q", id.CertPEM, newCertPEM)
	}
	if len(id.KeyPEM) == 0 || string(id.KeyPEM) == "old-key" {
		t.Fatal("id.KeyPEM should be replaced with the freshly generated key")
	}

	onDiskCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read persisted cert: %v", err)
	}
	if string(onDiskCert) != newCertPEM {
		t.Fatalf("persisted cert = %q, want %q", onDiskCert, newCertPEM)
	}
	onDiskKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	if string(onDiskKey) != string(id.KeyPEM) {
		t.Fatal("persisted key does not match id.KeyPEM")
	}

	info, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("cert file mode = %v, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(certPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind after atomic write")
	}
}

func TestAtomicWriteFileLeavesNoTempFileOnSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	if err := atomicWriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("content = %q, want %q", got, "hello")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should not remain after a successful write")
	}
}
