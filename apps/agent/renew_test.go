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
// NotAfter, standing in for a CA-issued agent cert — renew.go's certExpiry
// only reads NotAfter from the parsed certificate, so a self-signed one
// exercises the same parsing path as a real one.
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

func TestCertExpiry(t *testing.T) {
	want := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	certPEM := selfSignedCertPEM(t, want)

	got, err := certExpiry(certPEM)
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("certExpiry = %v, want %v", got, want)
	}
}

func TestCertExpiryRejectsGarbage(t *testing.T) {
	if _, err := certExpiry([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for non-PEM input")
	}
}

func TestAtomicWriteFileReplacesExistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")

	if err := atomicWriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := atomicWriteFile(path, []byte("second"), 0600); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("content = %q, want %q", got, "second")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected .tmp file to be renamed away, stat err = %v", err)
	}
}

func TestPersistRenewedIdentityUpdatesDiskAndMemory(t *testing.T) {
	dir := t.TempDir()
	oldCert := selfSignedCertPEM(t, time.Now().Add(1*24*time.Hour))
	id := &identity{ServerID: "srv_test", CertPEM: oldCert, KeyPEM: []byte("old-key"), GatewayAddr: "gw:8843"}

	// identityPaths' cert/key paths must already be creatable; dataDir
	// itself need not pre-exist beyond what register() would already have
	// created (MkdirAll'd at first registration), so create it here too.
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	newCert := selfSignedCertPEM(t, time.Now().Add(30*24*time.Hour))
	newKey := []byte("new-key")

	if err := persistRenewedIdentity(dir, id, newCert, newKey); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	certPath, keyPath, _, _ := identityPaths(dir)
	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(gotCert) != string(newCert) {
		t.Fatal("cert file on disk does not match renewed certificate")
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(gotKey) != string(newKey) {
		t.Fatal("key file on disk does not match renewed key")
	}

	snapCert, snapKey := id.snapshot()
	if string(snapCert) != string(newCert) || string(snapKey) != string(newKey) {
		t.Fatal("in-memory identity was not updated to the renewed cert/key")
	}
}
