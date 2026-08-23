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

func testCert(t *testing.T, notAfter time.Time) []byte {
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

func TestCertExpiryParsesNotAfter(t *testing.T) {
	want := time.Now().Add(20 * 24 * time.Hour).Truncate(time.Second)
	certPEM := testCert(t, want)

	got, err := certExpiry(certPEM)
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if !got.Truncate(time.Second).Equal(want) {
		t.Fatalf("certExpiry = %s, want %s", got, want)
	}
}

func TestCertExpiryRejectsGarbage(t *testing.T) {
	if _, err := certExpiry([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM, got nil")
	}
}

func TestApplyRenewalPersistsCertAndKeyAtomically(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dataDir)

	// Pre-existing identity files, as if the agent had already registered.
	if err := os.WriteFile(certPath, []byte("old-cert"), 0600); err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	newCertPEM := testCert(t, time.Now().Add(30*24*time.Hour))

	if err := applyRenewal(dataDir, key, newCertPEM); err != nil {
		t.Fatalf("applyRenewal: %v", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(gotCert) != string(newCertPEM) {
		t.Fatalf("cert file was not updated to the renewed certificate")
	}

	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	wantKeyDER, _ := x509.MarshalECPrivateKey(key)
	wantKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: wantKeyDER})
	if string(gotKey) != string(wantKeyPEM) {
		t.Fatal("key file was not updated to the renewed key")
	}

	// No leftover .tmp files from the atomic write.
	if _, err := os.Stat(certPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no leftover %s.tmp", certPath)
	}
	if _, err := os.Stat(keyPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no leftover %s.tmp", keyPath)
	}

	// loadIdentity (used by main.go after errCertRenewed) must be able to
	// read back exactly what applyRenewal wrote, alongside the untouched
	// ca.pem/identity.json from the original registration.
	caPath := filepath.Join(dataDir, "ca.pem")
	if err := os.WriteFile(caPath, []byte("ca-pem"), 0600); err != nil {
		t.Fatalf("seed ca.pem: %v", err)
	}
	metaPath := filepath.Join(dataDir, "identity.json")
	if err := os.WriteFile(metaPath, []byte(`{"server_id":"srv_test","gateway_addr":"gw:443"}`), 0600); err != nil {
		t.Fatalf("seed identity.json: %v", err)
	}

	loaded, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity after renewal: %v", err)
	}
	if string(loaded.CertPEM) != string(newCertPEM) {
		t.Fatal("loadIdentity did not pick up the renewed certificate")
	}
	if loaded.ServerID != "srv_test" {
		t.Fatalf("loadIdentity ServerID = %q, want srv_test", loaded.ServerID)
	}
}
