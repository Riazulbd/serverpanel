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

// selfSignedCert builds a minimal self-signed leaf certificate with the
// given NotAfter, for exercising dueForRenewal/leafExpiry without needing
// the control plane's CA.
func selfSignedCert(t *testing.T, notAfter time.Time) []byte {
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

func TestDueForRenewalWindow(t *testing.T) {
	fresh := selfSignedCert(t, time.Now().Add(29*24*time.Hour))
	if dueForRenewal(fresh) {
		t.Error("a certificate with 29 days left should not be due for renewal")
	}

	expiringSoon := selfSignedCert(t, time.Now().Add(5*24*time.Hour))
	if !dueForRenewal(expiringSoon) {
		t.Error("a certificate with 5 days left should be due for renewal")
	}
}

func TestDueForRenewalTreatsUnparsableCertAsDue(t *testing.T) {
	if !dueForRenewal([]byte("not a certificate")) {
		t.Error("an unparsable certificate should be treated as due for renewal")
	}
}

func TestLeafExpiryRoundTrips(t *testing.T) {
	want := time.Now().Add(72 * time.Hour).UTC().Round(time.Second)
	cert := selfSignedCert(t, want)
	got, err := leafExpiry(cert)
	if err != nil {
		t.Fatalf("leafExpiry: %v", err)
	}
	if got.Round(time.Second).Unix() != want.Unix() {
		t.Errorf("leafExpiry = %s, want %s", got, want)
	}
}

func TestBuildRenewalCSRIsSelfConsistent(t *testing.T) {
	csrPEM, keyPEM, err := buildRenewalCSR("server-123")
	if err != nil {
		t.Fatalf("buildRenewalCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR did not decode as PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature does not verify against its own key: %v", err)
	}
	if csr.Subject.CommonName != "server-123" {
		t.Errorf("CSR CommonName = %q, want %q", csr.Subject.CommonName, "server-123")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("key did not decode as PEM")
	}
	if _, err := x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
		t.Errorf("returned key is not a valid EC private key: %v", err)
	}
}

func TestPersistRenewedIdentityWritesAtomicallyAndBacksUpOld(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dir)

	if err := os.WriteFile(certPath, []byte("old-cert"), 0600); err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatalf("seed old key: %v", err)
	}

	if err := persistRenewedIdentity(dir, []byte("new-cert"), []byte("new-key")); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil || string(gotCert) != "new-cert" {
		t.Errorf("cert path = %q, %v; want new-cert", gotCert, err)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil || string(gotKey) != "new-key" {
		t.Errorf("key path = %q, %v; want new-key", gotKey, err)
	}

	bakCert, err := os.ReadFile(certPath + ".bak")
	if err != nil || string(bakCert) != "old-cert" {
		t.Errorf("cert backup = %q, %v; want old-cert", bakCert, err)
	}
	bakKey, err := os.ReadFile(keyPath + ".bak")
	if err != nil || string(bakKey) != "old-key" {
		t.Errorf("key backup = %q, %v; want old-key", bakKey, err)
	}

	// No leftover .tmp files after a successful write.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestPersistRenewedIdentityWithoutExistingFilesSkipsBackup(t *testing.T) {
	dir := t.TempDir()
	if err := persistRenewedIdentity(dir, []byte("cert"), []byte("key")); err != nil {
		t.Fatalf("persistRenewedIdentity on empty dir: %v", err)
	}
	certPath, keyPath, _, _ := identityPaths(dir)
	if _, err := os.Stat(certPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf("expected no cert backup when nothing existed before, stat err = %v", err)
	}
	if _, err := os.Stat(keyPath + ".bak"); !os.IsNotExist(err) {
		t.Errorf("expected no key backup when nothing existed before, stat err = %v", err)
	}
}
