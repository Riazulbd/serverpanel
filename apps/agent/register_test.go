package main

import (
	"bytes"
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

// selfSignedCertPEM builds a throwaway self-signed certificate valid from
// now until notAfter, for exercising needsRenewal/parseCertPEM without a
// real CA round trip.
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

func TestGenerateKeyAndCSRRoundTrips(t *testing.T) {
	key, csrPEM, err := generateKeyAndCSR("pending-registration")
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
	}
	if key == nil {
		t.Fatal("nil key returned")
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
		t.Fatalf("CSR signature does not verify against its own embedded key: %v", err)
	}
}

func TestMarshalECKeyPEMRoundTrips(t *testing.T) {
	key, _, err := generateKeyAndCSR("x")
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
	}
	keyPEM, err := marshalECKeyPEM(key)
	if err != nil {
		t.Fatalf("marshalECKeyPEM: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatalf("keyPEM did not decode to an EC PRIVATE KEY block: %+v", block)
	}
	parsed, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse EC private key: %v", err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Fatal("round-tripped key does not match the original")
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		notAfter  time.Time
		threshold time.Duration
		want      bool
	}{
		{"far from expiry", now.Add(30 * 24 * time.Hour), 7 * 24 * time.Hour, false},
		{"just inside threshold", now.Add(6 * 24 * time.Hour), 7 * 24 * time.Hour, true},
		{"already expired", now.Add(-time.Hour), 7 * 24 * time.Hour, true},
		{"just outside threshold", now.Add(8 * 24 * time.Hour), 7 * 24 * time.Hour, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert := &x509.Certificate{NotAfter: c.notAfter}
			if got := needsRenewal(cert, now, c.threshold); got != c.want {
				t.Fatalf("needsRenewal(NotAfter=%s, threshold=%s) = %v, want %v", c.notAfter, c.threshold, got, c.want)
			}
		})
	}
}

func TestParseCertPEMRejectsGarbage(t *testing.T) {
	if _, err := parseCertPEM([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error parsing non-PEM garbage")
	}
}

func TestParseCertPEMParsesRealCert(t *testing.T) {
	certPEM := selfSignedCertPEM(t, time.Now().Add(24*time.Hour))
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parseCertPEM: %v", err)
	}
	if cert.Subject.CommonName != "srv_test" {
		t.Fatalf("CommonName = %q, want srv_test", cert.Subject.CommonName)
	}
}

func TestGenerateRenewalCSRProducesDistinctKeyEachCall(t *testing.T) {
	key1PEM, csr1, err := generateRenewalCSR()
	if err != nil {
		t.Fatalf("generateRenewalCSR: %v", err)
	}
	key2PEM, csr2, err := generateRenewalCSR()
	if err != nil {
		t.Fatalf("generateRenewalCSR: %v", err)
	}
	if bytes.Equal(key1PEM, key2PEM) {
		t.Fatal("two renewal calls produced the same private key")
	}
	if bytes.Equal(csr1, csr2) {
		t.Fatal("two renewal calls produced the same CSR")
	}
}

func TestAtomicWriteFileReplacesContentAndLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.pem")

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
		t.Fatalf("expected the .tmp file to be gone after rename, stat err = %v", err)
	}
}

func TestPersistRenewedIdentityWritesFilesAndUpdatesInMemoryIdentity(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity("srv_test", []byte("old-cert"), []byte("old-key"), []byte("ca-pem"), "127.0.0.1:1234")
	newCert := []byte("new-cert-pem")
	newKey := []byte("new-key-pem")

	if err := persistRenewedIdentity(dir, id, newCert, newKey); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	gotCertPEM, gotKeyPEM := id.certKeyPEM()
	if !bytes.Equal(gotCertPEM, newCert) || !bytes.Equal(gotKeyPEM, newKey) {
		t.Fatal("in-memory identity was not updated with the renewed cert/key")
	}

	certPath, keyPath, _, _ := identityPaths(dir)
	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read persisted cert: %v", err)
	}
	if !bytes.Equal(gotCert, newCert) {
		t.Fatalf("persisted cert = %q, want %q", gotCert, newCert)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	if !bytes.Equal(gotKey, newKey) {
		t.Fatalf("persisted key = %q, want %q", gotKey, newKey)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key file mode = %v, want 0600 (private key must stay root-only)", info.Mode().Perm())
	}
}

// A fresh process calling loadIdentity after persistRenewedIdentity must see
// the renewed cert/key, not the ones from the original registration — this
// is what makes renewal survive an agent restart, not just an in-memory
// reconnect.
func TestPersistRenewedIdentitySurvivesReloadFromDisk(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity("srv_test", []byte("old-cert"), []byte("old-key"), []byte("ca-pem"), "127.0.0.1:1234")

	// Seed the on-disk files as register() would have.
	certPath, keyPath, caPath, metaPath := identityPaths(dir)
	seedCertPEM, seedKeyPEM := id.certKeyPEM()
	if err := os.WriteFile(certPath, seedCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, seedKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, id.CAPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, []byte(`{"server_id":"srv_test","gateway_addr":"127.0.0.1:1234"}`), 0600); err != nil {
		t.Fatal(err)
	}

	newCert, newKey := []byte("renewed-cert"), []byte("renewed-key")
	if err := persistRenewedIdentity(dir, id, newCert, newKey); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	reloaded, err := loadIdentity(dir)
	if err != nil {
		t.Fatalf("loadIdentity after renewal: %v", err)
	}
	reloadedCertPEM, reloadedKeyPEM := reloaded.certKeyPEM()
	if !bytes.Equal(reloadedCertPEM, newCert) || !bytes.Equal(reloadedKeyPEM, newKey) {
		t.Fatal("reloaded identity from disk still has the pre-renewal cert/key")
	}
}
