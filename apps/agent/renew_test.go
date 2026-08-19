package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

func genSelfSignedPair(t *testing.T, cn string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeInitialIdentity seeds dataDir with a complete on-disk identity
// (cert, key, CA, metadata) so loadIdentity/persistRenewedIdentity can be
// exercised without going through the network register() flow.
func writeInitialIdentity(t *testing.T, dataDir string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	mustWriteFile(t, certPath, certPEM)
	mustWriteFile(t, keyPath, keyPEM)
	mustWriteFile(t, caPath, []byte("dummy-ca-pem"))
	meta, _ := json.Marshal(map[string]string{"server_id": "srv-test", "gateway_addr": "127.0.0.1:9999"})
	mustWriteFile(t, metaPath, meta)
}

func TestCertDueForRenewal(t *testing.T) {
	farCert, _ := genSelfSignedPair(t, "srv-test", time.Now().Add(30*24*time.Hour))
	due, _, err := certDueForRenewal(farCert)
	if err != nil {
		t.Fatalf("certDueForRenewal: %v", err)
	}
	if due {
		t.Fatal("a certificate 30 days from expiry should not be due for renewal yet")
	}

	soonCert, _ := genSelfSignedPair(t, "srv-test", time.Now().Add(2*24*time.Hour))
	due, _, err = certDueForRenewal(soonCert)
	if err != nil {
		t.Fatalf("certDueForRenewal: %v", err)
	}
	if !due {
		t.Fatal("a certificate 2 days from expiry should be due for renewal")
	}
}

func TestCertDueForRenewalRejectsGarbage(t *testing.T) {
	if _, _, err := certDueForRenewal([]byte("not a pem certificate")); err == nil {
		t.Fatal("expected an error for unparseable certificate data")
	}
}

func TestPersistRenewedIdentityRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	oldCert, oldKey := genSelfSignedPair(t, "srv-test", time.Now().Add(24*time.Hour))
	writeInitialIdentity(t, dataDir, oldCert, oldKey)

	newCert, newKey := genSelfSignedPair(t, "srv-test", time.Now().Add(30*24*time.Hour))
	if err := persistRenewedIdentity(dataDir, newCert, newKey); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	id, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity after renewal: %v", err)
	}
	if string(id.CertPEM) != string(newCert) || string(id.KeyPEM) != string(newKey) {
		t.Fatal("loaded identity does not reflect the renewed certificate/key")
	}

	certPath, keyPath, _, _ := identityPaths(dataDir)
	prevCert, err := os.ReadFile(certPath + ".prev")
	if err != nil {
		t.Fatalf("expected a backed-up previous certificate: %v", err)
	}
	if string(prevCert) != string(oldCert) {
		t.Fatal("backup certificate does not match the pre-renewal certificate")
	}
	prevKey, err := os.ReadFile(keyPath + ".prev")
	if err != nil {
		t.Fatalf("expected a backed-up previous key: %v", err)
	}
	if string(prevKey) != string(oldKey) {
		t.Fatal("backup key does not match the pre-renewal key")
	}
}

func TestPersistRenewedIdentityRejectsMismatchedPair(t *testing.T) {
	dataDir := t.TempDir()
	oldCert, oldKey := genSelfSignedPair(t, "srv-test", time.Now().Add(24*time.Hour))
	writeInitialIdentity(t, dataDir, oldCert, oldKey)

	newCert, _ := genSelfSignedPair(t, "srv-test", time.Now().Add(30*24*time.Hour))
	_, unrelatedKey := genSelfSignedPair(t, "srv-test", time.Now().Add(30*24*time.Hour))

	if err := persistRenewedIdentity(dataDir, newCert, unrelatedKey); err == nil {
		t.Fatal("expected persistRenewedIdentity to reject a cert/key pair that doesn't match")
	}

	// Rejected renewal must leave the existing identity completely
	// untouched — no partial writes, no backup files created.
	id, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity after rejected renewal: %v", err)
	}
	if string(id.CertPEM) != string(oldCert) {
		t.Fatal("original certificate should be untouched after a rejected renewal")
	}
	certPath, _, _, _ := identityPaths(dataDir)
	if _, err := os.Stat(certPath + ".prev"); err == nil {
		t.Fatal("no backup file should be created for a renewal that was never persisted")
	}
}

// TestLoadIdentityRecoversFromInterruptedRenewal simulates the exact crash
// window persistRenewedIdentity is designed to survive: the backup and the
// new certificate were written, but the process died before the matching
// new key followed, leaving a mismatched cert(new)/key(old) pair as the
// live identity files.
func TestLoadIdentityRecoversFromInterruptedRenewal(t *testing.T) {
	dataDir := t.TempDir()
	oldCert, oldKey := genSelfSignedPair(t, "srv-test", time.Now().Add(24*time.Hour))
	writeInitialIdentity(t, dataDir, oldCert, oldKey)

	newCert, _ := genSelfSignedPair(t, "srv-test", time.Now().Add(30*24*time.Hour))

	certPath, keyPath, _, _ := identityPaths(dataDir)
	mustWriteFile(t, certPath+".prev", oldCert)
	mustWriteFile(t, keyPath+".prev", oldKey)
	mustWriteFile(t, certPath, newCert) // key path still holds the old key

	id, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity should recover from the backup pair, got error: %v", err)
	}
	if string(id.CertPEM) != string(oldCert) || string(id.KeyPEM) != string(oldKey) {
		t.Fatal("loadIdentity did not recover the previous, matching cert/key pair")
	}
}

func TestLoadIdentityFailsWhenMismatchedAndNoBackup(t *testing.T) {
	dataDir := t.TempDir()
	oldCert, oldKey := genSelfSignedPair(t, "srv-test", time.Now().Add(24*time.Hour))
	writeInitialIdentity(t, dataDir, oldCert, oldKey)

	newCert, _ := genSelfSignedPair(t, "srv-test", time.Now().Add(30*24*time.Hour))
	certPath, _, _, _ := identityPaths(dataDir)
	mustWriteFile(t, certPath, newCert) // no .prev backup available

	if _, err := loadIdentity(dataDir); err == nil {
		t.Fatal("expected loadIdentity to fail loudly when the pair is mismatched and unrecoverable")
	}
}
