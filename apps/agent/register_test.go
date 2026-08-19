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
	"strings"
	"testing"
	"time"
)

// issueTestCert mints a self-signed certificate with the given expiry,
// standing in for one the control plane's CA would have issued.
func issueTestCert(t *testing.T, notAfter time.Time) []byte {
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

func TestCertNotAfter(t *testing.T) {
	want := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	id := &identity{CertPEM: issueTestCert(t, want)}

	got, err := id.certNotAfter()
	if err != nil {
		t.Fatalf("certNotAfter: %v", err)
	}
	if !got.Equal(want.UTC()) {
		t.Fatalf("certNotAfter = %s, want %s", got, want.UTC())
	}
}

func TestCertNotAfterRejectsGarbage(t *testing.T) {
	for name, certPEM := range map[string][]byte{
		"empty":        nil,
		"not PEM":      []byte("this is not a certificate"),
		"PEM but junk": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
	} {
		if _, err := (&identity{CertPEM: certPEM}).certNotAfter(); err == nil {
			t.Errorf("certNotAfter(%s) returned no error", name)
		}
	}
}

// TestNewRenewalCSRUsesAFreshKey covers the property that makes rotation
// worth doing: each renewal is a new keypair, not a re-certification of the
// key an attacker may already have.
func TestNewRenewalCSRUsesAFreshKey(t *testing.T) {
	csrA, keyA, err := newRenewalCSR()
	if err != nil {
		t.Fatalf("newRenewalCSR: %v", err)
	}
	_, keyB, err := newRenewalCSR()
	if err != nil {
		t.Fatalf("newRenewalCSR: %v", err)
	}
	if string(keyA) == string(keyB) {
		t.Fatal("two renewals produced the same private key")
	}

	block, _ := pem.Decode(csrA)
	if block == nil {
		t.Fatal("CSR is not valid PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	// The gateway calls CheckSignature before signing, so a CSR that isn't
	// self-consistent would be rejected in production.
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify: %v", err)
	}
}

func TestPersistRenewedIdentityReplacesFilesAndPermissions(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, caPath, _ := identityPaths(dir)
	for _, p := range []string{certPath, keyPath, caPath} {
		if err := os.WriteFile(p, []byte("old"), 0600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}

	if err := persistRenewedIdentity(dir, []byte("new-cert"), []byte("new-key"), []byte("new-ca")); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	for path, want := range map[string]string{certPath: "new-cert", keyPath: "new-key", caPath: "new-ca"} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", filepath.Base(path), got, want)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		// The private key in particular must never widen to group/other
		// readable through the rename-into-place path.
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s mode = %04o, want 0600", filepath.Base(path), perm)
		}
	}

	// No temporary files may be left behind — a stray *.tmp copy of the
	// private key would be exactly the kind of thing nobody notices.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	// os.CreateTemp appends random digits, so the marker is ".tmp" anywhere
	// in the name, not a ".tmp" extension.
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("renewal left a temporary file behind: %s", e.Name())
		}
	}
}

// TestPersistRenewedIdentityLeavesOldIdentityOnFailure covers the recovery
// property the whole renewal ordering depends on: if the new identity can't
// be written, the existing one must still be intact and usable, because the
// agent will keep authenticating with it until a later attempt succeeds.
func TestPersistRenewedIdentityLeavesOldIdentityOnFailure(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, caPath, _ := identityPaths(dir)
	for _, p := range []string{certPath, keyPath, caPath} {
		if err := os.WriteFile(p, []byte("old"), 0600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}

	// A directory where the certificate file belongs makes the rename fail
	// without any way for the write itself to have partially "succeeded".
	if err := os.Remove(certPath); err != nil {
		t.Fatalf("remove cert: %v", err)
	}
	if err := os.Mkdir(certPath, 0700); err != nil {
		t.Fatalf("mkdir over cert path: %v", err)
	}

	if err := persistRenewedIdentity(dir, []byte("new-cert"), []byte("new-key"), nil); err == nil {
		t.Fatal("expected persistRenewedIdentity to fail when the certificate cannot be written")
	}

	// The key must not have been replaced by a key whose certificate never
	// landed — that mismatch is unrecoverable without re-registration.
	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(got) != "old" {
		t.Fatalf("key = %q after a failed renewal, want the original", got)
	}
}
