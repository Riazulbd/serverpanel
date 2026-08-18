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

// selfSignedCertPEM builds a minimal self-signed certificate valid from now
// until notAfter, for exercising certNotAfter without depending on the
// control plane's CA package (agent and control plane are separate modules
// under the same repo but this keeps the agent's own tests self-contained).
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

func TestCertNotAfterParsesRealExpiry(t *testing.T) {
	want := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	certPEM := selfSignedCertPEM(t, want)

	got, err := certNotAfter(certPEM)
	if err != nil {
		t.Fatalf("certNotAfter: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("NotAfter = %s, want %s", got, want)
	}
}

func TestCertNotAfterRejectsInvalidPEM(t *testing.T) {
	if _, err := certNotAfter([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM, got nil")
	}
}

func TestRenewalDue(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"far in the future", now.Add(30 * 24 * time.Hour), false},
		{"just outside the window", now.Add(renewalWindow + time.Hour), false},
		{"just inside the window", now.Add(renewalWindow - time.Hour), true},
		{"already expired", now.Add(-time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renewalDue(tc.notAfter, now); got != tc.want {
				t.Fatalf("renewalDue(%s) = %v, want %v", tc.notAfter, got, tc.want)
			}
		})
	}
}

func TestWriteFileAtomicReplacesExistingContentCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.pem")

	if err := writeFileAtomic(path, []byte("first"), 0600); err != nil {
		t.Fatalf("writeFileAtomic (first write): %v", err)
	}
	if err := writeFileAtomic(path, []byte("second, and longer"), 0600); err != nil {
		t.Fatalf("writeFileAtomic (second write): %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "second, and longer" {
		t.Fatalf("file content = %q, want %q", got, "second, and longer")
	}

	// No leftover temp files should remain in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory has %d entries after atomic writes, want 1 (leftover temp file?): %v", len(entries), entries)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file mode = %v, want 0600", info.Mode().Perm())
	}
}
