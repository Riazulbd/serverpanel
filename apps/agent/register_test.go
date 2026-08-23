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

func TestGenerateKeyAndCSRRoundTrips(t *testing.T) {
	key, csrPEM, err := generateKeyAndCSR("srv_test")
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
	}
	if key == nil {
		t.Fatal("expected a non-nil private key")
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
		t.Fatalf("CSR signature does not verify against its own key: %v", err)
	}
	if csr.Subject.CommonName != "srv_test" {
		t.Fatalf("CommonName = %q, want %q", csr.Subject.CommonName, "srv_test")
	}
}

func TestWriteIdentityFilesIsAtomicAndOverwrites(t *testing.T) {
	dir := t.TempDir()
	if err := writeIdentityFiles(dir, []byte("cert-v1"), []byte("key-v1")); err != nil {
		t.Fatalf("writeIdentityFiles: %v", err)
	}
	certPath, keyPath, _, _ := identityPaths(dir)
	certBytes, err := os.ReadFile(certPath)
	if err != nil || string(certBytes) != "cert-v1" {
		t.Fatalf("cert = %q, %v, want cert-v1", certBytes, err)
	}

	if err := writeIdentityFiles(dir, []byte("cert-v2"), []byte("key-v2")); err != nil {
		t.Fatalf("writeIdentityFiles (overwrite): %v", err)
	}
	certBytes, err = os.ReadFile(certPath)
	if err != nil || string(certBytes) != "cert-v2" {
		t.Fatalf("cert after overwrite = %q, %v, want cert-v2", certBytes, err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil || string(keyBytes) != "key-v2" {
		t.Fatalf("key after overwrite = %q, %v, want key-v2", keyBytes, err)
	}

	// No leftover .tmp files from the atomic write-then-rename.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover temp file after atomicWriteFile: %s", e.Name())
		}
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"far from expiry", now.Add(30 * 24 * time.Hour), false},
		{"just outside the renewal window", now.Add(certRenewalWindow + time.Minute), false},
		{"just inside the renewal window", now.Add(certRenewalWindow - time.Minute), true},
		{"already expired", now.Add(-time.Hour), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := needsRenewal(c.notAfter, now); got != c.want {
				t.Fatalf("needsRenewal(%s from now) = %v, want %v", c.notAfter.Sub(now), got, c.want)
			}
		})
	}
}

func TestCertExpiryParsesNotAfter(t *testing.T) {
	// Build a minimal self-signed cert with a known NotAfter using the same
	// key/CSR machinery as generateKeyAndCSR, then self-sign it directly
	// with x509.CreateCertificate so this test has no dependency on the
	// control plane's CA.
	key, _, err := generateKeyAndCSR("srv_test")
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
	}
	notAfter := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	got, err := certExpiry(certPEM)
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if !got.Equal(notAfter) {
		t.Fatalf("certExpiry = %s, want %s", got, notAfter)
	}
}

func TestCertExpiryRejectsInvalidPEM(t *testing.T) {
	if _, err := certExpiry([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM")
	}
}
