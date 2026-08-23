package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyAndCSRProducesValidSignedCSR(t *testing.T) {
	key, csrPEM, err := generateKeyAndCSR("pending-renewal")
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected a CERTIFICATE REQUEST PEM block, got %+v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if key == nil {
		t.Fatal("returned key is nil")
	}
	if !key.PublicKey.Equal(csr.PublicKey) {
		t.Fatal("CSR public key does not match the returned private key's public key")
	}
}

func TestWriteFileAtomicReplacesExistingFileCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.pem")

	if err := writeFileAtomic(path, []byte("first"), 0600); err != nil {
		t.Fatalf("writeFileAtomic (first): %v", err)
	}
	if err := writeFileAtomic(path, []byte("second"), 0600); err != nil {
		t.Fatalf("writeFileAtomic (second): %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("file content = %q, want %q", got, "second")
	}

	// No leftover .tmp file.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no leftover temp file, stat err = %v", err)
	}
}
