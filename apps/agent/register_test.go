package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestGenerateKeyAndCSRProducesAVerifiableCSR(t *testing.T) {
	csrPEM, keyPEM, err := generateKeyAndCSR()
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
	}

	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		t.Fatal("CSR is not valid PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify against its own public key: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("key is not valid PEM")
	}
	if _, err := x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("returned key PEM does not parse as an EC private key: %v", err)
	}
}

func TestPersistRenewedCertReplacesOnDiskFilesAtomically(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)

	if err := os.WriteFile(certPath, []byte("original-cert"), 0600); err != nil {
		t.Fatalf("seed cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("original-key"), 0600); err != nil {
		t.Fatalf("seed key file: %v", err)
	}
	if err := os.WriteFile(caPath, []byte("ca"), 0600); err != nil {
		t.Fatalf("seed ca file: %v", err)
	}
	if err := os.WriteFile(metaPath, []byte(`{"server_id":"srv_1","gateway_addr":"127.0.0.1:8843"}`), 0600); err != nil {
		t.Fatalf("seed meta file: %v", err)
	}

	id := &identity{DataDir: dataDir}
	if err := id.persistRenewedCert([]byte("renewed-cert"), []byte("renewed-key")); err != nil {
		t.Fatalf("persistRenewedCert: %v", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert after renewal: %v", err)
	}
	if string(gotCert) != "renewed-cert" {
		t.Fatalf("cert on disk = %q, want %q", gotCert, "renewed-cert")
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key after renewal: %v", err)
	}
	if string(gotKey) != "renewed-key" {
		t.Fatalf("key on disk = %q, want %q", gotKey, "renewed-key")
	}

	// No leftover .tmp files from the atomic write-then-rename.
	if _, err := os.Stat(certPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no leftover temp cert file, stat err = %v", err)
	}
	if _, err := os.Stat(keyPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no leftover temp key file, stat err = %v", err)
	}

	// loadIdentity should now see the renewed cert/key and still have the
	// untouched ca/meta content.
	reloaded, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity after renewal: %v", err)
	}
	if string(reloaded.CertPEM) != "renewed-cert" || string(reloaded.KeyPEM) != "renewed-key" {
		t.Fatalf("loadIdentity returned stale cert/key: cert=%q key=%q", reloaded.CertPEM, reloaded.KeyPEM)
	}
	if reloaded.ServerID != "srv_1" {
		t.Fatalf("loadIdentity ServerID = %q, want %q (meta file should be untouched by a cert-only renewal)", reloaded.ServerID, "srv_1")
	}
}

// TestIdentityCertAccessorsAreRaceSafe is a regression test for a data race
// found during development of certificate renewal: renewalLoop reads the
// identity's current certificate every tick on its own goroutine while
// runConnection's read loop can concurrently overwrite it after a
// successful renewal. Both must go through currentCert/setCert, never the
// CertPEM/KeyPEM fields directly, for exactly this reason. Run with
// `go test -race` to make the point — without the certMu-guarded
// accessors, this test reliably trips the race detector.
func TestIdentityCertAccessorsAreRaceSafe(t *testing.T) {
	id := &identity{CertPEM: []byte("initial-cert"), KeyPEM: []byte("initial-key")}

	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-stop:
				return
			default:
				id.setCert([]byte("renewed-cert"), []byte("renewed-key"))
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		_, _ = id.currentCert()
	}

	close(stop)
	<-writerDone
}
