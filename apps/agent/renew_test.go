package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// selfSignedCertPEM builds a minimal self-signed certificate valid until
// notAfter — enough for certExpiry/maybeRequestRenewal to exercise real PEM
// parsing without needing the control plane's CA.
func selfSignedCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return certForPublicKeyPEM(t, &key.PublicKey, key, notAfter)
}

// certForPublicKeyPEM issues a certificate binding subjectPub (the public
// key half of whatever private key a caller wants the result to pair
// with), signed by signer — used to build a "renewed" certificate that
// actually matches certRenewer's pendingKey, the way a real CA response
// would, rather than an unrelated self-signed cert.
func certForPublicKeyPEM(t *testing.T, subjectPub *ecdsa.PublicKey, signer *ecdsa.PrivateKey, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, subjectPub, signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertExpiryParsesNotAfter(t *testing.T) {
	want := time.Now().Add(10 * 24 * time.Hour).Truncate(time.Second)
	got, err := certExpiry(selfSignedCertPEM(t, want))
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if !got.Truncate(time.Second).Equal(want) {
		t.Fatalf("certExpiry = %s, want %s", got, want)
	}
}

func TestCertExpiryRejectsInvalidPEM(t *testing.T) {
	if _, err := certExpiry([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM")
	}
}

func TestMaybeRequestRenewalSkipsWhenFarFromExpiry(t *testing.T) {
	id := &identity{CertPEM: selfSignedCertPEM(t, time.Now().Add(29*24*time.Hour))}
	r := &certRenewer{}
	sent := false
	r.maybeRequestRenewal(id, func(string) error { sent = true; return nil })
	if sent {
		t.Fatal("expected no renewal request when the certificate isn't close to expiring")
	}
}

func TestMaybeRequestRenewalSendsWhenNearExpiry(t *testing.T) {
	id := &identity{CertPEM: selfSignedCertPEM(t, time.Now().Add(2*24*time.Hour))}
	r := &certRenewer{}
	var gotCSR string
	sent := 0
	r.maybeRequestRenewal(id, func(csrPEM string) error {
		sent++
		gotCSR = csrPEM
		return nil
	})
	if sent != 1 {
		t.Fatalf("expected exactly one renewal request, got %d", sent)
	}
	if gotCSR == "" {
		t.Fatal("expected a non-empty CSR to be sent")
	}
	r.mu.Lock()
	pending := r.pendingKey
	r.mu.Unlock()
	if pending == nil {
		t.Fatal("expected a pending key to be recorded after sending a renewal request")
	}
}

func TestMaybeRequestRenewalDoesNotResendWhilePending(t *testing.T) {
	id := &identity{CertPEM: selfSignedCertPEM(t, time.Now().Add(2*24*time.Hour))}
	r := &certRenewer{}
	sent := 0
	send := func(string) error { sent++; return nil }

	r.maybeRequestRenewal(id, send)
	r.maybeRequestRenewal(id, send) // still pending, within renewRetryInterval — must not resend

	if sent != 1 {
		t.Fatalf("expected exactly one renewal request while one is still pending, got %d", sent)
	}
}

func TestHandleRenewResultWithNoPendingRequestIsANoOp(t *testing.T) {
	dataDir := t.TempDir()
	original := selfSignedCertPEM(t, time.Now().Add(29*24*time.Hour))
	id := &identity{CertPEM: original, KeyPEM: []byte("original-key")}
	r := &certRenewer{}

	r.handleRenewResult(id, dataDir, proto.RenewCertResult{CertPEM: "should be ignored"})

	if string(id.CertPEM) != string(original) {
		t.Fatal("expected id.CertPEM to be unchanged when no renewal was pending")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "agent-cert.pem")); !os.IsNotExist(err) {
		t.Fatal("expected no certificate file to be written when no renewal was pending")
	}
}

func TestHandleRenewResultWithErrorClearsPendingWithoutPersisting(t *testing.T) {
	dataDir := t.TempDir()
	original := selfSignedCertPEM(t, time.Now().Add(2*24*time.Hour))
	id := &identity{CertPEM: original, KeyPEM: []byte("original-key")}
	r := &certRenewer{}

	r.maybeRequestRenewal(id, func(string) error { return nil })
	r.mu.Lock()
	hadPending := r.pendingKey != nil
	r.mu.Unlock()
	if !hadPending {
		t.Fatal("test setup: expected a pending key before handling the error result")
	}

	r.handleRenewResult(id, dataDir, proto.RenewCertResult{Error: "gateway declined"})

	r.mu.Lock()
	stillPending := r.pendingKey != nil
	r.mu.Unlock()
	if stillPending {
		t.Fatal("expected the pending key to be cleared after an error result")
	}
	if string(id.CertPEM) != string(original) {
		t.Fatal("expected id.CertPEM to be unchanged after a renewal error")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "agent-cert.pem")); !os.IsNotExist(err) {
		t.Fatal("expected no certificate file to be written after a renewal error")
	}
}

func TestHandleRenewResultSuccessPersistsAndUpdatesIdentity(t *testing.T) {
	dataDir := t.TempDir()
	original := selfSignedCertPEM(t, time.Now().Add(2*24*time.Hour))
	id := &identity{CertPEM: original, KeyPEM: []byte("original-key"), ServerID: "srv_test", GatewayAddr: "gw:1"}
	r := &certRenewer{}

	r.maybeRequestRenewal(id, func(string) error { return nil })

	r.mu.Lock()
	pendingKey := r.pendingKey
	r.mu.Unlock()
	if pendingKey == nil {
		t.Fatal("test setup: expected a pending key after maybeRequestRenewal")
	}
	// A real gateway response's certificate is signed against the CSR's own
	// public key (see ca.go signAgentCSR / gateway_test.go), so build the
	// test's "renewed" cert the same way — bound to pendingKey's public
	// key — rather than an unrelated self-signed cert, so the
	// tls.X509KeyPair check below is meaningful.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate throwaway signer key: %v", err)
	}
	newCertPEM := certForPublicKeyPEM(t, &pendingKey.PublicKey, caKey, time.Now().Add(30*24*time.Hour))
	r.handleRenewResult(id, dataDir, proto.RenewCertResult{CertPEM: string(newCertPEM)})

	if string(id.CertPEM) != string(newCertPEM) {
		t.Fatal("expected id.CertPEM to be updated to the renewed certificate")
	}
	if len(id.KeyPEM) == 0 || string(id.KeyPEM) == "original-key" {
		t.Fatal("expected id.KeyPEM to be updated to the new key that matches the renewed certificate")
	}
	// The new key must actually pair with the new certificate.
	if _, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM); err != nil {
		t.Fatalf("renewed cert/key do not form a valid pair: %v", err)
	}

	certOnDisk, err := os.ReadFile(filepath.Join(dataDir, "agent-cert.pem"))
	if err != nil {
		t.Fatalf("read persisted cert: %v", err)
	}
	if string(certOnDisk) != string(newCertPEM) {
		t.Fatal("persisted certificate on disk does not match the renewed certificate")
	}
	keyOnDisk, err := os.ReadFile(filepath.Join(dataDir, "agent-key.pem"))
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	if string(keyOnDisk) != string(id.KeyPEM) {
		t.Fatal("persisted key on disk does not match id.KeyPEM")
	}

	// ServerID/GatewayAddr must be left untouched by a renewal — only the
	// certificate/key rotate.
	if id.ServerID != "srv_test" || id.GatewayAddr != "gw:1" {
		t.Fatalf("renewal must not change ServerID/GatewayAddr, got %+v", id)
	}
}
