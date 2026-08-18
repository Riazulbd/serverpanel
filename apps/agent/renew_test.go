package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// selfSignedCert returns a PEM-encoded, self-signed certificate expiring in
// notAfter, purely to exercise certExpiry/renewIfDue's expiry math — no
// relation to the real agent CA (packages/proto callers never need one for
// these unit tests).
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

func TestCertExpiry(t *testing.T) {
	want := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	got, err := certExpiry(selfSignedCert(t, want))
	if err != nil {
		t.Fatalf("certExpiry: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("certExpiry = %s, want %s", got, want)
	}

	if _, err := certExpiry([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM, got none")
	}
}

// fakeEncoder records every envelope passed to Encode, standing in for the
// live TLS connection's *json.Encoder in tests.
type fakeEncoder struct {
	sent []proto.Envelope
	err  error
}

func (f *fakeEncoder) Encode(v any) error {
	if f.err != nil {
		return f.err
	}
	env, ok := v.(proto.Envelope)
	if !ok {
		return errors.New("unexpected value type")
	}
	f.sent = append(f.sent, env)
	return nil
}

// loopbackConn returns one side of an in-memory net.Conn pair, good enough
// to verify renewIfDue's success path actually calls Close() on it.
func loopbackConn(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { b.Close() })
	return a
}

func TestRenewIfDueSkipsWhenFarFromExpiry(t *testing.T) {
	id := &identity{ServerID: "srv-1", CertPEM: selfSignedCert(t, time.Now().Add(30*24*time.Hour))}
	enc := &fakeEncoder{}
	conn := loopbackConn(t)

	renewIfDue(context.Background(), t.TempDir(), id, enc, make(chan proto.RenewResponse), conn)

	if len(enc.sent) != 0 {
		t.Fatalf("expected no renewal request when cert is far from expiry, got %d envelope(s)", len(enc.sent))
	}
}

func TestRenewIfDueRequestsAndPersistsOnSuccess(t *testing.T) {
	dataDir := t.TempDir()
	// identityPaths expects these files to already exist as the "current"
	// identity being replaced; renewal only needs cert/key writable.
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	origCert := selfSignedCert(t, time.Now().Add(24*time.Hour)) // within the 7-day threshold
	if err := os.WriteFile(certPath, origCert, 0o600); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("placeholder-key"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := os.WriteFile(caPath, []byte("placeholder-ca"), 0o600); err != nil {
		t.Fatalf("seed ca: %v", err)
	}
	if err := os.WriteFile(metaPath, []byte(`{"server_id":"srv-1","gateway_addr":"x"}`), 0o600); err != nil {
		t.Fatalf("seed meta: %v", err)
	}

	id := &identity{ServerID: "srv-1", CertPEM: origCert, KeyPEM: []byte("placeholder-key")}
	enc := &fakeEncoder{}
	conn := loopbackConn(t)

	newCert := selfSignedCert(t, time.Now().Add(30*24*time.Hour))
	resultCh := make(chan proto.RenewResponse, 1)
	resultCh <- proto.RenewResponse{CertPEM: string(newCert)}

	renewIfDue(context.Background(), dataDir, id, enc, resultCh, conn)

	if len(enc.sent) != 1 || enc.sent[0].Type != proto.MsgRenewRequest {
		t.Fatalf("expected exactly one renew_request envelope, got %+v", enc.sent)
	}
	if id.CertPEM == nil || string(id.CertPEM) != string(newCert) {
		t.Fatal("in-memory identity was not updated with the renewed certificate")
	}
	if len(id.KeyPEM) == 0 {
		t.Fatal("in-memory identity was not updated with the new private key")
	}

	onDiskCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read renewed cert from disk: %v", err)
	}
	if string(onDiskCert) != string(newCert) {
		t.Fatal("renewed certificate was not persisted to disk")
	}
	onDiskKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read renewed key from disk: %v", err)
	}
	if string(onDiskKey) == "placeholder-key" {
		t.Fatal("renewed private key was not persisted to disk")
	}

	// A successful renewal must close the connection so the caller's read
	// loop returns and the agent reconnects using the new certificate.
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected connection to be closed after a successful renewal")
	}
}

func TestRenewIfDueLeavesIdentityUntouchedOnGatewayError(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, _, _ := identityPaths(dataDir)
	origCert := selfSignedCert(t, time.Now().Add(24*time.Hour))
	os.WriteFile(certPath, origCert, 0o600)
	os.WriteFile(keyPath, []byte("placeholder-key"), 0o600)

	id := &identity{ServerID: "srv-1", CertPEM: origCert, KeyPEM: []byte("placeholder-key")}
	enc := &fakeEncoder{}
	conn := loopbackConn(t)

	resultCh := make(chan proto.RenewResponse, 1)
	resultCh <- proto.RenewResponse{Error: "server not found"}

	renewIfDue(context.Background(), dataDir, id, enc, resultCh, conn)

	if string(id.CertPEM) != string(origCert) {
		t.Fatal("identity must not change when the gateway rejects renewal")
	}
	onDiskCert, _ := os.ReadFile(certPath)
	if string(onDiskCert) != string(origCert) {
		t.Fatal("on-disk cert must not change when the gateway rejects renewal")
	}
}

func TestAtomicWriteFileReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.pem")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := atomicWriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("file contents = %q, want %q", got, "new")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file was not cleaned up by rename")
	}
}
