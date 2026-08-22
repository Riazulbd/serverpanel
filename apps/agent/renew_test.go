package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// selfSignedCert builds a minimal self-signed client certificate with the
// given NotAfter, standing in for what the control plane's CA would issue —
// only the NotAfter field matters to the code under test here.
func selfSignedCert(t *testing.T, notAfter time.Time) []byte {
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

func TestCertNotAfterParsesCertificate(t *testing.T) {
	want := time.Now().Add(11 * 24 * time.Hour).Truncate(time.Second)
	got, err := certNotAfter(selfSignedCert(t, want))
	if err != nil {
		t.Fatalf("certNotAfter: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("certNotAfter = %v, want %v", got, want)
	}
}

func TestCertNotAfterRejectsInvalidPEM(t *testing.T) {
	if _, err := certNotAfter([]byte("not a certificate")); err == nil {
		t.Fatal("expected an error for invalid PEM")
	}
}

// pipeEncoder returns a *json.Encoder writing into one end of an in-memory
// pipe and a decode function to read the other end, so maybeRenew's
// behavior (does it send a renew_request or not) can be observed without a
// real network connection.
func pipeEncoder(t *testing.T) (*json.Encoder, func() (proto.Envelope, error)) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	dec := json.NewDecoder(server)
	return json.NewEncoder(client), func() (proto.Envelope, error) {
		var env proto.Envelope
		err := dec.Decode(&env)
		return env, err
	}
}

func TestMaybeRenewSkipsWhenFarFromExpiry(t *testing.T) {
	id := &identity{ServerID: "srv_test", CertPEM: selfSignedCert(t, time.Now().Add(30*24*time.Hour))}
	enc, recv := pipeEncoder(t)
	pending := &pendingRenewal{}

	done := make(chan struct{})
	go func() {
		maybeRenew(enc, id, 7*24*time.Hour, pending)
		close(done)
	}()
	<-done

	// Nothing should have been sent; prove it by racing a short timeout
	// against a read that should never complete.
	resultCh := make(chan error, 1)
	go func() { _, err := recv(); resultCh <- err }()
	select {
	case <-resultCh:
		t.Fatal("maybeRenew sent a message when the cert was nowhere near expiry")
	case <-time.After(50 * time.Millisecond):
	}
	if pending.inFlight() {
		t.Fatal("no renewal should be marked in-flight when none was sent")
	}
}

func TestMaybeRenewSendsRequestWhenNearExpiry(t *testing.T) {
	id := &identity{ServerID: "srv_test", CertPEM: selfSignedCert(t, time.Now().Add(2*24*time.Hour))}
	enc, recv := pipeEncoder(t)
	pending := &pendingRenewal{}

	go maybeRenew(enc, id, 7*24*time.Hour, pending)

	env, err := recv()
	if err != nil {
		t.Fatalf("expected a renew_request, got error: %v", err)
	}
	if env.Type != proto.MsgRenewRequest || env.RenewRequest == nil || env.RenewRequest.CSRPEM == "" {
		t.Fatalf("got %+v, want a populated renew_request", env)
	}
	if !pending.inFlight() {
		t.Fatal("expected a renewal to be marked in-flight after sending the request")
	}
}

func TestMaybeRenewDoesNotDoubleSendWhileInFlight(t *testing.T) {
	id := &identity{ServerID: "srv_test", CertPEM: selfSignedCert(t, time.Now().Add(2*24*time.Hour))}
	enc, recv := pipeEncoder(t)
	pending := &pendingRenewal{}

	go maybeRenew(enc, id, 7*24*time.Hour, pending)
	if _, err := recv(); err != nil {
		t.Fatalf("first renew_request: %v", err)
	}

	// A second check while the first is still awaiting a response must not
	// fire another request (that would leak the first request's key and
	// desync pendingRenewal.take()'s single-slot bookkeeping).
	maybeRenew(enc, id, 7*24*time.Hour, pending)

	resultCh := make(chan error, 1)
	go func() { _, err := recv(); resultCh <- err }()
	select {
	case <-resultCh:
		t.Fatal("maybeRenew sent a second request while one was still in flight")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPersistRenewedIdentityWritesFilesAndUpdatesInMemoryIdentity(t *testing.T) {
	dataDir := t.TempDir()
	// Seed the on-disk identity the way register() would.
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	if err := os.WriteFile(certPath, []byte("old-cert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte("ca"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, []byte(`{"server_id":"srv_test"}`), 0600); err != nil {
		t.Fatal(err)
	}

	id := &identity{ServerID: "srv_test", CertPEM: []byte("old-cert"), KeyPEM: []byte("old-key")}
	newCert, newKey := []byte("new-cert"), []byte("new-key")

	if err := persistRenewedIdentity(dataDir, id, newCert, newKey); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	if !bytes.Equal(id.CertPEM, newCert) || !bytes.Equal(id.KeyPEM, newKey) {
		t.Fatal("in-memory identity was not updated to the renewed cert/key")
	}
	onDiskCert, err := os.ReadFile(certPath)
	if err != nil || !bytes.Equal(onDiskCert, newCert) {
		t.Fatalf("on-disk cert = %q, err=%v, want %q", onDiskCert, err, newCert)
	}
	onDiskKey, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(onDiskKey, newKey) {
		t.Fatalf("on-disk key = %q, err=%v, want %q", onDiskKey, err, newKey)
	}
	// No leftover .tmp files from the atomic write.
	if _, err := os.Stat(certPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp cert file was not cleaned up by rename")
	}

	// A loadIdentity call (what the next process restart would do) must
	// also see the renewed files.
	reloaded, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity after renewal: %v", err)
	}
	if !bytes.Equal(reloaded.CertPEM, newCert) || !bytes.Equal(reloaded.KeyPEM, newKey) {
		t.Fatal("loadIdentity did not observe the renewed cert/key on disk")
	}
}

func TestHandleRenewResponseIgnoresUnsolicitedResponse(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	os.WriteFile(certPath, []byte("old-cert"), 0600)
	os.WriteFile(keyPath, []byte("old-key"), 0600)
	os.WriteFile(caPath, []byte("ca"), 0600)
	os.WriteFile(metaPath, []byte(`{"server_id":"srv_test"}`), 0600)

	id := &identity{ServerID: "srv_test", CertPEM: []byte("old-cert"), KeyPEM: []byte("old-key")}
	enc, recv := pipeEncoder(t)
	pending := &pendingRenewal{} // nothing in flight

	go handleRenewResponse(dataDir, id, enc, proto.RenewResponse{CertPEM: "should-be-ignored"}, pending)

	resultCh := make(chan error, 1)
	go func() { _, err := recv(); resultCh <- err }()
	select {
	case <-resultCh:
		t.Fatal("an unsolicited renew_response must not produce a renew_ack")
	case <-time.After(50 * time.Millisecond):
	}
	if !bytes.Equal(id.CertPEM, []byte("old-cert")) {
		t.Fatal("identity must not change from an unsolicited renew_response")
	}
}

func TestHandleRenewResponseAppliesErrorWithoutTouchingIdentity(t *testing.T) {
	dataDir := t.TempDir()
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	os.WriteFile(certPath, []byte("old-cert"), 0600)
	os.WriteFile(keyPath, []byte("old-key"), 0600)
	os.WriteFile(caPath, []byte("ca"), 0600)
	os.WriteFile(metaPath, []byte(`{"server_id":"srv_test"}`), 0600)

	id := &identity{ServerID: "srv_test", CertPEM: []byte("old-cert"), KeyPEM: []byte("old-key")}
	pending := &pendingRenewal{}
	pending.start([]byte("in-flight-key"))
	enc, recv := pipeEncoder(t)

	go handleRenewResponse(dataDir, id, enc, proto.RenewResponse{Error: "server too busy"}, pending)

	resultCh := make(chan error, 1)
	go func() { _, err := recv(); resultCh <- err }()
	select {
	case <-resultCh:
		t.Fatal("a rejected renewal must not send a renew_ack")
	case <-time.After(50 * time.Millisecond):
	}
	if !bytes.Equal(id.CertPEM, []byte("old-cert")) {
		t.Fatal("identity must be unchanged after a rejected renewal")
	}
	if pending.inFlight() {
		t.Fatal("pending renewal must be cleared even when rejected, so the next tick can retry")
	}
}
