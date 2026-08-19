package main

import (
	"context"
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
	"path/filepath"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

func TestShouldRenew(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"far in the future", now.Add(30 * 24 * time.Hour), false},
		{"just outside window", now.Add(renewalWindow + time.Minute), false},
		{"just inside window", now.Add(renewalWindow - time.Minute), true},
		{"already expired", now.Add(-time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRenew(now, tc.notAfter, renewalWindow); got != tc.want {
				t.Errorf("shouldRenew(now, %s, %s) = %v, want %v", tc.notAfter, renewalWindow, got, tc.want)
			}
		})
	}
}

// selfSignedCertPEM builds a minimal self-signed certificate with the given
// expiry, standing in for a CA-issued one purely for exercising
// certNotAfter/persistRenewedCert without depending on the control-plane
// package (a separate `main` package that can't be imported here).
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

func TestCertNotAfterParsesExpiry(t *testing.T) {
	want := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	certPEM := selfSignedCertPEM(t, want)

	got, err := certNotAfter(certPEM)
	if err != nil {
		t.Fatalf("certNotAfter: %v", err)
	}
	if !got.Truncate(time.Second).Equal(want) {
		t.Fatalf("certNotAfter = %s, want %s", got, want)
	}
}

func TestCertNotAfterRejectsGarbage(t *testing.T) {
	if _, err := certNotAfter([]byte("not a cert")); err == nil {
		t.Fatal("expected an error for invalid PEM")
	}
}

// TestPersistRenewedCertIsAtomicAndUpdatesIdentity writes an initial
// identity to disk (mirroring what register() produces), then persists a
// renewal on top of it, and verifies both the in-memory *identity and a
// fresh loadIdentity() from disk reflect the new certificate — the whole
// point of persisting is that a reconnect after this point uses the new
// cert, not the old one.
func TestPersistRenewedCertIsAtomicAndUpdatesIdentity(t *testing.T) {
	dataDir := t.TempDir()
	initialCert := selfSignedCertPEM(t, time.Now().Add(24*time.Hour))
	initialKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	initialKeyDER, err := x509.MarshalECPrivateKey(initialKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	initialKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: initialKeyDER})

	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	if err := os.WriteFile(certPath, initialCert, 0600); err != nil {
		t.Fatalf("write initial cert: %v", err)
	}
	if err := os.WriteFile(keyPath, initialKeyPEM, 0600); err != nil {
		t.Fatalf("write initial key: %v", err)
	}
	if err := os.WriteFile(caPath, []byte("dummy-ca"), 0600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	metaBytes, _ := json.Marshal(map[string]string{"server_id": "srv_test", "gateway_addr": "127.0.0.1:1234"})
	if err := os.WriteFile(metaPath, metaBytes, 0600); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	id, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}

	newCert := selfSignedCertPEM(t, time.Now().Add(30*24*time.Hour))
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate renewal key: %v", err)
	}

	if err := persistRenewedCert(dataDir, id, newKey, newCert); err != nil {
		t.Fatalf("persistRenewedCert: %v", err)
	}

	if string(id.CertPEM) != string(newCert) {
		t.Fatal("in-memory identity.CertPEM was not updated to the renewed cert")
	}

	reloaded, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity after renewal: %v", err)
	}
	if string(reloaded.CertPEM) != string(newCert) {
		t.Fatal("cert on disk was not updated to the renewed cert")
	}
	// The renewal must persist the *new* private key paired with the new
	// cert, not silently keep the old one around.
	newKeyDER, _ := x509.MarshalECPrivateKey(newKey)
	wantKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: newKeyDER})
	if string(reloaded.KeyPEM) != string(wantKeyPEM) {
		t.Fatal("key on disk was not updated to the renewed key")
	}

	// No leftover .tmp files from the atomic write.
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover temp file after atomic write: %s", e.Name())
		}
	}
}

// TestAttemptRenewalRoundTrip exercises the agent's wire-level side of
// renewal against a fake gateway peer over a real net.Conn (net.Pipe),
// mirroring apps/controlplane's TestHandleRenewCertIssuesFreshCertAndUpdatesStore
// from the other end of the same protocol.
func TestAttemptRenewalRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	initialCert := selfSignedCertPEM(t, time.Now().Add(time.Hour))
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	os.WriteFile(certPath, initialCert, 0600)
	os.WriteFile(keyPath, []byte("dummy-key"), 0600)
	os.WriteFile(caPath, []byte("dummy-ca"), 0600)
	metaBytes, _ := json.Marshal(map[string]string{"server_id": "srv_test", "gateway_addr": "127.0.0.1:1234"})
	os.WriteFile(metaPath, metaBytes, 0600)

	id, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}

	serverConn, agentConn := net.Pipe()
	defer serverConn.Close()
	defer agentConn.Close()

	w := &safeEncoder{enc: json.NewEncoder(agentConn)}
	results := make(chan proto.RenewCertResult, 1)

	newCert := selfSignedCertPEM(t, time.Now().Add(30*24*time.Hour))

	// Fake gateway: read the renewal request, hand back a fresh cert.
	go func() {
		dec := json.NewDecoder(serverConn)
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return
		}
		if env.Type != proto.MsgRenewCert || env.RenewCert == nil || env.RenewCert.CSRPEM == "" {
			return
		}
		resp := proto.Envelope{Type: proto.MsgRenewCertResult, RenewCertResult: &proto.RenewCertResult{Ok: true, CertPEM: string(newCert)}}
		json.NewEncoder(serverConn).Encode(resp)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// attemptRenewal writes the request on agentConn and blocks on results;
	// we need a reader pulling the fake gateway's response off agentConn
	// and into results, since attemptRenewal itself only writes.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		dec := json.NewDecoder(agentConn)
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return
		}
		if env.Type == proto.MsgRenewCertResult && env.RenewCertResult != nil {
			results <- *env.RenewCertResult
		}
	}()

	if err := attemptRenewal(ctx, w, dataDir, id, results); err != nil {
		t.Fatalf("attemptRenewal: %v", err)
	}
	<-readerDone

	if string(id.CertPEM) != string(newCert) {
		t.Fatal("attemptRenewal did not persist the renewed certificate into identity")
	}
	reloaded, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if string(reloaded.CertPEM) != string(newCert) {
		t.Fatal("attemptRenewal did not persist the renewed certificate to disk")
	}
}

func TestAttemptRenewalSurfacesGatewayDecline(t *testing.T) {
	dataDir := t.TempDir()
	initialCert := selfSignedCertPEM(t, time.Now().Add(time.Hour))
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	os.WriteFile(certPath, initialCert, 0600)
	os.WriteFile(keyPath, []byte("dummy-key"), 0600)
	os.WriteFile(caPath, []byte("dummy-ca"), 0600)
	metaBytes, _ := json.Marshal(map[string]string{"server_id": "srv_test", "gateway_addr": "127.0.0.1:1234"})
	os.WriteFile(metaPath, metaBytes, 0600)

	id, err := loadIdentity(dataDir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}

	serverConn, agentConn := net.Pipe()
	defer serverConn.Close()
	defer agentConn.Close()
	w := &safeEncoder{enc: json.NewEncoder(agentConn)}
	results := make(chan proto.RenewCertResult, 1)

	go func() {
		dec := json.NewDecoder(serverConn)
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return
		}
		json.NewEncoder(serverConn).Encode(proto.Envelope{Type: proto.MsgRenewCertResult, RenewCertResult: &proto.RenewCertResult{Ok: false, Error: "server no longer registered"}})
	}()

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		dec := json.NewDecoder(agentConn)
		var env proto.Envelope
		if err := dec.Decode(&env); err != nil {
			return
		}
		if env.RenewCertResult != nil {
			results <- *env.RenewCertResult
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	preRenewalCert := string(id.CertPEM)
	if err := attemptRenewal(ctx, w, dataDir, id, results); err == nil {
		t.Fatal("expected attemptRenewal to return an error on gateway decline")
	}
	<-readerDone

	if string(id.CertPEM) != preRenewalCert {
		t.Fatal("identity must be left untouched when the gateway declines renewal")
	}
}
