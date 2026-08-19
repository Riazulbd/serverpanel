package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// testKeyAndCSR generates a throwaway ECDSA keypair and its PEM-encoded
// CSR, mirroring what the real agent does in apps/agent/register.go (kept
// independent here since that's a separate `package main` and can't be
// imported from this package's tests).
func testKeyAndCSR(t *testing.T) (keyPEM, csrPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test-agent"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return keyPEM, csrPEM
}

// reserveAddr grabs an OS-assigned loopback port and immediately frees it,
// so the caller has a concrete address to hand to gw.listenAndServe (which
// takes an address to bind, not a pre-made listener).
func reserveAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// closeAndSettle closes a test agent connection and gives the gateway's
// per-connection goroutine a moment to run its disconnect handling
// (session cleanup, audit log) before the test's own store/db teardown
// runs — otherwise that goroutine can still be mid-flight when t.Cleanup
// closes the underlying database, logging a harmless but noisy
// "database is closed" error.
func closeAndSettle(conn *tls.Conn) {
	conn.Close()
	time.Sleep(50 * time.Millisecond)
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("gateway did not start listening on %s in time", addr)
}

// dialTestAgent performs a real mTLS handshake against a live gateway
// listener and completes the same Hello/Ack exchange
// apps/agent/connect.go's runConnection does before entering its main
// loop, so this test exercises the exact wire behavior a real agent would.
func dialTestAgent(t *testing.T, ca *agentCA, addr, serverID string, certPEM, keyPEM []byte) (*tls.Conn, *json.Encoder, *json.Decoder) {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.rootCert)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13}

	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(bufio.NewReader(conn))
	if err := enc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: serverID, AgentVersion: "test"}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("expected ack, got %q", ack.Type)
	}
	return conn, enc, dec
}

// TestRenewOverGatewayIssuesFreshCertBoundToSameServerID is a real,
// end-to-end exercise of the certificate-renewal protocol: a real mTLS
// connection, a real proto.MsgRenew request, and a real signed certificate
// back — matching exactly what apps/agent/connect.go's renewal loop does,
// short of running the actual agent binary.
func TestRenewOverGatewayIssuesFreshCertBoundToSameServerID(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	serverID, _, err := st.createServer("renew-test", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	initialKeyPEM, initialCSRPEM := testKeyAndCSR(t)
	initialCertPEM, initialSerial, err := ca.signAgentCSR(initialCSRPEM, serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("sign initial cert: %v", err)
	}
	st.markIssuedCert(serverID, initialSerial.String())

	addr := reserveAddr(t)
	go gw.listenAndServe(addr)
	waitForListener(t, addr)

	conn, enc, dec := dialTestAgent(t, ca, addr, serverID, initialCertPEM, initialKeyPEM)
	defer closeAndSettle(conn)

	_, renewCSRPEM := testKeyAndCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenew, Renew: &proto.RenewRequest{CSRPEM: string(renewCSRPEM)}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}

	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode renew result: %v", err)
	}
	if resp.Type != proto.MsgRenewResult || resp.RenewResult == nil {
		t.Fatalf("expected renew_result, got %+v", resp)
	}
	if resp.RenewResult.Error != "" {
		t.Fatalf("renewal refused: %s", resp.RenewResult.Error)
	}

	block, _ := pem.Decode([]byte(resp.RenewResult.CertPEM))
	if block == nil {
		t.Fatal("renewed cert is not valid PEM")
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (must bind to the connection's identity, not the CSR's)", newCert.Subject.CommonName, serverID)
	}
	if initialSerial.Cmp(newCert.SerialNumber) == 0 {
		t.Fatal("renewed cert should have a fresh serial, not reuse the original's")
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server should still exist after renewal")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("store cert_serial = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}
}

// TestRenewCannotClaimAnotherServersIdentity proves the CSR's own Subject
// is never trusted: the renewed certificate is always bound to the server
// ID of the already-authenticated connection it was requested over,
// regardless of what CommonName the CSR asks for.
func TestRenewCannotClaimAnotherServersIdentity(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	serverID, _, err := st.createServer("renew-identity-test", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	initialKeyPEM, initialCSRPEM := testKeyAndCSR(t)
	initialCertPEM, initialSerial, err := ca.signAgentCSR(initialCSRPEM, serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("sign initial cert: %v", err)
	}
	st.markIssuedCert(serverID, initialSerial.String())

	addr := reserveAddr(t)
	go gw.listenAndServe(addr)
	waitForListener(t, addr)

	conn, enc, dec := dialTestAgent(t, ca, addr, serverID, initialCertPEM, initialKeyPEM)
	defer closeAndSettle(conn)

	// A CSR whose own requested subject claims to be a totally different
	// server — the gateway must ignore this and bind to serverID anyway.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "someone-elses-server"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	maliciousCSRPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenew, Renew: &proto.RenewRequest{CSRPEM: string(maliciousCSRPEM)}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}
	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode renew result: %v", err)
	}
	if resp.RenewResult == nil || resp.RenewResult.Error != "" {
		t.Fatalf("expected a successful renewal, got %+v", resp.RenewResult)
	}
	block, _ := pem.Decode([]byte(resp.RenewResult.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if cert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q — the CSR's claimed subject must never be trusted", cert.Subject.CommonName, serverID)
	}
}
