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
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// testAgentConn drives a real mTLS connection to a gateway under test,
// mirroring apps/agent/connect.go closely enough to exercise the real wire
// protocol (not a mock) — this is what actually catches wire-format /
// concurrency bugs a pure unit test of either side in isolation would miss.
type testAgentConn struct {
	t    *testing.T
	conn *tls.Conn
	enc  *json.Encoder
	dec  *json.Decoder
}

func dialTestAgent(t *testing.T, addr string, certPEM, keyPEM, caPEM []byte) *testAgentConn {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("could not parse CA PEM")
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ac := &testAgentConn{t: t, conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(bufio.NewReader(conn))}
	if err := ac.enc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: "irrelevant-gateway-derives-identity-from-cert", AgentVersion: "test"}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	var ack proto.Envelope
	if err := ac.dec.Decode(&ack); err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("expected ack, got %q", ack.Type)
	}
	return ac
}

func generateAgentCertAndCSR(t *testing.T) (key *ecdsa.PrivateKey, csrPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// startTestGateway binds a gateway on an OS-assigned loopback port and
// serves it in the background for the duration of the test.
func startTestGateway(t *testing.T, gw *gateway) string {
	t.Helper()
	ln, err := gw.listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("gateway.listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go gw.serve(ln)
	return ln.Addr().String()
}

// TestGatewayRenewalRotatesCertAndKeepsSessionAlive drives the full renewal
// round trip over a real mTLS connection: an agent already connected with
// its original certificate asks for a fresh one, the gateway issues it and
// revokes the superseded serial, and the *existing* session — still
// authenticated under the now-revoked serial — keeps working, matching
// gateway.handleRenew's documented "don't disrupt the live session" contract.
func TestGatewayRenewalRotatesCertAndKeepsSessionAlive(t *testing.T) {
	a := newTestAPIServer(t)
	serverID, _, err := a.store.createServer("renew-test", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	addr := startTestGateway(t, a.gw)

	key, csrPEM := generateAgentCertAndCSR(t)
	certPEM, serial, err := a.ca.signAgentCSR(csrPEM, serverID, AgentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	a.store.markIssuedCert(serverID, serial.String())

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	ac := dialTestAgent(t, addr, certPEM, keyPEM, a.ca.CAPEM())

	if a.store.isRevoked(serial.String()) {
		t.Fatal("freshly issued serial must not start out revoked")
	}

	// Request renewal over the live session.
	_, renewCSR := generateAgentCertAndCSR(t)
	if err := ac.enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(renewCSR)}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}

	var resp proto.Envelope
	if err := ac.dec.Decode(&resp); err != nil {
		t.Fatalf("read renew response: %v", err)
	}
	if resp.Type != proto.MsgRenewResponse || resp.RenewResponse == nil {
		t.Fatalf("expected renew_response, got %q", resp.Type)
	}
	if resp.RenewResponse.Error != "" {
		t.Fatalf("renewal was rejected: %s", resp.RenewResponse.Error)
	}
	if resp.RenewResponse.CertPEM == "" {
		t.Fatal("renewal response carried no certificate")
	}
	if resp.RenewResponse.CertPEM == string(certPEM) {
		t.Fatal("renewed certificate must differ from the original")
	}

	// The old serial (the one this session is still authenticated with) must
	// now be revoked, per rotateCert's documented invariant.
	if !a.store.isRevoked(serial.String()) {
		t.Fatal("original serial should be revoked immediately after a successful renewal")
	}

	// The store's active serial must reflect the newly issued cert.
	block, _ := pem.Decode([]byte(resp.RenewResponse.CertPEM))
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	rec, ok := a.store.get(serverID)
	if !ok {
		t.Fatal("server record disappeared")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("store's active cert_serial = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}

	// Despite dialing under a now-revoked serial, the already-established
	// session must still be usable — revocation is checked at handshake
	// time, not per-message (see gateway.handleRenew's doc comment).
	if err := ac.enc.Encode(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{SentAt: time.Now().UTC()}}); err != nil {
		t.Fatalf("heartbeat after renewal should still succeed on the live session: %v", err)
	}
}

// TestGatewayRenewalRejectsMalformedCSR covers the failure path: a renewal
// request carrying a CSR the CA can't parse/verify (corrupt bytes, or a
// signature that doesn't validate) must produce an Error in the response —
// never a crash, and never a certificate issued off an unverifiable request.
func TestGatewayRenewalRejectsMalformedCSR(t *testing.T) {
	a := newTestAPIServer(t)
	serverID, _, err := a.store.createServer("renew-test-2", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	key, csrPEM := generateAgentCertAndCSR(t)
	certPEM, serial, err := a.ca.signAgentCSR(csrPEM, serverID, AgentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	a.store.markIssuedCert(serverID, serial.String())
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	addr := startTestGateway(t, a.gw)
	ac := dialTestAgent(t, addr, certPEM, keyPEM, a.ca.CAPEM())

	if err := ac.enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: "not a real CSR"}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}
	var resp proto.Envelope
	if err := ac.dec.Decode(&resp); err != nil {
		t.Fatalf("read renew response: %v", err)
	}
	if resp.RenewResponse == nil || resp.RenewResponse.Error == "" {
		t.Fatal("expected a renewal error for a server record that no longer exists")
	}
	if resp.RenewResponse.CertPEM != "" {
		t.Fatal("must not return a certificate alongside an error")
	}
}
