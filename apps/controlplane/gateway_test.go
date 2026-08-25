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

// testAgentCSR generates a fresh ECDSA key + CSR, matching what the real
// agent does in apps/agent/register.go and apps/agent/connect.go's
// requestCertRenewal. The CSR's requested Subject is deliberately ignored
// by signAgentCSR (it derives CommonName from the caller-supplied,
// already-validated server_id instead), so it's left as a placeholder here.
func testAgentCSR(t *testing.T) (key *ecdsa.PrivateKey, csrPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func testKeyToPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// dialAgent brings up a real mTLS connection to the gateway using the given
// client cert/key, exactly as apps/agent/connect.go does, and confirms the
// session-accepted ack the gateway sends before anything else.
func dialAgent(t *testing.T, addr string, caPEM, certPEM, keyPEM []byte) (*json.Encoder, *json.Decoder, *tls.Conn) {
	t.Helper()
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("could not parse CA PEM")
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(bufio.NewReader(conn))

	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("first message type = %q, want ack", ack.Type)
	}
	return enc, dec, conn
}

// TestGatewayCertRenewalOverRealMTLSConnection exercises the full in-band
// renewal path (proto.MsgRenewCert/MsgRenewCertResult) over a real TLS
// connection to a real gateway listener: an agent holding a still-valid
// certificate asks for a fresh one, gets it, and the store ends up tracking
// both serials so a later revocation catches both — not just the latest.
func TestGatewayCertRenewalOverRealMTLSConnection(t *testing.T) {
	a := newTestAPIServer(t)

	serverID, _, err := a.store.createServer("renew-test", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	// Simulate the initial registration (the HTTP /agents/register path
	// itself is already covered by http_test.go; this test is about what
	// happens after: renewal).
	key, csrPEM := testAgentCSR(t)
	certPEM, serial, err := a.ca.signAgentCSR(csrPEM, serverID, time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	a.store.markIssuedCert(serverID, serial.String())
	keyPEM := testKeyToPEM(t, key)

	ln, err := a.gw.newTLSListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newTLSListener: %v", err)
	}
	defer ln.Close()
	go a.gw.serve(ln)

	enc, dec, conn := dialAgent(t, ln.Addr().String(), a.ca.CAPEM(), certPEM, keyPEM)
	defer conn.Close()

	_, newCSRPEM := testAgentCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCertReq{CSRPEM: string(newCSRPEM)}}); err != nil {
		t.Fatalf("send renew_cert: %v", err)
	}

	var result proto.Envelope
	if err := dec.Decode(&result); err != nil {
		t.Fatalf("decode renew_cert_result: %v", err)
	}
	if result.Type != proto.MsgRenewCertResult || result.RenewCertResult == nil {
		t.Fatalf("expected renew_cert_result, got %+v", result)
	}
	if !result.RenewCertResult.OK {
		t.Fatalf("renewal rejected: %s", result.RenewCertResult.Error)
	}
	newSerial := result.RenewCertResult.Serial
	if newSerial == "" || newSerial == serial.String() {
		t.Fatalf("expected a distinct new serial, got %q (old was %q)", newSerial, serial.String())
	}
	if _, err := x509.ParseCertificate(mustDecodePEM(t, result.RenewCertResult.CertPEM)); err != nil {
		t.Fatalf("renewed cert_pem does not parse: %v", err)
	}

	rec, ok := a.store.get(serverID)
	if !ok {
		t.Fatal("server should still exist")
	}
	if rec.CertSerial != newSerial {
		t.Fatalf("store cert_serial = %q, want %q", rec.CertSerial, newSerial)
	}
	// A renewal must not look like a fresh registration in the server's
	// status: the gateway already flipped this to "connected" on handshake,
	// and recordCertRenewal must leave it alone.
	if rec.Status != statusConnected {
		t.Fatalf("status after renewal = %q, want %q", rec.Status, statusConnected)
	}

	if err := a.store.revokeServer(serverID, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}
	if !a.store.isRevoked(serial.String()) {
		t.Fatal("original (pre-renewal) cert serial should be revoked")
	}
	if !a.store.isRevoked(newSerial) {
		t.Fatal("renewed cert serial should also be revoked")
	}
}

// TestGatewayRejectsRenewalOnRevokedSession is defense in depth: even if a
// session using an already-revoked certificate is somehow still open (the
// normal path force-disconnects it immediately — see http.go
// handleRevokeServer), the gateway must never hand out a fresh certificate
// to it.
func TestGatewayRejectsRenewalOnRevokedSession(t *testing.T) {
	a := newTestAPIServer(t)

	serverID, _, err := a.store.createServer("revoked-renew-test", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	key, csrPEM := testAgentCSR(t)
	certPEM, serial, err := a.ca.signAgentCSR(csrPEM, serverID, time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	a.store.markIssuedCert(serverID, serial.String())
	keyPEM := testKeyToPEM(t, key)

	ln, err := a.gw.newTLSListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newTLSListener: %v", err)
	}
	defer ln.Close()
	go a.gw.serve(ln)

	enc, dec, conn := dialAgent(t, ln.Addr().String(), a.ca.CAPEM(), certPEM, keyPEM)
	defer conn.Close()

	// Revoke the server (and thus this exact serial) while the connection
	// stays open, simulating the narrow race handleRenewCert's isRevoked
	// check exists for.
	if err := a.store.revokeServer(serverID, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}

	_, newCSRPEM := testAgentCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCertReq{CSRPEM: string(newCSRPEM)}}); err != nil {
		t.Fatalf("send renew_cert: %v", err)
	}

	var result proto.Envelope
	if err := dec.Decode(&result); err != nil {
		t.Fatalf("decode renew_cert_result: %v", err)
	}
	if result.RenewCertResult == nil || result.RenewCertResult.OK {
		t.Fatal("expected renewal to be rejected for a session using an already-revoked certificate")
	}
}

func mustDecodePEM(t *testing.T, s string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatalf("could not PEM-decode %q", s)
	}
	return block.Bytes
}
