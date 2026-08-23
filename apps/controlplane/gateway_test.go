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
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// testGenerateCSR mints a throwaway ECDSA keypair and CSR, mirroring what
// apps/agent/register.go's generateKeyAndCSR does — kept as a small local
// copy here rather than an import, since apps/agent is an unrelated `main`
// package this test can't import.
func testGenerateCSR(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test-agent"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

// newTestGateway wires up a store + real in-process CA + gateway, matching
// newTestAPIServer's construction, but also hands back the CA and store
// directly since gateway-level tests need to sign certs and inspect
// persisted state that a plain apiServer doesn't expose.
func newTestGateway(t *testing.T) (*gateway, *agentCA, *store) {
	t.Helper()
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	return newGateway(ca, st), ca, st
}

// dialTestAgent opens a real mTLS connection to a running gateway using the
// given client identity and performs the same Hello/ack handshake
// apps/agent/connect.go's runConnection does, returning a decoder/encoder
// the test can drive further messages over.
func dialTestAgent(t *testing.T, ln net.Listener, ca *agentCA, serverID string, certPEM []byte, key *ecdsa.PrivateKey) (net.Conn, *json.Encoder, *json.Decoder) {
	t.Helper()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), cfg)
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
		t.Fatalf("expected ack from gateway, got %q", ack.Type)
	}
	return conn, enc, dec
}

// TestGatewayRenewsCertOverLiveMTLSSession exercises the actual wire
// protocol end to end (real TLS listener, real mTLS handshake, real CA
// signing) for the agent certificate renewal path added alongside this
// test: an agent nearing its certificate's expiry (see
// apps/agent/connect.go renewalLoop) sends a renewal CSR over its already
// -authenticated session, and the gateway must sign and return a fresh
// certificate for the same identity without requiring a bootstrap token.
func TestGatewayRenewsCertOverLiveMTLSSession(t *testing.T) {
	gw, ca, st := newTestGateway(t)

	serverID, _, err := st.createServer("renew-test", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	csrPEM, key := testGenerateCSR(t)
	certPEM, serial, err := ca.signAgentCSR(csrPEM, serverID, time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String())

	ln, err := gw.newTLSListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newTLSListener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go gw.serve(ln)

	conn, enc, dec := dialTestAgent(t, ln, ca, serverID, certPEM, key)

	renewCSR, _ := testGenerateCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(renewCSR)}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	if resp.Type != proto.MsgRenewResponse || resp.RenewResponse == nil {
		t.Fatalf("expected a renew_response, got %+v", resp)
	}

	block, _ := pem.Decode([]byte(resp.RenewResponse.CertPEM))
	if block == nil {
		t.Fatal("renewed certificate is not valid PEM")
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CN = %q, want %q (must come from the authenticated session, not the CSR)", newCert.Subject.CommonName, serverID)
	}
	if newCert.SerialNumber.String() == serial.String() {
		t.Fatal("renewed cert reused the old serial instead of getting a new one")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.rootCert)
	if _, err := newCert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("renewed cert does not verify against this CA: %v", err)
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server should still exist")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("store cert_serial = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}
	if st.isRevoked(serial.String()) {
		t.Fatal("renewal alone must not revoke the superseded certificate (see rotateCert's doc comment)")
	}

	// A later explicit revocation must still invalidate the whole
	// certificate history for this server, original and renewed alike —
	// otherwise a renewed-but-still-valid old cert would keep working
	// after the operator believes they've revoked the server.
	if err := st.revokeServer(serverID, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}
	if !st.isRevoked(serial.String()) {
		t.Fatal("revokeServer should revoke the original pre-renewal certificate too")
	}
	if !st.isRevoked(newCert.SerialNumber.String()) {
		t.Fatal("revokeServer should revoke the renewed certificate")
	}
}

// TestGatewayEnforcesRenewalCooldown guards against a buggy or malicious
// agent hammering the gateway with renewal requests: a second request
// arriving before renewCooldown has elapsed must be silently dropped, not
// answered with (and billed for) another freshly signed certificate.
func TestGatewayEnforcesRenewalCooldown(t *testing.T) {
	gw, ca, st := newTestGateway(t)

	serverID, _, err := st.createServer("renew-cooldown-test", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	csrPEM, key := testGenerateCSR(t)
	certPEM, serial, err := ca.signAgentCSR(csrPEM, serverID, time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String())

	ln, err := gw.newTLSListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newTLSListener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go gw.serve(ln)

	conn, enc, dec := dialTestAgent(t, ln, ca, serverID, certPEM, key)

	firstCSR, _ := testGenerateCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(firstCSR)}}); err != nil {
		t.Fatalf("send first renew request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var first proto.Envelope
	if err := dec.Decode(&first); err != nil || first.Type != proto.MsgRenewResponse {
		t.Fatalf("expected first renewal to succeed, got resp=%+v err=%v", first, err)
	}

	secondCSR, _ := testGenerateCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(secondCSR)}}); err != nil {
		t.Fatalf("send second renew request: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var second proto.Envelope
	err = dec.Decode(&second)
	if err == nil {
		t.Fatalf("expected no second renewal response within the cooldown window, got %+v", second)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a read timeout waiting out the cooldown, got a different error: %v", err)
	}
}
