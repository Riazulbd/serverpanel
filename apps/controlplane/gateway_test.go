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
	"path/filepath"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// newTestGateway wires a gateway against a fresh store and a real in-process
// CA, matching how main.go constructs one (see newTestAPIServer), but
// without the HTTP apiServer wrapper — these tests dial the gateway's mTLS
// listener directly, the way the real agent does.
func newTestGateway(t *testing.T) (*gateway, *store) {
	t.Helper()
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	return newGateway(ca, st), st
}

// newKeyAndCSR generates a fresh ECDSA key and a CSR for it, mirroring what
// apps/agent/register.go and apps/agent/renew.go do. The CSR's Subject is
// never trusted by the CA (see ca.signAgentCSR) so its content doesn't
// matter here beyond being well-formed.
func newKeyAndCSR(t *testing.T) (keyPEM, csrPEM []byte) {
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
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return keyPEM, csrPEM
}

func mustParseCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("could not PEM-decode certificate: %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// dialGateway performs a real mTLS handshake against a running gateway
// listener using certPEM/keyPEM as the client identity, and returns the
// connection after reading the gateway's session-establishment ack — the
// same sequence apps/agent/connect.go's runConnection follows.
func dialGateway(t *testing.T, addr string, certPEM, keyPEM []byte, caPool *x509.CertPool) (*tls.Conn, *json.Encoder, *json.Decoder) {
	t.Helper()
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build client cert: %v", err)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(bufio.NewReader(conn))

	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("decode session ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("first message from gateway = %q, want %q", ack.Type, proto.MsgAck)
	}
	return conn, enc, dec
}

// TestGatewayRenewCSRIssuesFreshCertBoundToSameServerID exercises the full
// on-the-wire renewal path end to end: register an agent identity, connect
// with it over real mTLS, request a renewal, and confirm the control plane
// issues a new certificate for the same server_id with a new serial — the
// documented rotation model (docs/SECURITY.md §2), previously untested at
// the gateway/transport layer (only the HTTP register endpoint had
// integration coverage before this).
func TestGatewayRenewCSRIssuesFreshCertBoundToSameServerID(t *testing.T) {
	gw, st := newTestGateway(t)

	serverID, _, err := st.createServer("web-renew", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	initialKeyPEM, initialCSR := newKeyAndCSR(t)
	initialCertPEM, initialSerial, err := gw.ca.signAgentCSR(initialCSR, serverID, time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR (initial): %v", err)
	}
	st.markIssuedCert(serverID, initialSerial.String(), time.Now().Add(time.Hour))

	ln, err := gw.newTLSListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newTLSListener: %v", err)
	}
	defer ln.Close()
	go gw.serve(ln)

	_, enc, dec := dialGateway(t, ln.Addr().String(), initialCertPEM, initialKeyPEM, gw.ca.certPool())

	_, renewalCSR := newKeyAndCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCSR, RenewCSR: &proto.RenewCSR{CSRPEM: string(renewalCSR)}}); err != nil {
		t.Fatalf("send renew_csr: %v", err)
	}

	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode renew_cert response: %v", err)
	}
	if resp.Type != proto.MsgRenewCert || resp.RenewCert == nil {
		t.Fatalf("got envelope type %q, want %q with a payload", resp.Type, proto.MsgRenewCert)
	}
	if resp.RenewCert.Error != "" {
		t.Fatalf("renewal unexpectedly rejected: %s", resp.RenewCert.Error)
	}
	if resp.RenewCert.CertPEM == "" {
		t.Fatal("expected a renewed certificate")
	}

	renewedCert := mustParseCert(t, resp.RenewCert.CertPEM)
	if renewedCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (must stay bound to the same server identity)", renewedCert.Subject.CommonName, serverID)
	}
	if renewedCert.SerialNumber.String() == initialSerial.String() {
		t.Fatal("renewed cert must have a new serial, not reuse the connection's current one")
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record should still exist after renewal")
	}
	if rec.CertSerial != renewedCert.SerialNumber.String() {
		t.Fatalf("store cert_serial = %q, want %q", rec.CertSerial, renewedCert.SerialNumber.String())
	}
	if rec.CertExpiresAt.IsZero() {
		t.Fatal("store cert_expires_at should be populated after renewal")
	}
	if !resp.RenewCert.NotAfter.Equal(rec.CertExpiresAt) {
		t.Fatalf("response NotAfter %v does not match stored cert_expires_at %v", resp.RenewCert.NotAfter, rec.CertExpiresAt)
	}
}

// TestGatewayRenewCSRRejectsMalformedCSRWithoutDroppingSession confirms a
// bad renewal request gets an error reply, not a dropped connection: the
// agent's current, still-valid certificate must go on working normally
// after a failed renewal attempt (see docs "a renewal attempt that fails
// must leave the agent exactly as connected as it was before trying").
func TestGatewayRenewCSRRejectsMalformedCSRWithoutDroppingSession(t *testing.T) {
	gw, st := newTestGateway(t)

	serverID, _, err := st.createServer("web-renew-bad", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	keyPEM, csrPEM := newKeyAndCSR(t)
	certPEM, serial, err := gw.ca.signAgentCSR(csrPEM, serverID, time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String(), time.Now().Add(time.Hour))

	ln, err := gw.newTLSListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newTLSListener: %v", err)
	}
	defer ln.Close()
	go gw.serve(ln)

	conn, enc, dec := dialGateway(t, ln.Addr().String(), certPEM, keyPEM, gw.ca.certPool())

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCSR, RenewCSR: &proto.RenewCSR{CSRPEM: "this is not a CSR"}}); err != nil {
		t.Fatalf("send malformed renew_csr: %v", err)
	}
	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.RenewCert == nil || resp.RenewCert.Error == "" {
		t.Fatal("expected the malformed CSR to be rejected with a non-empty error")
	}
	if resp.RenewCert.CertPEM != "" {
		t.Fatal("a rejected renewal must not carry a certificate")
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record should still exist")
	}
	if rec.CertSerial != serial.String() {
		t.Fatalf("cert_serial changed after a rejected renewal: got %q, want unchanged %q", rec.CertSerial, serial.String())
	}

	// The session must still be alive and usable: a heartbeat sent right
	// after the failed renewal should be accepted, not find a closed conn.
	if err := enc.Encode(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{SentAt: time.Now().UTC()}}); err != nil {
		t.Fatalf("session should still accept messages after a rejected renewal: %v", err)
	}
	_ = conn
}
