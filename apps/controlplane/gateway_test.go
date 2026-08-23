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

// testAgentConn dials the gateway's real mTLS listener with a client
// certificate the test's own CA instance issues (mirroring exactly what
// apps/agent/register.go and connect.go do), completes the Hello/Ack
// handshake, and hands back a ready-to-use encoder/decoder pair — so tests
// exercise the exact wire protocol an agent uses, not a shortcut.
func testAgentConn(t *testing.T, ca *agentCA, gatewayAddr, serverID string, certPEM, keyPEM []byte) (*json.Encoder, *json.Decoder, func()) {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CAPEM()) {
		t.Fatal("could not parse CA PEM")
	}
	conn, err := tls.Dial("tcp", gatewayAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := enc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: serverID, AgentVersion: "test"}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("expected ack, got %q", ack.Type)
	}

	return enc, dec, func() { conn.Close() }
}

// newAgentCSR generates a throwaway ECDSA keypair and PEM-encoded CSR,
// exactly like apps/agent/register.go and renew.go do — the CA ignores the
// requested Subject either way (see ca.go signAgentCSR).
func newAgentCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// setUpConnectedTestAgent creates a server record, issues it an initial
// client certificate (as if it had just registered), starts a real gateway
// listener on an ephemeral port, and dials into it — returning everything a
// test needs to then exercise gateway behavior over that live session.
func setUpConnectedTestAgent(t *testing.T) (st *store, ca *agentCA, gw *gateway, serverID string, initialSerial string, enc *json.Encoder, dec *json.Decoder, closeConn func()) {
	t.Helper()
	st = newTestStore(t)
	dir := t.TempDir()
	var err error
	ca, err = loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw = newGateway(ca, st)

	serverID, _, err = st.createServer("agent-1", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	initialKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate initial key: %v", err)
	}
	initialCSRDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, initialKey)
	if err != nil {
		t.Fatalf("create initial CSR: %v", err)
	}
	initialCSRPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: initialCSRDER})
	initialCertPEM, serial, err := ca.signAgentCSR(initialCSRPEM, serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String())
	initialKeyDER, err := x509.MarshalECPrivateKey(initialKey)
	if err != nil {
		t.Fatalf("marshal initial key: %v", err)
	}
	initialKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: initialKeyDER})

	ln, err := gw.listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("gw.listen: %v", err)
	}
	go gw.serve(ln)
	t.Cleanup(func() { ln.Close() })

	enc, dec, closeConn = testAgentConn(t, ca, ln.Addr().String(), serverID, initialCertPEM, initialKeyPEM)
	return st, ca, gw, serverID, serial.String(), enc, dec, closeConn
}

func TestGatewayRenewCertIssuesFreshCertAndPreservesConnectedStatus(t *testing.T) {
	st, _, _, serverID, initialSerial, enc, dec, closeConn := setUpConnectedTestAgent(t)
	defer closeConn()

	// The session is live, so the gateway should already show this server
	// as connected — renewal must not disturb that.
	rec, ok := st.get(serverID)
	if !ok || rec.Status != statusConnected {
		t.Fatalf("expected server to be connected before renewal, got %+v", rec)
	}

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCert{CSRPEM: string(newAgentCSR(t))}}); err != nil {
		t.Fatalf("send renew_cert: %v", err)
	}

	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("read renew_cert_result: %v", err)
	}
	if resp.Type != proto.MsgRenewCertResult || resp.RenewCertResult == nil {
		t.Fatalf("expected renew_cert_result, got %+v", resp)
	}
	if resp.RenewCertResult.Error != "" {
		t.Fatalf("unexpected renewal error: %s", resp.RenewCertResult.Error)
	}
	if resp.RenewCertResult.CertPEM == "" {
		t.Fatal("expected a non-empty renewed certificate")
	}

	block, _ := pem.Decode([]byte(resp.RenewCertResult.CertPEM))
	if block == nil {
		t.Fatal("renewed cert is not valid PEM")
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (must bind to the session's own identity, not anything caller-supplied)", newCert.Subject.CommonName, serverID)
	}
	if newCert.SerialNumber.String() == initialSerial {
		t.Fatal("renewed cert has the same serial as the original — expected a fresh one")
	}
	if time.Until(newCert.NotAfter) < 29*24*time.Hour {
		t.Fatalf("renewed cert NotAfter = %s, want roughly agentCertTTL (30 days) out", newCert.NotAfter)
	}

	// The store's recorded serial should now be the new one, and status
	// must still read connected — this is the bug updateCertSerial (as
	// opposed to reusing markIssuedCert, which forces status back to
	// offline) exists to prevent.
	rec, ok = st.get(serverID)
	if !ok {
		t.Fatal("server record vanished after renewal")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("store CertSerial = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}
	if rec.Status != statusConnected {
		t.Fatalf("server status after renewal = %q, want %q (renewal must not disturb a live session's connected status)", rec.Status, statusConnected)
	}
}

func TestGatewayRenewCertRejectsMalformedCSRWithoutClosingSession(t *testing.T) {
	_, _, _, _, _, enc, dec, closeConn := setUpConnectedTestAgent(t)
	defer closeConn()

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCert{CSRPEM: "not a csr"}}); err != nil {
		t.Fatalf("send malformed renew_cert: %v", err)
	}

	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("read renew_cert_result: %v", err)
	}
	if resp.RenewCertResult == nil || resp.RenewCertResult.Error == "" {
		t.Fatalf("expected a renewal error for a malformed CSR, got %+v", resp.RenewCertResult)
	}
	if resp.RenewCertResult.CertPEM != "" {
		t.Fatal("expected no certificate to be issued for a malformed CSR")
	}

	// The session itself must still be usable afterward — a rejected
	// renewal is not a fatal condition for the connection (see
	// gateway.go handleRenewCert).
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCert{CSRPEM: string(newAgentCSR(t))}}); err != nil {
		t.Fatalf("send valid renew_cert after a failed one: %v", err)
	}
	var resp2 proto.Envelope
	if err := dec.Decode(&resp2); err != nil {
		t.Fatalf("read second renew_cert_result: %v", err)
	}
	if resp2.RenewCertResult == nil || resp2.RenewCertResult.Error != "" || resp2.RenewCertResult.CertPEM == "" {
		t.Fatalf("expected a successful renewal to still work after a prior failure, got %+v", resp2.RenewCertResult)
	}
}
