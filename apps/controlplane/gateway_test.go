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
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// testAgent is a minimal stand-in for apps/agent's connect.go, built
// directly against packages/proto and a real mTLS dial — exercising the
// actual wire protocol end-to-end instead of mocking gateway internals.
type testAgent struct {
	t    *testing.T
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
}

func dialTestAgent(t *testing.T, addr string, ca *agentCA, serverID string, key *ecdsa.PrivateKey, certPEM []byte) *testAgent {
	t.Helper()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ta := &testAgent{t: t, conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(bufio.NewReader(conn))}

	if err := ta.enc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: serverID, AgentVersion: "test"}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	var ack proto.Envelope
	if err := ta.dec.Decode(&ack); err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("expected ack, got %q", ack.Type)
	}
	return ta
}

// newTestGatewayServer wires up a store + CA + gateway exactly like
// newTestAPIServer does, then starts the real mTLS accept loop on an
// ephemeral port so tests can dial it directly.
func newTestGatewayServer(t *testing.T) (*gateway, *store, *agentCA, string) {
	t.Helper()
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(dir+"/ca-cert.pem", dir+"/ca-key.pem", 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	ln, err := gw.newTLSListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newTLSListener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go gw.serve(ln)

	return gw, st, ca, ln.Addr().String()
}

// registerTestAgent mints a server record and a real agent certificate for
// it directly through the CA (bypassing the HTTP /agents/register handler,
// which is covered separately) so gateway tests can focus on the mTLS
// session and renewal protocol.
func registerTestAgent(t *testing.T, st *store, ca *agentCA, name string) (serverID string, key *ecdsa.PrivateKey, certPEM []byte) {
	t.Helper()
	serverID, _, err := st.createServer(name, "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, serial, notAfter, err := ca.signAgentCSR(csrPEM, serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String(), notAfter)
	return serverID, key, certPEM
}

func TestGatewayHandleRenewIssuesFreshCertBoundToSameServerID(t *testing.T) {
	_, st, ca, addr := newTestGatewayServer(t)
	serverID, origKey, certPEM := registerTestAgent(t, st, ca, "web-renew")

	oldCert, err := parseFirstCert(certPEM)
	if err != nil {
		t.Fatalf("parse original cert: %v", err)
	}
	oldSerial := oldCert.SerialNumber.String()

	ta := dialTestAgent(t, addr, ca, serverID, origKey, certPEM)

	newKey := mustNewKey(t)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "attacker-claimed-id"}}, newKey)
	if err != nil {
		t.Fatalf("create renewal CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := ta.enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}

	ta.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp proto.Envelope
	if err := ta.dec.Decode(&resp); err != nil {
		t.Fatalf("read renew response: %v", err)
	}
	if resp.Type != proto.MsgRenewResponse || resp.RenewResponse == nil {
		t.Fatalf("expected renew_response, got %+v", resp)
	}

	newCert, err := parseFirstCert([]byte(resp.RenewResponse.CertPEM))
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}

	// Identity must come from the authenticated session, not the CSR's
	// (attacker-controlled, in this test) requested subject.
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (CSR subject must be ignored)", newCert.Subject.CommonName, serverID)
	}
	if newCert.SerialNumber.String() == oldSerial {
		t.Fatal("renewed cert must have a new serial number")
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record should still exist")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("store CertSerial = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}
	if st.isRevoked(oldSerial) {
		t.Fatal("the pre-renewal certificate must not be revoked by a successful renewal")
	}

	// The new certificate must actually work for a fresh connection.
	ta2 := dialTestAgent(t, addr, ca, serverID, newKey, []byte(resp.RenewResponse.CertPEM))
	ta2.conn.Close()
}

func TestGatewayHandleRenewRejectsInvalidCSR(t *testing.T) {
	_, st, ca, addr := newTestGatewayServer(t)
	serverID, key, certPEM := registerTestAgent(t, st, ca, "web-renew-bad-csr")
	ta := dialTestAgent(t, addr, ca, serverID, key, certPEM)

	if err := ta.enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: "not a csr"}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}

	// An invalid CSR must not crash the session or hand back a bogus
	// success; the gateway logs and drops it, and the connection (and the
	// server's existing certificate) must remain usable.
	if err := ta.enc.Encode(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{SentAt: time.Now().UTC()}}); err != nil {
		t.Fatalf("connection should still be usable after a rejected renewal: %v", err)
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record should still exist")
	}
	origCert, _ := parseFirstCert(certPEM)
	if rec.CertSerial != origCert.SerialNumber.String() {
		t.Fatalf("CertSerial should be unchanged after a rejected renewal, got %q", rec.CertSerial)
	}
}

func mustNewKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func parseFirstCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	return x509.ParseCertificate(block.Bytes)
}
