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

// testAgentConn is a minimal stand-in for apps/agent's real TLS client,
// enough to drive the wire protocol (Hello/Ack/CertRenewReq/CertRenewResp)
// against a real gateway TLS listener without importing the agent binary's
// package (it's an unrelated `main` package).
type testAgentConn struct {
	t    *testing.T
	conn *tls.Conn
	enc  *json.Encoder
	dec  *json.Decoder
}

func newKeyAndCSR(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "irrelevant"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// dialTestAgent starts the gateway on an ephemeral port, registers a fresh
// server identity against it (mirroring what handleRegister does), and
// dials in over real mTLS through Hello/Ack — i.e. everything an agent does
// before it's ready to send/receive application messages.
func dialTestAgent(t *testing.T, ca *agentCA, st *store, gw *gateway) (*testAgentConn, string, string) {
	t.Helper()

	serverID, _, err := st.createServer("web-renew", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	key, csrPEM := newKeyAndCSR(t)
	certPEM, serial, err := ca.signAgentCSR(csrPEM, serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String())

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	ln, err := gw.listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("gw.listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go gw.serve(ln)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ta := &testAgentConn{
		t:    t,
		conn: conn,
		enc:  json.NewEncoder(conn),
		dec:  json.NewDecoder(bufio.NewReader(conn)),
	}

	if err := ta.enc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: serverID, AgentVersion: "test"}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	var ack proto.Envelope
	if err := ta.dec.Decode(&ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("expected ack, got %q", ack.Type)
	}

	return ta, serverID, serial.String()
}

func (ta *testAgentConn) requestRenewal(csrPEM []byte) proto.CertRenewResp {
	ta.t.Helper()
	if err := ta.enc.Encode(proto.Envelope{Type: proto.MsgCertRenewReq, CertRenewReq: &proto.CertRenewReq{CSRPEM: string(csrPEM)}}); err != nil {
		ta.t.Fatalf("send cert_renew_req: %v", err)
	}
	var env proto.Envelope
	if err := ta.dec.Decode(&env); err != nil {
		ta.t.Fatalf("decode cert_renew_resp: %v", err)
	}
	if env.Type != proto.MsgCertRenewResp || env.CertRenewResp == nil {
		ta.t.Fatalf("expected cert_renew_resp, got %q", env.Type)
	}
	return *env.CertRenewResp
}

func newTestCA(t *testing.T) *agentCA {
	t.Helper()
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	return ca
}

// TestCertRenewalOverLiveConnection exercises the full renewal wire
// protocol against a real mTLS listener: an already-connected agent (using
// its original registration cert) requests renewal, and must get back a
// certificate that (a) is signed by the same CA, (b) is bound to the same
// server_id via CommonName, (c) carries a new serial distinct from the
// original, and (d) is reflected in the store without disturbing the
// server's "connected" status — renewal happens mid-session, so it must
// never look like the server just went offline (see store.markRenewedCert).
func TestCertRenewalOverLiveConnection(t *testing.T) {
	st := newTestStore(t)
	ca := newTestCA(t)
	gw := newGateway(ca, st)

	agent, serverID, originalSerial := dialTestAgent(t, ca, st, gw)

	// Give handleConn's goroutine a moment to record the connection before
	// asserting on status below (Ack has already round-tripped, but
	// store.setConnected is called just before the Ack is sent, so this is
	// already true — no sleep needed).
	rec, ok := st.get(serverID)
	if !ok || rec.Status != statusConnected {
		t.Fatalf("server should be statusConnected right after handshake+ack, got %+v", rec)
	}

	_, newCSR := newKeyAndCSR(t)
	resp := agent.requestRenewal(newCSR)
	if resp.Error != "" {
		t.Fatalf("renewal rejected: %s", resp.Error)
	}
	if resp.CertPEM == "" {
		t.Fatal("renewal response has no cert_pem")
	}

	block, _ := pem.Decode([]byte(resp.CertPEM))
	if block == nil {
		t.Fatal("renewed cert is not valid PEM")
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (must stay bound to the same server identity)", newCert.Subject.CommonName, serverID)
	}
	if newCert.SerialNumber.String() == originalSerial {
		t.Fatal("renewed cert has the same serial as the original — renewal must issue a distinct certificate")
	}

	pool := ca.certPool()
	if _, err := newCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("renewed cert does not chain to the CA: %v", err)
	}

	rec, ok = st.get(serverID)
	if !ok {
		t.Fatal("server disappeared after renewal")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("store cert_serial = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}
	if rec.Status != statusConnected {
		t.Fatalf("status after renewal = %q, want %q (renewal must not look like a disconnect)", rec.Status, statusConnected)
	}

	// The original certificate must not have been revoked by renewal — the
	// live connection using it is still open and must keep working.
	if st.isRevoked(originalSerial) {
		t.Fatal("renewal must not revoke the certificate the live connection is still using")
	}
}

// TestCertRenewalRejectsMalformedCSRWithoutDroppingSession confirms that a
// bad renewal request gets a structured error back (not a dropped
// connection), so a single malformed CSR can't take down an otherwise
// healthy, already-authenticated session.
func TestCertRenewalRejectsMalformedCSRWithoutDroppingSession(t *testing.T) {
	st := newTestStore(t)
	ca := newTestCA(t)
	gw := newGateway(ca, st)

	agent, serverID, originalSerial := dialTestAgent(t, ca, st, gw)

	resp := agent.requestRenewal([]byte("not a csr"))
	if resp.Error == "" {
		t.Fatal("expected an error for a malformed CSR")
	}
	if resp.CertPEM != "" {
		t.Fatal("must not return a certificate alongside an error")
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server should still exist")
	}
	if rec.CertSerial != originalSerial {
		t.Fatalf("cert_serial changed after a rejected renewal: got %q, want unchanged %q", rec.CertSerial, originalSerial)
	}

	// The session must still be usable after a rejected renewal: retry with
	// a valid CSR over the same connection and expect success.
	_, goodCSR := newKeyAndCSR(t)
	resp2 := agent.requestRenewal(goodCSR)
	if resp2.Error != "" || resp2.CertPEM == "" {
		t.Fatalf("retry after a rejected renewal should succeed, got error=%q cert_pem_empty=%v", resp2.Error, resp2.CertPEM == "")
	}
}
