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

func newTestCSR(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func parseCertPEM(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("could not decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestHandleRenewIssuesFreshCertBoundToSameServerID exercises the whole
// renewal path (§ docs/SECURITY.md §2): a server that already has an
// initial cert_serial (as if freshly registered and connected) requests
// renewal, and the response must be a new certificate for the *same*
// server_id with a later expiry and a different serial — the whole point
// of renewal is a like-for-like replacement, never a chance to claim a
// different identity.
func TestHandleRenewIssuesFreshCertBoundToSameServerID(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	id, _, err := st.createServer("web-1", "prod", nil, 15*time.Minute, "actor@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	origCertPEM, origSerial, err := ca.signAgentCSR([]byte(newTestCSR(t, "pending-registration")), id, agentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR (initial): %v", err)
	}
	st.markIssuedCert(id, origSerial.String())
	// Simulate the agent having actually connected since registration —
	// this is the status a live renewal would be requested from, and is
	// exactly the value handleRenew/updateCertSerial must not disturb.
	st.setConnected(id, true)

	origCert := parseCertPEM(t, string(origCertPEM))

	resp := gw.handleRenew(id, newTestCSR(t, "pending-renewal"))
	if resp.Error != "" {
		t.Fatalf("handleRenew returned an error: %s", resp.Error)
	}
	if resp.CertPEM == "" {
		t.Fatal("handleRenew returned an empty certificate")
	}

	newCert := parseCertPEM(t, resp.CertPEM)
	if newCert.Subject.CommonName != id {
		t.Fatalf("renewed cert CommonName = %q, want %q", newCert.Subject.CommonName, id)
	}
	if newCert.SerialNumber.Cmp(origCert.SerialNumber) == 0 {
		t.Fatal("renewed cert has the same serial number as the original — renewal must always mint a fresh one")
	}
	if !newCert.NotAfter.After(origCert.NotAfter.Add(-time.Minute)) {
		t.Fatalf("renewed cert NotAfter (%s) is not later than original (%s)", newCert.NotAfter, origCert.NotAfter)
	}

	rec, ok := st.get(id)
	if !ok {
		t.Fatal("server record disappeared")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("stored cert_serial = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}
	// The critical regression this guards against: markIssuedCert (used at
	// initial registration) forces status to "offline" because the agent
	// hasn't connected yet at that point, but a renewal happens *during* an
	// already-live session — updateCertSerial must leave status alone.
	if rec.Status != statusConnected {
		t.Fatalf("status after renewal = %q, want %q (renewal must not clobber live connection status)", rec.Status, statusConnected)
	}
}

// TestGatewayRenewalOverRealMTLSConnection exercises the actual wire
// protocol end-to-end — real TCP, real mTLS handshake, real JSON envelopes
// — rather than calling gateway.handleRenew directly. This is the only test
// in the suite that establishes a live agent session against gateway.serve,
// so it also incidentally covers the Hello/Ack session-establishment path
// that handleConn otherwise has no automated coverage for at all.
func TestGatewayRenewalOverRealMTLSConnection(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	serverID, _, err := st.createServer("web-3", "prod", nil, 15*time.Minute, "actor@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	// Simulate what registration (http.go handleRegister) does: generate a
	// keypair, sign its CSR into the initial client cert, and record the
	// serial — this is the identity the test client dials in with below.
	origKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	origCSRDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending-registration"}}, origKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	origCertPEM, origSerial, err := ca.signAgentCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: origCSRDER}), serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR (initial): %v", err)
	}
	st.markIssuedCert(serverID, origSerial.String())
	origKeyDER, err := x509.MarshalECPrivateKey(origKey)
	if err != nil {
		t.Fatalf("marshal agent key: %v", err)
	}
	origKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: origKeyDER})

	clientCert, err := tls.X509KeyPair(origCertPEM, origKeyPEM)
	if err != nil {
		t.Fatalf("build client cert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go gw.serve(ln)

	caPool := ca.certPool()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial gateway over mTLS: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

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

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: newTestCSR(t, "pending-renewal")}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}
	var renewEnv proto.Envelope
	if err := dec.Decode(&renewEnv); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	if renewEnv.Type != proto.MsgRenewResponse || renewEnv.RenewResponse == nil {
		t.Fatalf("expected a renew_response envelope, got %+v", renewEnv)
	}
	if renewEnv.RenewResponse.Error != "" {
		t.Fatalf("renewal over the wire failed: %s", renewEnv.RenewResponse.Error)
	}

	newCert := parseCertPEM(t, renewEnv.RenewResponse.CertPEM)
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q", newCert.Subject.CommonName, serverID)
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record disappeared")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("stored cert_serial = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}
}

// TestHandleRenewRejectsInvalidCSR ensures a malformed/unsigned CSR is
// reported back as an error in the response rather than panicking or
// silently issuing a certificate — a live session must survive a bad
// renewal attempt (see renew.go performRenewal / renewalLoop retry logic).
func TestHandleRenewRejectsInvalidCSR(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	id, _, err := st.createServer("web-2", "prod", nil, 15*time.Minute, "actor@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	resp := gw.handleRenew(id, "not a valid CSR")
	if resp.Error == "" {
		t.Fatal("expected an error for an invalid CSR, got none")
	}
	if resp.CertPEM != "" {
		t.Fatal("expected no certificate to be issued for an invalid CSR")
	}
}
