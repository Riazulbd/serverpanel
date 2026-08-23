package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// generateTestCSR mirrors what apps/agent/register.go and apps/agent/renew.go
// generate: a fresh keypair and a CSR for it. The requested CommonName is
// deliberately allowed to be nonsense in these tests — handleRenewRequest
// must ignore it and bind the issued certificate to the connection's already
// -authenticated identity instead.
func generateTestCSR(t *testing.T, requestedCN string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: requestedCN}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// newTestAgentSession returns an agentSession backed by an in-memory
// net.Pipe rather than a real mTLS socket. handleRenewRequest only ever
// touches sess.conn's identity implicitly (via the serverID passed
// separately) and writes through sess.enc, so a pipe exercises the same
// code path as a live connection without standing up TLS in every test.
func newTestAgentSession(serverID string) (sess *agentSession, clientConn net.Conn) {
	serverConn, clientConn := net.Pipe()
	return &agentSession{serverID: serverID, conn: serverConn, enc: json.NewEncoder(serverConn)}, clientConn
}

func TestHandleRenewRequestIssuesFreshCertBoundToConnectionIdentity(t *testing.T) {
	a := newTestAPIServer(t)
	st, gw := a.store, a.gw

	serverID, _, err := st.createServer("web-1", "", nil, 15*time.Minute, "owner@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "1") // simulate the certificate issued at first registration

	sess, clientConn := newTestAgentSession(serverID)
	defer sess.conn.Close()
	defer clientConn.Close()

	respCh := make(chan proto.Envelope, 1)
	go func() {
		var env proto.Envelope
		if err := json.NewDecoder(clientConn).Decode(&env); err == nil {
			respCh <- env
		}
	}()

	// The CSR asks for a completely different CommonName — this must be
	// ignored; the issued cert must be bound to serverID, exactly as
	// registration binds it from the validated bootstrap token, not from
	// anything the requester asserts.
	csrPEM := generateTestCSR(t, "attacker-supplied-identity")
	gw.handleRenewRequest(sess, serverID, &proto.RenewRequest{CSRPEM: csrPEM})

	var resp proto.Envelope
	select {
	case resp = <-respCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for renewal response")
	}
	if resp.Type != proto.MsgRenewResponse || resp.RenewResponse == nil {
		t.Fatalf("unexpected response: %+v", resp)
	}

	block, _ := pem.Decode([]byte(resp.RenewResponse.CertPEM))
	if block == nil {
		t.Fatal("renewal response did not contain a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if cert.Subject.CommonName != serverID {
		t.Fatalf("issued certificate CN = %q, want %q (must come from the authenticated connection, never the CSR)", cert.Subject.CommonName, serverID)
	}
	if time.Until(cert.NotAfter) < agentCertTTL-time.Hour {
		t.Fatalf("issued certificate NotAfter = %s, want ~agentCertTTL from now", cert.NotAfter)
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record vanished")
	}
	if rec.CertSerial != cert.SerialNumber.String() {
		t.Fatalf("store cert_serial = %q, want %q (the newly issued serial)", rec.CertSerial, cert.SerialNumber.String())
	}

	var sawAudit bool
	for _, e := range st.auditLog() {
		if e.ServerID == serverID && e.Action == "agent.cert_renewed" {
			sawAudit = true
		}
	}
	if !sawAudit {
		t.Fatal("expected an agent.cert_renewed audit entry")
	}
}

func TestHandleRenewRequestDoesNotFlipConnectedStatusOffline(t *testing.T) {
	a := newTestAPIServer(t)
	st, gw := a.store, a.gw

	serverID, _, err := st.createServer("web-2", "", nil, 15*time.Minute, "owner@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "1")
	st.setConnected(serverID, true) // the renewal happens over a connection that is, by definition, already open

	sess, clientConn := newTestAgentSession(serverID)
	defer sess.conn.Close()
	defer clientConn.Close()
	go func() {
		var env proto.Envelope
		json.NewDecoder(clientConn).Decode(&env) // drain the response so the encode doesn't block
	}()

	gw.handleRenewRequest(sess, serverID, &proto.RenewRequest{CSRPEM: generateTestCSR(t, "irrelevant")})

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record vanished")
	}
	if rec.Status != statusConnected {
		t.Fatalf("status = %q after renewal, want %q — renewal must never make a live session look offline", rec.Status, statusConnected)
	}
}

func TestHandleRenewRequestRejectsInvalidCSR(t *testing.T) {
	a := newTestAPIServer(t)
	st, gw := a.store, a.gw

	serverID, _, err := st.createServer("web-3", "", nil, 15*time.Minute, "owner@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "1")

	sess, clientConn := newTestAgentSession(serverID)
	defer sess.conn.Close()
	defer clientConn.Close()

	// No goroutine draining clientConn: a rejected CSR must return before
	// ever attempting to send a response, so this must not block.
	gw.handleRenewRequest(sess, serverID, &proto.RenewRequest{CSRPEM: "this is not a CSR"})

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record vanished")
	}
	if rec.CertSerial != "1" {
		t.Fatalf("cert_serial changed to %q on an invalid CSR, want unchanged", rec.CertSerial)
	}

	var sawFailureAudit bool
	for _, e := range st.auditLog() {
		if e.ServerID == serverID && e.Action == "agent.cert_renewal_failed" {
			sawFailureAudit = true
		}
	}
	if !sawFailureAudit {
		t.Fatal("expected an agent.cert_renewal_failed audit entry")
	}
}

func TestHandleRenewRequestIgnoresEmptyRequest(t *testing.T) {
	a := newTestAPIServer(t)
	st, gw := a.store, a.gw

	serverID, _, err := st.createServer("web-4", "", nil, 15*time.Minute, "owner@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "1")

	sess, clientConn := newTestAgentSession(serverID)
	defer sess.conn.Close()
	defer clientConn.Close()

	gw.handleRenewRequest(sess, serverID, nil)
	gw.handleRenewRequest(sess, serverID, &proto.RenewRequest{CSRPEM: ""})

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record vanished")
	}
	if rec.CertSerial != "1" {
		t.Fatalf("cert_serial changed on a nil/empty renewal request, want unchanged")
	}
}
