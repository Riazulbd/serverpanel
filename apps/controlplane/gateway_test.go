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
	"path/filepath"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

func generateCSRPEM(t *testing.T, commonName string) []byte {
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

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

// TestHandleRenewCertIssuesFreshCertAndUpdatesStore exercises the full
// renewal path over a real net.Conn (net.Pipe): the gateway must issue a new
// certificate bound to the *session's* server_id (never whatever CN the
// agent's CSR asked for), and must advance the store's cert_serial so a
// subsequent revocation targets the certificate actually in use.
func TestHandleRenewCertIssuesFreshCertAndUpdatesStore(t *testing.T) {
	gw, st := newTestGateway(t)

	serverID, _, err := st.createServer("web-renew", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "200")

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	sess := &agentSession{serverID: serverID, conn: serverConn, enc: json.NewEncoder(serverConn), pending: map[string]chan proto.TaskEvent{}}

	// CN deliberately does not match serverID: the CA must ignore it and
	// bind identity from the authenticated session, not the CSR's requested
	// subject (mirrors signAgentCSR's registration-time guarantee).
	csrPEM := generateCSRPEM(t, "attacker-claimed-identity")

	done := make(chan struct{})
	go func() {
		gw.handleRenewCert(sess, serverID, &proto.RenewCertRequest{CSRPEM: string(csrPEM)})
		close(done)
	}()

	var env proto.Envelope
	dec := json.NewDecoder(clientConn)
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("decode renewal response: %v", err)
	}
	<-done

	if env.Type != proto.MsgRenewCertResult || env.RenewCertResult == nil {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	if !env.RenewCertResult.Ok {
		t.Fatalf("renewal failed: %s", env.RenewCertResult.Error)
	}

	block, _ := pem.Decode([]byte(env.RenewCertResult.CertPEM))
	if block == nil {
		t.Fatal("no PEM block in renewed cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if cert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CN = %q, want %q (must bind to session identity, not CSR-requested subject)", cert.Subject.CommonName, serverID)
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server missing")
	}
	if rec.CertSerial != cert.SerialNumber.String() {
		t.Fatalf("store cert_serial = %q, want %q", rec.CertSerial, cert.SerialNumber.String())
	}
	if rec.CertSerial == "200" {
		t.Fatal("cert_serial should have advanced past the pre-renewal serial")
	}

	// The security-critical property: revoking the server now must revoke
	// the renewed serial, not the stale pre-renewal one.
	if err := st.revokeServer(serverID, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}
	if st.isRevoked("200") {
		t.Fatal("stale pre-renewal serial should not be revocation's target")
	}
	if !st.isRevoked(cert.SerialNumber.String()) {
		t.Fatal("revocation must target the renewed (currently in-use) serial")
	}
}

func TestHandleRenewCertRejectsUnknownServer(t *testing.T) {
	gw, _ := newTestGateway(t)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	sess := &agentSession{serverID: "srv_doesnotexist", conn: serverConn, enc: json.NewEncoder(serverConn), pending: map[string]chan proto.TaskEvent{}}

	csrPEM := generateCSRPEM(t, "pending-renewal")
	done := make(chan struct{})
	go func() {
		gw.handleRenewCert(sess, "srv_doesnotexist", &proto.RenewCertRequest{CSRPEM: string(csrPEM)})
		close(done)
	}()

	var env proto.Envelope
	dec := json.NewDecoder(clientConn)
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("decode renewal response: %v", err)
	}
	<-done
	if env.RenewCertResult == nil || env.RenewCertResult.Ok {
		t.Fatal("expected renewal to be rejected for an unknown server")
	}
}

func TestHandleRenewCertRejectsEmptyRequest(t *testing.T) {
	gw, st := newTestGateway(t)
	serverID, _, err := st.createServer("web-renew-empty", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "300")

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	sess := &agentSession{serverID: serverID, conn: serverConn, enc: json.NewEncoder(serverConn), pending: map[string]chan proto.TaskEvent{}}

	done := make(chan struct{})
	go func() {
		gw.handleRenewCert(sess, serverID, nil)
		close(done)
	}()

	var env proto.Envelope
	dec := json.NewDecoder(clientConn)
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("decode renewal response: %v", err)
	}
	<-done
	if env.RenewCertResult == nil || env.RenewCertResult.Ok {
		t.Fatal("expected renewal to be rejected for a nil request")
	}

	rec, _ := st.get(serverID)
	if rec.CertSerial != "300" {
		t.Fatalf("cert_serial should be untouched on a rejected renewal, got %q", rec.CertSerial)
	}
}
