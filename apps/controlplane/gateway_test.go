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

func testCSR(t *testing.T, commonName string) string {
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

// TestHandleRenewRequestIssuesFreshCertAndRevokesOld exercises the full
// renewal path a live agent session takes: a server with a known "current"
// cert serial requests renewal with a real CSR, and the gateway must both
// hand back a certificate that verifies against its CA and bound to the
// same server_id, and make the old serial unusable going forward.
func TestHandleRenewRequestIssuesFreshCertAndRevokesOld(t *testing.T) {
	gw, st := newTestGateway(t)
	serverID, _, err := st.createServer("renew-1", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "500")

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	sess := &agentSession{serverID: serverID, conn: serverConn, enc: json.NewEncoder(serverConn), pending: map[string]chan proto.TaskEvent{}}

	clientDec := json.NewDecoder(clientConn)
	respCh := make(chan proto.Envelope, 1)
	go func() {
		var env proto.Envelope
		if err := clientDec.Decode(&env); err == nil {
			respCh <- env
		}
	}()

	gw.handleRenewRequest(sess, serverID, "500", &proto.RenewRequest{CSRPEM: testCSR(t, "irrelevant-requested-cn")})

	var env proto.Envelope
	select {
	case env = <-respCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for renew response")
	}
	if env.Type != proto.MsgRenewResponse || env.RenewResponse == nil {
		t.Fatalf("got envelope %+v, want a renew_response", env)
	}
	if env.RenewResponse.Error != "" {
		t.Fatalf("unexpected renewal error: %s", env.RenewResponse.Error)
	}

	block, _ := pem.Decode([]byte(env.RenewResponse.CertPEM))
	if block == nil {
		t.Fatal("renewed cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	// The CommonName must come from the authenticated session's server_id,
	// never from the CSR's requested subject — otherwise an agent could
	// rename itself (or claim another server's identity) on renewal.
	if cert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CN = %q, want %q (server_id), not the CSR's requested CN", cert.Subject.CommonName, serverID)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: gw.ca.certPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("renewed cert does not verify against the CA: %v", err)
	}

	if !st.isRevoked("500") {
		t.Fatal("old cert serial should be revoked after renewal")
	}
	newSerial := cert.SerialNumber.String()
	if st.isRevoked(newSerial) {
		t.Fatal("newly issued cert serial should not be revoked")
	}
	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server should still exist")
	}
	if rec.CertSerial != newSerial {
		t.Fatalf("server's cert_serial = %q, want %q", rec.CertSerial, newSerial)
	}
}

// TestHandleRenewRequestRejectsInvalidCSR verifies a malformed CSR gets a
// structured Error back over the session rather than a crash or a silently
// dropped request, and never rotates anything.
func TestHandleRenewRequestRejectsInvalidCSR(t *testing.T) {
	gw, st := newTestGateway(t)
	serverID, _, err := st.createServer("renew-2", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "600")

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	sess := &agentSession{serverID: serverID, conn: serverConn, enc: json.NewEncoder(serverConn), pending: map[string]chan proto.TaskEvent{}}

	clientDec := json.NewDecoder(clientConn)
	respCh := make(chan proto.Envelope, 1)
	go func() {
		var env proto.Envelope
		if err := clientDec.Decode(&env); err == nil {
			respCh <- env
		}
	}()

	gw.handleRenewRequest(sess, serverID, "600", &proto.RenewRequest{CSRPEM: "not a csr"})

	var env proto.Envelope
	select {
	case env = <-respCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for renew response")
	}
	if env.RenewResponse == nil || env.RenewResponse.Error == "" {
		t.Fatalf("got %+v, want a RenewResponse with a non-empty Error", env.RenewResponse)
	}
	if st.isRevoked("600") {
		t.Fatal("a rejected renewal must not revoke the still-valid current certificate")
	}
	rec, _ := st.get(serverID)
	if rec.CertSerial != "600" {
		t.Fatalf("cert_serial changed to %q after a rejected renewal, want unchanged \"600\"", rec.CertSerial)
	}
}
