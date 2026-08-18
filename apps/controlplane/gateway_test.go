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

// newTestCA returns a bare agentCA for tests that don't need the full
// apiServer wiring newTestAPIServer builds.
func newTestCA(t *testing.T) *agentCA {
	t.Helper()
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	return ca
}

func testCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// newPipedSession wires an agentSession's encoder to one end of an in-memory
// net.Pipe, with the other end returned as a plain json.Decoder — enough to
// exercise handleRenew's real read/encode path without a real mTLS socket.
func newPipedSession(serverID string) (*agentSession, *json.Decoder, func()) {
	client, server := net.Pipe()
	sess := &agentSession{
		serverID: serverID,
		conn:     server,
		enc:      json.NewEncoder(server),
		pending:  map[string]chan proto.TaskEvent{},
	}
	dec := json.NewDecoder(client)
	return sess, dec, func() { client.Close(); server.Close() }
}

func TestHandleRenewIssuesFreshCertBoundToServerID(t *testing.T) {
	st := newTestStore(t)
	ca := newTestCA(t)
	gw := newGateway(ca, st)

	serverID, _, err := st.createServer("srv-1", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "111")
	st.setConnected(serverID, true)

	sess, dec, cleanup := newPipedSession(serverID)
	defer cleanup()

	done := make(chan struct{})
	go func() {
		gw.handleRenew(sess, serverID, proto.RenewRequest{CSRPEM: string(testCSR(t, "irrelevant"))})
		close(done)
	}()

	var env proto.Envelope
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	<-done

	if env.Type != proto.MsgRenewResponse || env.RenewResponse == nil {
		t.Fatalf("got envelope %+v, want a renew_response", env)
	}
	if env.RenewResponse.Error != "" {
		t.Fatalf("renewal was rejected: %s", env.RenewResponse.Error)
	}

	block, _ := pem.Decode([]byte(env.RenewResponse.CertPEM))
	if block == nil {
		t.Fatal("returned cert_pem did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	// The CA must bind CommonName to the authenticated session's server ID,
	// never to whatever the CSR's own (attacker-influenced) subject asked
	// for — mirrors the same defense signAgentCSR already applies to the
	// initial registration path (see ca.go).
	if cert.Subject.CommonName != serverID {
		t.Errorf("issued cert CommonName = %q, want %q (CSR's requested CN must be ignored)", cert.Subject.CommonName, serverID)
	}
	if time.Until(cert.NotAfter) < 29*24*time.Hour {
		t.Errorf("issued cert NotAfter = %s, want ~%s out", cert.NotAfter, agentCertTTL)
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record vanished")
	}
	if rec.CertSerial == "111" || rec.CertSerial == "" {
		t.Errorf("cert_serial was not updated to the newly issued serial, still %q", rec.CertSerial)
	}
	if rec.Status != statusConnected {
		t.Errorf("handleRenew must not disturb a live agent's connected status, got %q", rec.Status)
	}
}

func TestHandleRenewRejectsMalformedCSRWithoutIssuingACert(t *testing.T) {
	st := newTestStore(t)
	ca := newTestCA(t)
	gw := newGateway(ca, st)
	serverID, _, err := st.createServer("srv-2", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "222")

	sess, dec, cleanup := newPipedSession(serverID)
	defer cleanup()

	go gw.handleRenew(sess, serverID, proto.RenewRequest{CSRPEM: "not a csr"})

	var env proto.Envelope
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	if env.RenewResponse == nil || env.RenewResponse.Error == "" {
		t.Fatalf("expected an error response for a malformed CSR, got %+v", env.RenewResponse)
	}
	if env.RenewResponse.CertPEM != "" {
		t.Error("a rejected renewal must not also return a certificate")
	}

	rec, _ := st.get(serverID)
	if rec.CertSerial != "222" {
		t.Errorf("cert_serial changed to %q despite a rejected renewal", rec.CertSerial)
	}
}
