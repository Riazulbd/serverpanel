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

func csrPEMFor(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// TestHandleRenewRequestIssuesNewCertAndUpdatesStore exercises the gateway
// side of agent certificate renewal end to end (minus the mTLS transport
// itself, which agentSession abstracts away): a connected agent's CSR
// should be signed for its own server_id and the store's cert_serial
// updated, without ever touching connection status.
func TestHandleRenewRequestIssuesNewCertAndUpdatesStore(t *testing.T) {
	gw, st := newTestGateway(t)
	serverID, _, err := st.createServer("renew-test", "", nil, time.Hour, "tester")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	before, ok := st.get(serverID)
	if !ok {
		t.Fatalf("server %s not found after creation", serverID)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	sess := &agentSession{serverID: serverID, conn: serverConn, enc: json.NewEncoder(serverConn), pending: map[string]chan proto.TaskEvent{}}

	respCh := make(chan proto.Envelope, 1)
	go func() {
		dec := json.NewDecoder(clientConn)
		var env proto.Envelope
		_ = dec.Decode(&env)
		respCh <- env
	}()

	gw.handleRenewRequest(sess, serverID, proto.RenewRequest{CSRPEM: csrPEMFor(t, "irrelevant-cn-should-be-ignored")})

	select {
	case env := <-respCh:
		if env.Type != proto.MsgRenewResponse || env.RenewResponse == nil {
			t.Fatalf("unexpected envelope: %+v", env)
		}
		if env.RenewResponse.Error != "" {
			t.Fatalf("unexpected renewal error: %s", env.RenewResponse.Error)
		}
		block, _ := pem.Decode([]byte(env.RenewResponse.CertPEM))
		if block == nil {
			t.Fatal("renewal response certificate is not valid PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse renewed certificate: %v", err)
		}
		// The issued certificate must be bound to the connection's actual
		// server_id (from the mTLS-derived session), never to whatever
		// subject the CSR itself requested.
		if cert.Subject.CommonName != serverID {
			t.Fatalf("renewed cert CN = %q, want %q (must ignore CSR-requested subject)", cert.Subject.CommonName, serverID)
		}
		after, ok := st.get(serverID)
		if !ok {
			t.Fatalf("server %s not found after renewal", serverID)
		}
		if after.CertSerial != cert.SerialNumber.String() {
			t.Fatalf("store cert_serial = %s, want %s", after.CertSerial, cert.SerialNumber.String())
		}
		if after.CertSerial == before.CertSerial {
			t.Fatal("cert_serial should have changed after renewal")
		}
		if after.Status != before.Status {
			t.Fatalf("renewal must not change connection status: was %s, now %s", before.Status, after.Status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for renewal response")
	}
}

// TestHandleRenewRequestRejectsInvalidCSR ensures a malformed CSR gets a
// structured error response rather than crashing the session, and that the
// store's cert_serial is left untouched.
func TestHandleRenewRequestRejectsInvalidCSR(t *testing.T) {
	gw, st := newTestGateway(t)
	serverID, _, err := st.createServer("renew-invalid-test", "", nil, time.Hour, "tester")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	before, _ := st.get(serverID)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	sess := &agentSession{serverID: serverID, conn: serverConn, enc: json.NewEncoder(serverConn), pending: map[string]chan proto.TaskEvent{}}

	respCh := make(chan proto.Envelope, 1)
	go func() {
		dec := json.NewDecoder(clientConn)
		var env proto.Envelope
		_ = dec.Decode(&env)
		respCh <- env
	}()

	gw.handleRenewRequest(sess, serverID, proto.RenewRequest{CSRPEM: "not a csr"})

	select {
	case env := <-respCh:
		if env.RenewResponse == nil || env.RenewResponse.Error == "" {
			t.Fatal("expected a renewal error for an invalid CSR")
		}
		if env.RenewResponse.CertPEM != "" {
			t.Fatal("no certificate should be issued for an invalid CSR")
		}
		after, _ := st.get(serverID)
		if after.CertSerial != before.CertSerial {
			t.Fatal("cert_serial must not change when renewal is rejected")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for renewal response")
	}
}
