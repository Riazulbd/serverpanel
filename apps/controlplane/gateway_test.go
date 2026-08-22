package main

import (
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

// genTestCSR builds a throwaway ECDSA keypair + CSR for gateway tests, the
// same shape apps/agent/register.go and renew.go produce.
func genTestCSR(t *testing.T, cn string) (csrPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return csrPEM, keyPEM
}

// startTestGateway spins up a real TLS listener on an OS-assigned port
// running gw.handleConn per connection — mirroring gateway.listenAndServe,
// which can't be reused directly here because it blocks forever in its own
// accept loop and never exposes the port it bound.
func startTestGateway(t *testing.T, ca *agentCA, gw *gateway) string {
	t.Helper()
	certPEM, keyPEM, err := ca.signServerCert([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("signServerCert: %v", err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go gw.handleConn(conn)
		}
	}()
	return ln.Addr().String()
}

func TestGatewayRenewCertOverExistingSession(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	serverID, _, err := st.createServer("renew-1", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	initialCSR, initialKeyPEM := genTestCSR(t, "pending-registration")
	initialCertPEM, initialSerial, err := ca.signAgentCSR(initialCSR, serverID, time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, initialSerial.String())

	addr := startTestGateway(t, ca, gw)

	clientCert, err := tls.X509KeyPair(initialCertPEM, initialKeyPEM)
	if err != nil {
		t.Fatalf("client X509KeyPair: %v", err)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil || ack.Type != proto.MsgAck {
		t.Fatalf("expected session ack, got %+v (err=%v)", ack, err)
	}

	// Deliberately request a CommonName different from the real server_id —
	// proves the CA binds the renewed cert's identity to the authenticated
	// session, never to whatever the agent puts in its CSR.
	renewalCSR, _ := genTestCSR(t, "attacker-supplied-identity")
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCertRequest{CSRPEM: string(renewalCSR)}}); err != nil {
		t.Fatalf("send renew_cert: %v", err)
	}

	var result proto.Envelope
	if err := dec.Decode(&result); err != nil {
		t.Fatalf("decode cert_renewed: %v", err)
	}
	if result.Type != proto.MsgCertRenewed || result.CertRenewed == nil {
		t.Fatalf("expected cert_renewed envelope, got %+v", result)
	}
	if result.CertRenewed.Error != "" {
		t.Fatalf("renewal rejected: %s", result.CertRenewed.Error)
	}
	if result.CertRenewed.CertPEM == "" {
		t.Fatal("renewed cert PEM is empty")
	}

	block, _ := pem.Decode([]byte(result.CertRenewed.CertPEM))
	if block == nil {
		t.Fatal("renewed cert did not decode as PEM")
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (must come from the session identity, not the CSR)", newCert.Subject.CommonName, serverID)
	}
	if newCert.SerialNumber.String() == initialSerial.String() {
		t.Fatal("renewed cert should have a new serial number, not reuse the original one")
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server should still exist")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("stored cert_serial = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}
	if rec.Status != statusConnected {
		t.Fatalf("status after renewal = %q, want %q (renewal must not disturb the live connection's status)", rec.Status, statusConnected)
	}
}

func TestGatewayRenewCertRejectsMalformedCSR(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	serverID, _, err := st.createServer("renew-2", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	initialCSR, initialKeyPEM := genTestCSR(t, "pending-registration")
	initialCertPEM, initialSerial, err := ca.signAgentCSR(initialCSR, serverID, time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, initialSerial.String())

	addr := startTestGateway(t, ca, gw)
	clientCert, err := tls.X509KeyPair(initialCertPEM, initialKeyPEM)
	if err != nil {
		t.Fatalf("client X509KeyPair: %v", err)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil || ack.Type != proto.MsgAck {
		t.Fatalf("expected session ack, got %+v (err=%v)", ack, err)
	}

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCertRequest{CSRPEM: "not a csr"}}); err != nil {
		t.Fatalf("send renew_cert: %v", err)
	}
	var result proto.Envelope
	if err := dec.Decode(&result); err != nil {
		t.Fatalf("decode cert_renewed: %v", err)
	}
	if result.CertRenewed == nil || result.CertRenewed.Error == "" {
		t.Fatalf("expected an error result for a malformed CSR, got %+v", result.CertRenewed)
	}
	if result.CertRenewed.CertPEM != "" {
		t.Fatal("a rejected renewal must not include a certificate")
	}

	// The server's on-record cert serial must be unchanged.
	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server should still exist")
	}
	if rec.CertSerial != initialSerial.String() {
		t.Fatalf("cert_serial changed after a rejected renewal: got %q, want unchanged %q", rec.CertSerial, initialSerial.String())
	}

	// The connection itself must remain usable after a rejected renewal
	// (the gateway must not tear down the session over a bad CSR).
	if err := enc.Encode(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{SentAt: time.Now().UTC()}}); err != nil {
		t.Fatalf("session should still be usable after a rejected renewal: %v", err)
	}
}
