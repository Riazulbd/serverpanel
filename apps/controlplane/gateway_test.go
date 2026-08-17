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

// startTestGateway binds an ephemeral port and serves the given gateway on
// it, matching the real listenAndServe/serve split in gateway.go. Returns
// the bound address.
func startTestGateway(t *testing.T, gw *gateway) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go gw.serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// dialTestAgent signs a fresh client certificate for serverID (mirroring
// what handleRegister does for a real agent) and completes the mTLS +
// Hello/Ack handshake against addr, exactly as apps/agent/connect.go does.
// Returns the live connection/codec and the serial of the certificate that
// authenticated it.
func dialTestAgent(t *testing.T, a *apiServer, addr, serverID string) (net.Conn, *json.Encoder, *json.Decoder, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending-registration"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, serial, err := a.ca.signAgentCSR(csrPEM, serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	a.store.markIssuedCert(serverID, serial.String())

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(a.ca.rootCert)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := enc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: serverID, AgentVersion: "test"}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("expected ack, got %q", ack.Type)
	}
	conn.SetReadDeadline(time.Time{})

	return conn, enc, dec, serial.String()
}

// TestCertificateRenewalFlow drives the full agent-certificate-renewal
// protocol (proto.MsgRenewRequest -> MsgRenewResponse -> MsgRenewConfirm)
// over a real mTLS session against a real gateway, the way
// apps/agent/renewal.go does. It asserts the safety property the whole
// design hinges on: the certificate being replaced must NOT be revoked
// until the agent confirms it switched to the new one, so a dropped confirm
// can never lock an agent out.
func TestCertificateRenewalFlow(t *testing.T) {
	a := newTestAPIServer(t)
	serverID, _, err := a.store.createServer("renewal-test-server", "", nil, 15*time.Minute, "tester@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	addr := startTestGateway(t, a.gw)
	conn, enc, dec, oldSerial := dialTestAgent(t, a, addr, serverID)
	defer conn.Close()

	// Deliberately request a CSR subject that does NOT match serverID, the
	// way a compromised or buggy agent might — the gateway must bind the
	// renewed certificate to the identity of the session that requested it
	// (derived from the client cert that authenticated this connection),
	// never to whatever the CSR itself claims.
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "attacker-claimed-identity"}}, newKey)
	if err != nil {
		t.Fatalf("create renewal CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	conn.SetReadDeadline(time.Time{})
	if resp.Type != proto.MsgRenewResponse || resp.RenewResponse == nil {
		t.Fatalf("expected renew_response, got %+v", resp)
	}

	block, _ := pem.Decode([]byte(resp.RenewResponse.CertPEM))
	if block == nil {
		t.Fatalf("renewed cert is not valid PEM")
	}
	newLeaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if newLeaf.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (gateway must ignore the CSR's requested subject)", newLeaf.Subject.CommonName, serverID)
	}
	if newLeaf.SerialNumber.String() == oldSerial {
		t.Fatalf("renewed cert has the same serial as the certificate it replaces")
	}
	if resp.RenewResponse.ExpiresAt.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Fatalf("renewed cert ExpiresAt = %s, want ~30 days out", resp.RenewResponse.ExpiresAt)
	}

	if a.store.isRevoked(oldSerial) {
		t.Fatalf("old certificate serial was revoked before the agent confirmed the swap — this can lock an agent out on a dropped confirm")
	}

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewConfirm}); err != nil {
		t.Fatalf("send renew confirm: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !a.store.isRevoked(oldSerial) {
		time.Sleep(10 * time.Millisecond)
	}
	if !a.store.isRevoked(oldSerial) {
		t.Fatalf("old certificate serial was never revoked after the agent confirmed the swap")
	}
	if a.store.isRevoked(newLeaf.SerialNumber.String()) {
		t.Fatalf("newly issued certificate serial was unexpectedly revoked")
	}

	rec, ok := a.store.get(serverID)
	if !ok {
		t.Fatalf("server record not found")
	}
	if rec.CertSerial != newLeaf.SerialNumber.String() {
		t.Fatalf("store cert_serial = %s, want %s (the newly issued serial)", rec.CertSerial, newLeaf.SerialNumber.String())
	}
}

// TestServeReturnsOnClosedListener guards against a regression of a bug
// where gateway.serve's accept loop, on a closed listener, would spin
// forever (continue on every Accept error, including a permanent one)
// instead of returning — burning CPU and flooding logs rather than shutting
// down.
func TestServeReturnsOnClosedListener(t *testing.T) {
	a := newTestAPIServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- a.gw.serve(ln) }()

	// Give serve a moment to start accepting, then close the listener out
	// from under it.
	time.Sleep(50 * time.Millisecond)
	ln.Close()

	select {
	case <-done:
		// serve returned, as it should.
	case <-time.After(2 * time.Second):
		t.Fatalf("gateway.serve did not return after its listener was closed (busy-loop regression)")
	}
}

// TestRenewConfirmWithoutPendingRenewalIsNoop guards against a stray or
// duplicate MsgRenewConfirm (e.g. a retransmit) revoking a certificate that
// was never actually replaced.
func TestRenewConfirmWithoutPendingRenewalIsNoop(t *testing.T) {
	a := newTestAPIServer(t)
	serverID, _, err := a.store.createServer("no-pending-renewal-server", "", nil, 15*time.Minute, "tester@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	addr := startTestGateway(t, a.gw)
	conn, enc, _, serial := dialTestAgent(t, a, addr, serverID)
	defer conn.Close()

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewConfirm}); err != nil {
		t.Fatalf("send stray renew confirm: %v", err)
	}

	// Give the gateway goroutine a moment to process, then confirm nothing
	// was revoked.
	time.Sleep(100 * time.Millisecond)
	if a.store.isRevoked(serial) {
		t.Fatalf("a stray renew_confirm with no pending renewal revoked the live certificate")
	}
}
