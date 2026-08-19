package main

import (
	"bufio"
	"context"
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

// startTestGateway brings up a real mTLS gateway on an ephemeral port and
// returns it with its address. These tests exercise the actual TLS
// handshake and revocation check rather than a stub, because that
// handshake *is* the agent trust boundary.
func startTestGateway(t *testing.T) (*gateway, *store, *agentCA, string) {
	t.Helper()

	st := newTestStore(t)
	ca, err := newAgentCA()
	if err != nil {
		t.Fatalf("newAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	certPEM, keyPEM, err := ca.signServerCert([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("signServerCert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
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

	return gw, st, ca, ln.Addr().String()
}

// enrollAgent creates a server record, redeems its token, and returns a
// client TLS certificate for it — the same path a real registration takes.
func enrollAgent(t *testing.T, st *store, ca *agentCA, name string) (serverID string, clientCert tls.Certificate, serial string) {
	t.Helper()

	id, token, err := st.createServer(name, "", nil, time.Minute, "t@e.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	if _, err := st.redeemToken(token); err != nil {
		t.Fatalf("redeemToken: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, sn, err := ca.signAgentCSR(csrPEM, id, time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(id, sn.String())

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return id, pair, sn.String()
}

func dialGateway(t *testing.T, addr string, ca *agentCA, clientCert tls.Certificate) (*tls.Conn, error) {
	t.Helper()
	return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	})
}

// TestGatewayAcceptsEnrolledAgent is the happy path, and also establishes
// the baseline the revocation test contrasts against.
func TestGatewayAcceptsEnrolledAgent(t *testing.T) {
	gw, st, ca, addr := startTestGateway(t)
	id, clientCert, _ := enrollAgent(t, st, ca, "good-agent")

	conn, err := dialGateway(t, addr, ca, clientCert)
	if err != nil {
		t.Fatalf("enrolled agent could not connect: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	if err := enc.Encode(proto.Envelope{
		Type:  proto.MsgHello,
		Hello: &proto.Hello{ServerID: id, AgentVersion: "test-1.0"},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	// The gateway acks an accepted session.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ack proto.Envelope
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&ack); err != nil {
		t.Fatalf("did not receive session ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Errorf("first gateway message = %q, want %q", ack.Type, proto.MsgAck)
	}

	waitFor(t, 2*time.Second, func() bool {
		rec, ok := st.get(id)
		return ok && rec.Status == statusConnected
	}, "server never reached connected status")

	// Agent version reported in Hello must be recorded, not just logged.
	rec, _ := st.get(id)
	if rec.AgentVer != "test-1.0" {
		t.Errorf("AgentVer = %q, want %q", rec.AgentVer, "test-1.0")
	}
	_ = gw
}

// TestGatewayRejectsRevokedCertificate is the revocation guarantee:
// a certificate that is still cryptographically valid and unexpired must
// be refused once revoked.
func TestGatewayRejectsRevokedCertificate(t *testing.T) {
	_, st, ca, addr := startTestGateway(t)
	id, clientCert, _ := enrollAgent(t, st, ca, "to-be-revoked")

	// Sanity: it works before revocation.
	conn, err := dialGateway(t, addr, ca, clientCert)
	if err != nil {
		t.Fatalf("precondition: agent should connect before revocation: %v", err)
	}
	conn.Close()

	if err := st.revokeServer(id, "t@e.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}

	// The TLS handshake itself may still succeed (the cert is signed by a
	// trusted CA and unexpired) — the gateway must close the session
	// anyway, so the agent never gets its ack.
	conn2, err := dialGateway(t, addr, ca, clientCert)
	if err != nil {
		return // refused outright: also an acceptable outcome
	}
	defer conn2.Close()

	conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ack proto.Envelope
	if err := json.NewDecoder(bufio.NewReader(conn2)).Decode(&ack); err == nil && ack.Type == proto.MsgAck {
		t.Fatal("gateway accepted a session from a revoked certificate")
	}
}

// TestGatewayRejectsUntrustedCA covers an agent presenting a well-formed
// certificate from a CA this control plane does not trust.
func TestGatewayRejectsUntrustedCA(t *testing.T) {
	_, st, ca, addr := startTestGateway(t)

	// A second, unrelated CA — think a stolen/forged agent identity.
	rogueCA, err := newAgentCA()
	if err != nil {
		t.Fatalf("newAgentCA: %v", err)
	}
	id, _, _ := enrollAgent(t, st, ca, "legit")
	_ = id

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	rogueCertPEM, _, _ := rogueCA.signAgentCSR(csrPEM, id, time.Hour)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	rogueKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	rogueCert, _ := tls.X509KeyPair(rogueCertPEM, rogueKeyPEM)

	conn, err := dialGateway(t, addr, ca, rogueCert)
	if err != nil {
		return // handshake rejected, as expected
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ack proto.Envelope
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&ack); err == nil && ack.Type == proto.MsgAck {
		t.Fatal("gateway accepted a certificate signed by an untrusted CA")
	}
}

// TestDispatchToDisconnectedServerFails makes sure a task aimed at an
// offline server reports a clear error instead of hanging.
func TestDispatchToDisconnectedServerFails(t *testing.T) {
	gw, st, _, _ := startTestGateway(t)
	id, _, _ := st.createServer("offline", "", nil, time.Minute, "t@e.com")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := gw.dispatch(ctx, id, "t@e.com", "system.ping", nil); err == nil {
		t.Error("dispatch to a disconnected server succeeded")
	}
	_ = gw
}

func waitFor(t *testing.T, limit time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}
