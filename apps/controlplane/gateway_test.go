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

// agentConn is a minimal stand-in for the real agent's side of the gateway
// protocol: enough to open a genuine mTLS session with a CA-issued client
// certificate and exchange envelopes. It exists so the renewal path is
// exercised over the real TLS listener and real certificate verification,
// not against a hand-rolled approximation of them.
type agentConn struct {
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
}

func (a *agentConn) send(t *testing.T, env proto.Envelope) {
	t.Helper()
	if err := a.enc.Encode(env); err != nil {
		t.Fatalf("send %s: %v", env.Type, err)
	}
}

func (a *agentConn) recv(t *testing.T) proto.Envelope {
	t.Helper()
	a.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var env proto.Envelope
	if err := a.dec.Decode(&env); err != nil {
		t.Fatalf("receive: %v", err)
	}
	return env
}

// newTestGateway starts a real mTLS gateway on an ephemeral port using the
// same tlsConfig() the production listener uses, and returns it with its
// address.
func newTestGateway(t *testing.T) (*gateway, *store, *agentCA, string) {
	t.Helper()
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(dir+"/ca-cert.pem", dir+"/ca-key.pem", 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	cfg, err := gw.tlsConfig()
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go gw.serve(ln)

	return gw, st, ca, ln.Addr().String()
}

// enrollAgent mints a client certificate for serverID the same way
// /agents/register does, and records it, returning the TLS keypair.
func enrollAgent(t *testing.T, ca *agentCA, st *store, serverID string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, serial, notAfter, err := ca.signAgentCSR(csrPEM, serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String(), notAfter)

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return pair, serial.String()
}

func dialGateway(t *testing.T, addr string, ca *agentCA, pair tls.Certificate) *agentConn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ac := &agentConn{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(bufio.NewReader(conn))}
	if env := ac.recv(t); env.Type != proto.MsgAck {
		t.Fatalf("expected session ack, got %q", env.Type)
	}
	return ac
}

func requestRenewal(t *testing.T, ac *agentConn) *proto.CertRenewResponse {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate renewal key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "renewal"}}, key)
	if err != nil {
		t.Fatalf("create renewal CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	ac.send(t, proto.Envelope{
		Type:             proto.MsgCertRenewRequest,
		CertRenewRequest: &proto.CertRenewRequest{CSRPEM: string(csrPEM)},
	})
	env := ac.recv(t)
	if env.Type != proto.MsgCertRenewResponse || env.CertRenewResponse == nil {
		t.Fatalf("expected a cert renew response, got %q", env.Type)
	}
	return env.CertRenewResponse
}

func TestCertRenewalOverMTLSIssuesANewCertificateForTheSameServer(t *testing.T) {
	gw, st, ca, addr := newTestGateway(t)
	_ = gw

	serverID, _, _ := st.createServer("web-renew", "", nil, time.Hour, "admin@example.com")
	pair, originalSerial := enrollAgent(t, ca, st, serverID)
	ac := dialGateway(t, addr, ca, pair)

	resp := requestRenewal(t, ac)
	if resp.Error != "" {
		t.Fatalf("renewal refused: %s", resp.Error)
	}
	if resp.Serial == originalSerial {
		t.Fatal("renewal returned the same serial; a renewal must be a new certificate")
	}

	block, _ := pem.Decode([]byte(resp.CertPEM))
	if block == nil {
		t.Fatal("renewal response did not contain a parseable certificate")
	}
	renewed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed certificate: %v", err)
	}

	// The identity must come from the authenticated connection, not from
	// anything the agent put in its CSR (whose CommonName was "renewal").
	if renewed.Subject.CommonName != serverID {
		t.Fatalf("renewed certificate CommonName = %q, want the connection's server ID %q",
			renewed.Subject.CommonName, serverID)
	}
	if !renewed.NotAfter.After(time.Now().Add(agentCertTTL - time.Hour)) {
		t.Fatalf("renewed certificate expires at %s, sooner than a full TTL from now", renewed.NotAfter)
	}

	rec, ok := st.get(serverID)
	if !ok || rec.CertSerial != resp.Serial {
		t.Fatalf("server's recorded cert_serial = %q, want the renewed serial %q", rec.CertSerial, resp.Serial)
	}
	// Renewal happens mid-session: it must not knock a connected server's
	// status back to offline.
	if rec.Status != statusConnected {
		t.Fatalf("status after renewal = %q, want %q", rec.Status, statusConnected)
	}

	// The superseded certificate is intentionally left valid so a renewal
	// the agent failed to persist is retryable rather than fatal.
	if st.isRevoked(originalSerial) {
		t.Fatal("the superseded certificate was revoked immediately; a failed persist would then brick the agent")
	}
}

func TestRevocationCoversEveryCertificateEverIssuedToAServer(t *testing.T) {
	_, st, ca, addr := newTestGateway(t)

	serverID, _, _ := st.createServer("web-revoke-all", "", nil, time.Hour, "admin@example.com")
	pair, originalSerial := enrollAgent(t, ca, st, serverID)
	ac := dialGateway(t, addr, ca, pair)

	resp := requestRenewal(t, ac)
	if resp.Error != "" {
		t.Fatalf("renewal refused: %s", resp.Error)
	}

	if err := st.revokeServer(serverID, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}

	// Both the current and the superseded certificate must be revoked: a
	// renewal leaves the old certificate valid, so revoking only the
	// current serial would leave a usable credential behind.
	if !st.isRevoked(resp.Serial) {
		t.Fatal("the current certificate was not revoked")
	}
	if !st.isRevoked(originalSerial) {
		t.Fatal("the superseded certificate survived revocation and could still be used to connect")
	}
}

func TestRevokedServerCannotRenewOnAnAlreadyOpenConnection(t *testing.T) {
	_, st, ca, addr := newTestGateway(t)

	serverID, _, _ := st.createServer("web-revoked-renew", "", nil, time.Hour, "admin@example.com")
	pair, _ := enrollAgent(t, ca, st, serverID)
	ac := dialGateway(t, addr, ca, pair)

	// Revoke after the session is already established — the handshake-time
	// revocation check has already passed for this connection, so renewal
	// has to refuse on its own.
	if err := st.revokeServer(serverID, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}

	resp := requestRenewal(t, ac)
	if resp.Error == "" {
		t.Fatal("a revoked server was able to mint itself a fresh certificate")
	}
	if resp.CertPEM != "" {
		t.Fatal("a refused renewal still returned a certificate")
	}
}

func TestRenewalRejectsAMalformedCSR(t *testing.T) {
	_, st, ca, addr := newTestGateway(t)

	serverID, _, _ := st.createServer("web-bad-csr", "", nil, time.Hour, "admin@example.com")
	pair, originalSerial := enrollAgent(t, ca, st, serverID)
	ac := dialGateway(t, addr, ca, pair)

	ac.send(t, proto.Envelope{
		Type:             proto.MsgCertRenewRequest,
		CertRenewRequest: &proto.CertRenewRequest{CSRPEM: "not a pem block at all"},
	})
	env := ac.recv(t)
	if env.CertRenewResponse == nil || env.CertRenewResponse.Error == "" {
		t.Fatalf("expected a refusal for a malformed CSR, got %+v", env.CertRenewResponse)
	}

	rec, _ := st.get(serverID)
	if rec.CertSerial != originalSerial {
		t.Fatalf("a failed renewal changed the recorded cert_serial to %q", rec.CertSerial)
	}
}
