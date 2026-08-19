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

// enrolledAgent is a real, fully registered agent identity: a keypair whose
// CSR went through the actual /agents/register endpoint and came back with
// a certificate signed by the real in-process CA.
type enrolledAgent struct {
	serverID string
	cert     tls.Certificate
	serial   string
}

func newCSR(t *testing.T) (csrPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pending-registration"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

// enrollAgent creates a server record and runs the real bootstrap-token →
// certificate exchange against the real /agents/register handler, so the
// certificate under test is issued exactly the way a production agent's is.
func enrollAgent(t *testing.T, a *apiServer, name string) enrolledAgent {
	t.Helper()
	serverID, token, err := a.store.createServer(name, "", nil, time.Hour, "test@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	csrPEM, key := newCSR(t)
	rec := doJSON(t, a.routes(), "POST", "/agents/register",
		map[string]string{"token": token, "csr_pem": string(csrPEM)}, nil)
	if rec.Code != 200 {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ServerID string `json:"server_id"`
		CertPEM  string `json:"cert_pem"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(resp.CertPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatalf("build keypair: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if leaf.Subject.CommonName != serverID {
		t.Fatalf("issued certificate CommonName = %q, want the server ID %q", leaf.Subject.CommonName, serverID)
	}

	return enrolledAgent{serverID: serverID, cert: cert, serial: leaf.SerialNumber.String()}
}

// startGateway binds the real mTLS gateway on an ephemeral port and serves
// it for the duration of the test.
func startGateway(t *testing.T, a *apiServer) net.Listener {
	t.Helper()
	ln, err := a.gw.listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("gateway listen: %v", err)
	}
	// Cleanups run last-registered-first, so this one runs after the test's
	// agent connections are closed but before newTestStore closes the
	// database. Waiting for sessions to drain matters: handleConn logs the
	// disconnect on its own goroutine, and letting that race the database
	// close produces spurious "AUDIT LOG WRITE FAILED" output that would
	// make a genuine audit-write failure easy to dismiss as test noise.
	t.Cleanup(func() {
		ln.Close()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			a.gw.mu.Lock()
			n := len(a.gw.sessions)
			a.gw.mu.Unlock()
			if n == 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	go a.gw.serve(ln)
	return ln
}

// dialAgent opens a real mTLS session to the gateway and completes the
// hello/ack handshake, returning the codecs for the established session.
func dialAgent(t *testing.T, a *apiServer, ln net.Listener, agent enrolledAgent) (*json.Encoder, *json.Decoder, net.Conn) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(a.ca.CAPEM()) {
		t.Fatal("could not build CA pool from the control plane's own CA PEM")
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{agent.cert},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("agent mTLS dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := enc.Encode(proto.Envelope{
		Type: proto.MsgHello, Hello: &proto.Hello{ServerID: agent.serverID, AgentVersion: "test"},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("read session ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("expected an ack from the gateway, got %q", ack.Type)
	}
	return enc, dec, conn
}

func requestRenewal(t *testing.T, enc *json.Encoder, dec *json.Decoder, conn net.Conn) proto.RenewResponse {
	t.Helper()
	csrPEM, _ := newCSR(t)
	if err := enc.Encode(proto.Envelope{
		Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)},
	}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var env proto.Envelope
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("read renew response: %v", err)
	}
	if env.Type != proto.MsgRenewResponse || env.RenewResponse == nil {
		t.Fatalf("expected a renew_response, got %q", env.Type)
	}
	return *env.RenewResponse
}

// waitForCertSerial polls the server record until its cert_serial reaches
// want. The renewal commit happens on the gateway's own goroutine after it
// reads the ack, so the test has to wait for it rather than assume it
// already ran.
func waitForCertSerial(t *testing.T, a *apiServer, serverID, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if rec, ok := a.store.get(serverID); ok && rec.CertSerial == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	rec, _ := a.store.get(serverID)
	t.Fatalf("cert_serial never became %q (still %q)", want, rec.CertSerial)
}

// TestCertificateRenewalOverMTLS is the full rotation flow against a real
// mTLS gateway, a real CA, and a real database: request → signed successor
// → the old certificate is still valid → ack → the old certificate is
// revoked and the new one is the server's certificate of record.
func TestCertificateRenewalOverMTLS(t *testing.T) {
	a := newTestAPIServer(t)
	ln := startGateway(t, a)
	agent := enrollAgent(t, a, "renew-1")
	enc, dec, conn := dialAgent(t, a, ln, agent)

	resp := requestRenewal(t, enc, dec, conn)
	if resp.Error != "" {
		t.Fatalf("renewal refused: %s", resp.Error)
	}
	if resp.CertPEM == "" {
		t.Fatal("renewal returned an empty certificate")
	}
	if resp.CAPEM == "" {
		t.Fatal("renewal response should carry the CA certificate so an agent can still verify the gateway")
	}

	block, _ := pem.Decode([]byte(resp.CertPEM))
	if block == nil {
		t.Fatal("renewed certificate is not valid PEM")
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed certificate: %v", err)
	}
	// The successor must be bound to the same identity the session
	// authenticated as — this is the property that stops an agent renewing
	// its way into a different server's identity.
	if newCert.Subject.CommonName != agent.serverID {
		t.Fatalf("renewed certificate CommonName = %q, want %q", newCert.Subject.CommonName, agent.serverID)
	}
	newSerial := newCert.SerialNumber.String()
	if newSerial == agent.serial {
		t.Fatal("renewal reused the old serial number")
	}
	if !newCert.NotAfter.After(time.Now().Add(20 * 24 * time.Hour)) {
		t.Fatalf("renewed certificate expires at %s, sooner than a full fresh TTL", newCert.NotAfter)
	}

	// Before the agent confirms, nothing may have changed: an agent that
	// dies here must still be able to reconnect with the certificate it has.
	if a.store.isRevoked(agent.serial) {
		t.Fatal("the old certificate was revoked before the agent confirmed it persisted the new one")
	}
	if rec, _ := a.store.get(agent.serverID); rec.CertSerial != agent.serial {
		t.Fatalf("cert_serial changed to %q before the agent's confirmation", rec.CertSerial)
	}

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewAck}); err != nil {
		t.Fatalf("send renew ack: %v", err)
	}
	waitForCertSerial(t, a, agent.serverID, newSerial)

	if !a.store.isRevoked(agent.serial) {
		t.Fatal("the superseded certificate should be revoked once the renewal is confirmed")
	}
	if a.store.isRevoked(newSerial) {
		t.Fatal("the new certificate must not be revoked")
	}
}

// TestRenewalRefusedTwiceOnOneSession covers the per-session cap: one
// renewal per connection, so a misbehaving agent can't churn serial numbers
// and revocation-list entries in a loop.
func TestRenewalRefusedTwiceOnOneSession(t *testing.T) {
	a := newTestAPIServer(t)
	ln := startGateway(t, a)
	agent := enrollAgent(t, a, "renew-2")
	enc, dec, conn := dialAgent(t, a, ln, agent)

	first := requestRenewal(t, enc, dec, conn)
	if first.Error != "" {
		t.Fatalf("first renewal refused: %s", first.Error)
	}
	block, _ := pem.Decode([]byte(first.CertPEM))
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed certificate: %v", err)
	}
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewAck}); err != nil {
		t.Fatalf("send renew ack: %v", err)
	}
	waitForCertSerial(t, a, agent.serverID, newCert.SerialNumber.String())

	second := requestRenewal(t, enc, dec, conn)
	if second.Error == "" {
		t.Fatal("a second renewal on the same session should be refused")
	}
	if second.CertPEM != "" {
		t.Fatal("a refused renewal must not return a certificate")
	}
}

// TestRenewalRefusedForRevokedCert proves a revoked agent cannot renew its
// way back into the fleet through a session that was already open when the
// revocation landed.
func TestRenewalRefusedForRevokedCert(t *testing.T) {
	a := newTestAPIServer(t)
	ln := startGateway(t, a)
	agent := enrollAgent(t, a, "renew-3")
	enc, dec, conn := dialAgent(t, a, ln, agent)

	if err := a.store.revokeServer(agent.serverID, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}

	resp := requestRenewal(t, enc, dec, conn)
	if resp.Error == "" {
		t.Fatal("a revoked certificate must not be renewable")
	}
	if resp.CertPEM != "" {
		t.Fatal("a refused renewal must not return a certificate")
	}
}

// TestRenewAckWithoutRequestIsIgnored covers the ordering guard: an ack
// that doesn't correspond to an issued certificate must not revoke
// anything, since that would be a one-message way to strand a server.
func TestRenewAckWithoutRequestIsIgnored(t *testing.T) {
	a := newTestAPIServer(t)
	ln := startGateway(t, a)
	agent := enrollAgent(t, a, "renew-4")
	enc, _, _ := dialAgent(t, a, ln, agent)

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewAck}); err != nil {
		t.Fatalf("send renew ack: %v", err)
	}
	// Give the gateway a chance to (incorrectly) act on it before asserting.
	time.Sleep(200 * time.Millisecond)

	if a.store.isRevoked(agent.serial) {
		t.Fatal("an unsolicited renew ack revoked the agent's certificate")
	}
	if rec, _ := a.store.get(agent.serverID); rec.CertSerial != agent.serial {
		t.Fatalf("an unsolicited renew ack changed cert_serial to %q", rec.CertSerial)
	}
}
