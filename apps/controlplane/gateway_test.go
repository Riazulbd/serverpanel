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
	"path/filepath"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// genAgentCSR mirrors apps/agent/register.go's generateKeyAndCSR (that
// package is `main` and can't be imported here, so the minimal CSR-building
// logic is duplicated for the test) — the CSR's subject is a placeholder;
// the CA never trusts it, matching production behavior exercised below.
func genAgentCSR(t *testing.T) (csrPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test-agent"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func keyToPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// freeAddr reserves and immediately releases a loopback TCP port. There is
// an inherent (tiny) TOCTOU window before the gateway binds it, acceptable
// for a test.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// dialAgent completes a full mTLS handshake against the gateway as an agent
// already holding certPEM/keyPEM, retrying briefly since listenAndServe's
// goroutine may not have bound the port yet.
func dialAgent(t *testing.T, addr string, ca *agentCA, certPEM, keyPEM []byte) net.Conn {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load agent keypair: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca.certPool(),
		MinVersion:   tls.VersionTLS13,
	}

	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 500 * time.Millisecond}, "tcp", addr, cfg)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dial gateway at %s: %v", addr, lastErr)
	return nil
}

func TestGatewayRenewIssuesFreshCertOverExistingSession(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	serverID, _, err := st.createServer("web-1", "prod", nil, 15*time.Minute, "test-actor")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	// Enroll the agent directly against the CA/store (equivalent to what
	// handleRegister does for a real POST /agents/register), since this
	// test is only exercising the persistent mTLS gateway, not the HTTP
	// bootstrap endpoint.
	csrPEM, key := genAgentCSR(t)
	certPEM, serial, err := ca.signAgentCSR(csrPEM, serverID, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String())
	keyPEM := keyToPEM(t, key)

	addr := freeAddr(t)
	go gw.listenAndServe(addr)

	conn := dialAgent(t, addr, ca, certPEM, keyPEM)
	defer conn.Close()

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

	rec, ok := st.get(serverID)
	if !ok || rec.CertSerial != serial.String() {
		t.Fatalf("store cert_serial before renewal = %q, want %q", rec.CertSerial, serial.String())
	}

	// Request a renewal, as renew.go's checkAndRenew does when the
	// certificate is close to expiry.
	newCSRPEM, _ := genAgentCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenew, Renew: &proto.RenewRequest{CSRPEM: string(newCSRPEM)}}); err != nil {
		t.Fatalf("send renew: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var renewed proto.Envelope
	if err := dec.Decode(&renewed); err != nil {
		t.Fatalf("decode renewed: %v", err)
	}
	if renewed.Type != proto.MsgRenewed || renewed.Renewed == nil {
		t.Fatalf("expected a renewed envelope, got %+v", renewed)
	}
	if renewed.Renewed.Error != "" {
		t.Fatalf("gateway rejected renewal: %s", renewed.Renewed.Error)
	}

	block, _ := pem.Decode([]byte(renewed.Renewed.CertPEM))
	if block == nil {
		t.Fatal("renewed cert_pem did not decode as PEM")
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CN = %q, want %q", newCert.Subject.CommonName, serverID)
	}
	if newCert.SerialNumber.Cmp(serial) == 0 {
		t.Fatal("renewed cert reused the old serial number")
	}
	if !newCert.NotAfter.After(time.Now().Add(29 * 24 * time.Hour)) {
		t.Fatalf("renewed cert NotAfter = %v, want ~30 days out", newCert.NotAfter)
	}

	rec, ok = st.get(serverID)
	if !ok {
		t.Fatal("server disappeared from store")
	}
	if rec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("store cert_serial after renewal = %q, want %q", rec.CertSerial, newCert.SerialNumber.String())
	}
	// The old serial must not have been revoked by renewal (see
	// handleRenew's comment: the previous cert stays valid until its own
	// natural expiry, so a crash before the new cert reaches disk doesn't
	// brick the agent).
	if st.isRevoked(serial.String()) {
		t.Fatal("renewal revoked the previous certificate; it should remain valid until its own expiry")
	}

	// The still-open connection (authenticated with the *old* cert) must
	// remain usable — a heartbeat sent right after renewal should not be
	// rejected, confirming renewal doesn't disrupt the live session.
	if err := enc.Encode(proto.Envelope{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{SentAt: time.Now().UTC()}}); err != nil {
		t.Fatalf("send heartbeat after renewal: %v", err)
	}
}
