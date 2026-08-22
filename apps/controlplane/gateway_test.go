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

// generateTestCSR mirrors what an agent generates in apps/agent/register.go
// and apps/agent/renew.go: a fresh ECDSA key plus a self-signed CSR for it.
// The requested CommonName is irrelevant — the CA always overrides it with
// the server ID validated server-side (see ca.go signAgentCSR).
func generateTestCSR(t *testing.T) (keyPEM, csrPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// testGateway wires a real gateway behind a real mTLS listener on an
// OS-assigned port, matching production wiring (newGateway + newTLSListener
// + serve) rather than calling handleConn's internals directly, so these
// tests exercise the actual wire protocol an agent speaks.
type testGateway struct {
	st *store
	ca *agentCA
	gw *gateway
	ln net.Listener
}

func newTestGateway(t *testing.T) *testGateway {
	t.Helper()
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)
	ln, err := gw.newTLSListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newTLSListener: %v", err)
	}
	go gw.serve(ln)
	t.Cleanup(func() { ln.Close() })
	return &testGateway{st: st, ca: ca, gw: gw, ln: ln}
}

// registerServer creates a server record and issues it an initial
// certificate directly via the CA, exactly what handleRegister does over
// HTTP — bypassing the HTTP layer since these tests are about the gateway's
// mTLS session handling, not registration.
func (tg *testGateway) registerServer(t *testing.T, name string) (serverID string, keyPEM, certPEM []byte, serial string) {
	t.Helper()
	id, _, err := tg.st.createServer(name, "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	keyPEM, csrPEM := generateTestCSR(t)
	certPEM, sn, notAfter, err := tg.ca.signAgentCSR(csrPEM, id, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	tg.st.markIssuedCert(id, sn.String(), notAfter)
	return id, keyPEM, certPEM, sn.String()
}

// dial opens a real mTLS connection to the gateway using the given identity
// and reads the initial session ack, mirroring apps/agent/connect.go.
func (tg *testGateway) dial(t *testing.T, keyPEM, certPEM []byte) (net.Conn, *json.Encoder, *json.Decoder) {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(tg.ca.rootCert)
	conn, err := tls.Dial("tcp", tg.ln.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(bufio.NewReader(conn))
	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("decode session ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("first message = %q, want ack", ack.Type)
	}
	return conn, enc, dec
}

func TestAgentCertRenewalIssuesNewCertAndRevokesOldOnAck(t *testing.T) {
	tg := newTestGateway(t)
	serverID, keyPEM, certPEM, oldSerial := tg.registerServer(t, "web-renew-1")
	_, enc, dec := tg.dial(t, keyPEM, certPEM)

	if tg.st.isRevoked(oldSerial) {
		t.Fatal("old cert should not be revoked before renewal")
	}

	_, renewCSR := generateTestCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(renewCSR)}}); err != nil {
		t.Fatalf("send renew_request: %v", err)
	}

	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode renew_response: %v", err)
	}
	if resp.Type != proto.MsgRenewResponse || resp.RenewResponse == nil {
		t.Fatalf("got %q, want renew_response", resp.Type)
	}
	if resp.RenewResponse.Error != "" {
		t.Fatalf("renewal rejected: %s", resp.RenewResponse.Error)
	}
	if resp.RenewResponse.CertPEM == "" {
		t.Fatal("renew_response carried no certificate")
	}
	if !resp.RenewResponse.NotAfter.After(time.Now()) {
		t.Fatalf("renewed cert NotAfter %v is not in the future", resp.RenewResponse.NotAfter)
	}

	newCertBlock, _ := pem.Decode([]byte(resp.RenewResponse.CertPEM))
	newCert, err := x509.ParseCertificate(newCertBlock.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	newSerial := newCert.SerialNumber.String()
	if newSerial == oldSerial {
		t.Fatal("renewed certificate reused the old serial number")
	}
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (must be server-assigned, not agent-requested)", newCert.Subject.CommonName, serverID)
	}

	// Before the ack, the DB reflects the new cert as current but the old
	// one is still valid (not revoked) — a lost/delayed ack must never
	// strand the agent with no working credential.
	rec, ok := tg.st.get(serverID)
	if !ok {
		t.Fatal("server record missing")
	}
	if rec.CertSerial != newSerial {
		t.Fatalf("store cert_serial = %q, want %q", rec.CertSerial, newSerial)
	}
	if tg.st.isRevoked(oldSerial) {
		t.Fatal("old cert must remain valid until renew_ack is received")
	}

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewAck, RenewAck: &proto.RenewAck{OK: true}}); err != nil {
		t.Fatalf("send renew_ack: %v", err)
	}

	// The ack is processed asynchronously by the gateway's read loop; poll
	// briefly rather than sleeping a fixed guess.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if tg.st.isRevoked(oldSerial) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old cert was never revoked after renew_ack")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if tg.st.isRevoked(newSerial) {
		t.Fatal("newly renewed cert must not itself be revoked")
	}
}

func TestReconnectWithRenewedCertSucceedsAndOldCertIsRejected(t *testing.T) {
	tg := newTestGateway(t)
	_, oldKeyPEM, oldCertPEM, oldSerial := tg.registerServer(t, "web-renew-2")
	conn, enc, dec := tg.dial(t, oldKeyPEM, oldCertPEM)

	// The renewal key stays with the agent throughout — only the CSR
	// derived from it is sent to the gateway, and only the signed
	// certificate comes back; the agent pairs that certificate with the
	// key it already holds, exactly as apps/agent/renew.go does.
	renewKeyPEM, renewCSR := generateTestCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(renewCSR)}}); err != nil {
		t.Fatalf("send renew_request: %v", err)
	}
	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode renew_response: %v", err)
	}
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewAck, RenewAck: &proto.RenewAck{OK: true}}); err != nil {
		t.Fatalf("send renew_ack: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !tg.st.isRevoked(oldSerial) {
		if time.Now().After(deadline) {
			t.Fatal("old cert never revoked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn.Close()

	newCert, err := tls.X509KeyPair([]byte(resp.RenewResponse.CertPEM), renewKeyPEM)
	if err != nil {
		t.Fatalf("pair renewed cert with its key: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(tg.ca.rootCert)
	if _, err := tls.Dial("tcp", tg.ln.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{newCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}); err != nil {
		t.Fatalf("reconnect with renewed cert: %v", err)
	}

	// The old cert must now be rejected outright.
	oldCert, err := tls.X509KeyPair(oldCertPEM, oldKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair(old): %v", err)
	}
	oldConn, err := tls.Dial("tcp", tg.ln.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{oldCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	})
	if err == nil {
		// The TLS handshake itself can succeed (revocation is an
		// application-level check in handleConn, not part of the TLS
		// verify callback) — the gateway must close the connection
		// immediately without ever sending the session ack.
		defer oldConn.Close()
		oldConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var env proto.Envelope
		if json.NewDecoder(oldConn).Decode(&env) == nil {
			t.Fatal("gateway sent a message to a connection using a revoked certificate")
		}
	}
}
