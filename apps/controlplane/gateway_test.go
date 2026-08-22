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

// testCSR generates a throwaway ECDSA keypair and CSR, mirroring what the
// real agent (apps/agent/register.go newCSR) sends — kept local to this test
// file since apps/agent is an unimportable "package main".
func testCSR(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test-csr"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// newTestGatewayConn spins up a real mTLS gateway listener on an ephemeral
// port, issues a server an initial client certificate exactly the way
// registration does (ca.signAgentCSR + store.markIssuedCert), and returns an
// already-connected, already-acked mTLS session to it — the same starting
// point apps/agent/connect.go's runConnection reaches right before it enters
// its message loop.
func newTestGatewayConn(t *testing.T) (st *store, ca *agentCA, gw *gateway, serverID string, conn net.Conn, dec *json.Decoder, enc *json.Encoder) {
	t.Helper()
	st = newTestStore(t)
	dir := t.TempDir()
	var err error
	ca, err = loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw = newGateway(ca, st)

	ln, err := gw.tlsListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("tlsListener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go gw.serve(ln)

	serverID, _, err = st.createServer("web-gw-test", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	key, csrPEM := testCSR(t)
	certPEM, serial, err := ca.signAgentCSR(csrPEM, serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String())

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
	caPool.AddCert(ca.rootCert)
	dialCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}
	conn, err = tls.Dial("tcp", ln.Addr().String(), dialCfg)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	enc = json.NewEncoder(conn)
	dec = json.NewDecoder(bufio.NewReader(conn))

	if err := enc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: serverID, AgentVersion: "test"}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	var ack proto.Envelope
	if err := dec.Decode(&ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("expected ack, got %q", ack.Type)
	}

	return st, ca, gw, serverID, conn, dec, enc
}

func TestRenewRequestIssuesFreshCertAndUpdatesStore(t *testing.T) {
	st, _, _, serverID, _, dec, enc := newTestGatewayConn(t)

	origRec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server should exist")
	}
	origSerial := origRec.CertSerial

	_, csrPEM := testCSR(t)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}

	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	if resp.Type != proto.MsgRenewResponse || resp.RenewResponse == nil {
		t.Fatalf("expected renew_response, got %+v", resp)
	}
	if resp.RenewResponse.Error != "" {
		t.Fatalf("unexpected renewal error: %s", resp.RenewResponse.Error)
	}
	if resp.RenewResponse.CertPEM == "" {
		t.Fatal("renewal response carried no certificate")
	}

	block, _ := pem.Decode([]byte(resp.RenewResponse.CertPEM))
	if block == nil {
		t.Fatal("renewed certificate is not valid PEM")
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed certificate: %v", err)
	}
	if newCert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (must be bound to the authenticated session's identity)", newCert.Subject.CommonName, serverID)
	}
	if newCert.SerialNumber.String() == origSerial {
		t.Fatal("renewal should mint a new serial, not reuse the original one")
	}
	if got := time.Until(newCert.NotAfter); got < 29*24*time.Hour || got > agentCertTTL {
		t.Fatalf("renewed cert NotAfter %s from now, want ~%s", got, agentCertTTL)
	}

	newRec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server should still exist after renewal")
	}
	if newRec.CertSerial != newCert.SerialNumber.String() {
		t.Fatalf("store cert_serial = %q, want %q (should track the newly issued cert)", newRec.CertSerial, newCert.SerialNumber.String())
	}
	if st.isRevoked(origSerial) {
		t.Fatal("the pre-renewal certificate must not be revoked by a routine renewal")
	}
}

func TestRenewRequestRejectsMalformedCSR(t *testing.T) {
	st, _, _, serverID, _, dec, enc := newTestGatewayConn(t)
	origRec, _ := st.get(serverID)

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: "not a csr"}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}

	var resp proto.Envelope
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	if resp.RenewResponse == nil || resp.RenewResponse.Error == "" {
		t.Fatalf("expected a renewal error for a malformed CSR, got %+v", resp)
	}
	if resp.RenewResponse.CertPEM != "" {
		t.Fatal("a rejected renewal must not carry a certificate")
	}

	newRec, _ := st.get(serverID)
	if newRec.CertSerial != origRec.CertSerial {
		t.Fatal("a rejected renewal must not change the server's tracked cert_serial")
	}
}
