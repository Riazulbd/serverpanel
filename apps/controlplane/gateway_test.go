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
	"net"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// genKeyAndCSR mirrors what the real agent does in apps/agent/cert.go
// (unimportable here — it's a separate `package main`), so these gateway
// tests drive the real wire protocol exactly as a real agent would.
func genKeyAndCSR(t *testing.T, cn string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func tlsClientCert(t *testing.T, key *ecdsa.PrivateKey, certPEM []byte) tls.Certificate {
	t.Helper()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build tls certificate: %v", err)
	}
	return cert
}

// dialGateway performs a real mTLS handshake against a running gateway
// listener and exchanges Hello/Ack, returning the live connection and
// decoder/encoder for the test to drive further. If the gateway rejects
// the session (e.g. a revoked certificate), ackErr is non-nil instead.
func dialGateway(t *testing.T, addr string, cert tls.Certificate, caPEM []byte, serverID string) (conn net.Conn, enc *json.Encoder, dec *json.Decoder, ackErr error) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("could not parse CA PEM")
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}

	enc = json.NewEncoder(conn)
	dec = json.NewDecoder(conn)
	if err := enc.Encode(proto.Envelope{Type: proto.MsgHello, Hello: &proto.Hello{ServerID: serverID, AgentVersion: "test"}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	var ack proto.Envelope
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := dec.Decode(&ack); err != nil {
		return conn, enc, dec, err
	}
	if ack.Type != proto.MsgAck {
		t.Fatalf("expected ack, got %q", ack.Type)
	}
	conn.SetReadDeadline(time.Time{})
	return conn, enc, dec, nil
}

// TestGatewayCertificateRenewalRoundTrip drives the actual wire protocol —
// real mTLS handshakes against a real gateway listener, not a mock — for
// the full lifecycle: register, renew before expiry, reconnect with the
// renewed certificate, then revoke the server and confirm BOTH the
// original and the renewed certificate stop working. That last step is
// the exact gap store.renewCert/revokeServer close: without recording
// every issued serial, a pre-renewal certificate would keep authenticating
// after the server was supposedly revoked.
func TestGatewayCertificateRenewalRoundTrip(t *testing.T) {
	a := newTestAPIServer(t)
	h := a.routes()

	id, token, err := a.store.createServer("web-renew-e2e", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	// Real registration over the public HTTP handler, exactly like the
	// agent's register() does.
	origKey, origCSR := genKeyAndCSR(t, "pending-registration")
	rec := doJSON(t, h, "POST", "/agents/register", map[string]string{"token": token, "csr_pem": origCSR}, nil)
	if rec.Code != 200 {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var regResp struct {
		ServerID string `json:"server_id"`
		CertPEM  string `json:"cert_pem"`
		CAPEM    string `json:"ca_pem"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &regResp); err != nil {
		t.Fatalf("parse register response: %v", err)
	}
	if regResp.ServerID != id {
		t.Fatalf("registered server_id = %q, want %q", regResp.ServerID, id)
	}
	origCert := tlsClientCert(t, origKey, []byte(regResp.CertPEM))
	origBlock, _ := pem.Decode([]byte(regResp.CertPEM))
	origParsed, err := x509.ParseCertificate(origBlock.Bytes)
	if err != nil {
		t.Fatalf("parse original cert: %v", err)
	}
	origSerial := origParsed.SerialNumber.String()

	// Bring up the real mTLS gateway listener on an ephemeral port.
	ln, err := a.gw.listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("gw.listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go a.gw.serve(ln)

	conn, enc, dec, ackErr := dialGateway(t, ln.Addr().String(), origCert, []byte(regResp.CAPEM), id)
	if ackErr != nil {
		t.Fatalf("initial session should be accepted: %v", ackErr)
	}
	defer conn.Close()

	// Request renewal over the live, already-authenticated session.
	newKey, newCSR := genKeyAndCSR(t, "pending-renewal")
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: newCSR}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}
	var renewEnv proto.Envelope
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := dec.Decode(&renewEnv); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	conn.SetReadDeadline(time.Time{})
	if renewEnv.Type != proto.MsgRenewResponse || renewEnv.RenewResponse == nil {
		t.Fatalf("expected renew_response, got %q", renewEnv.Type)
	}
	if renewEnv.RenewResponse.Error != "" {
		t.Fatalf("gateway declined renewal: %s", renewEnv.RenewResponse.Error)
	}
	newCertPEM := renewEnv.RenewResponse.CertPEM
	if newCertPEM == "" {
		t.Fatal("renewal response carried no certificate")
	}
	newBlock, _ := pem.Decode([]byte(newCertPEM))
	newParsed, err := x509.ParseCertificate(newBlock.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	newSerial := newParsed.SerialNumber.String()
	if newSerial == origSerial {
		t.Fatal("renewed certificate must have a different serial than the original")
	}

	// The store's view of the server's current certificate must reflect
	// the renewal, and the superseded certificate must still be usable
	// (renewal must never lock an agent out mid-rotation).
	srvRec, ok := a.store.get(id)
	if !ok {
		t.Fatal("server should still exist")
	}
	if srvRec.CertSerial != newSerial {
		t.Fatalf("store cert_serial = %q, want %q", srvRec.CertSerial, newSerial)
	}
	if a.store.isRevoked(origSerial) {
		t.Fatal("original serial must not be revoked immediately after renewal")
	}

	// The renewed certificate must actually work end-to-end against the
	// gateway — a fresh connection using it should be accepted.
	newTLSCert := tlsClientCert(t, newKey, []byte(newCertPEM))
	conn2, _, _, ackErr2 := dialGateway(t, ln.Addr().String(), newTLSCert, []byte(regResp.CAPEM), id)
	if ackErr2 != nil {
		t.Fatalf("session with renewed certificate should be accepted: %v", ackErr2)
	}
	conn2.Close()

	// Now revoke the server. Both the original and the renewed certificate
	// must stop working — this is the actual security property renewCert/
	// revokeServer exist to guarantee.
	if err := a.store.revokeServer(id, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}
	if !a.store.isRevoked(origSerial) {
		t.Fatal("original (pre-renewal) serial should be revoked after revokeServer")
	}
	if !a.store.isRevoked(newSerial) {
		t.Fatal("renewed serial should be revoked after revokeServer")
	}

	if _, _, _, err := dialGateway(t, ln.Addr().String(), origCert, []byte(regResp.CAPEM), id); err == nil {
		t.Fatal("a connection using the original (now-revoked) certificate should be rejected after revokeServer")
	}
	if _, _, _, err := dialGateway(t, ln.Addr().String(), newTLSCert, []byte(regResp.CAPEM), id); err == nil {
		t.Fatal("a connection using the renewed (now-revoked) certificate should be rejected after revokeServer")
	}
}

// TestGatewayRenewRequestRejectsMalformedCSR confirms a bad CSR gets a
// structured error back over the wire rather than the connection being
// silently dropped or the store being left inconsistent.
func TestGatewayRenewRequestRejectsMalformedCSR(t *testing.T) {
	a := newTestAPIServer(t)
	h := a.routes()

	id, token, err := a.store.createServer("web-renew-bad-csr", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	origKey, origCSR := genKeyAndCSR(t, "pending-registration")
	rec := doJSON(t, h, "POST", "/agents/register", map[string]string{"token": token, "csr_pem": origCSR}, nil)
	if rec.Code != 200 {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var regResp struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	json.Unmarshal(rec.Body.Bytes(), &regResp)
	origCert := tlsClientCert(t, origKey, []byte(regResp.CertPEM))

	ln, err := a.gw.listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("gw.listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go a.gw.serve(ln)

	conn, enc, dec, ackErr := dialGateway(t, ln.Addr().String(), origCert, []byte(regResp.CAPEM), id)
	if ackErr != nil {
		t.Fatalf("initial session should be accepted: %v", ackErr)
	}
	defer conn.Close()

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: "not a csr"}}); err != nil {
		t.Fatalf("send renew request: %v", err)
	}
	var renewEnv proto.Envelope
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := dec.Decode(&renewEnv); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	if renewEnv.RenewResponse == nil || renewEnv.RenewResponse.Error == "" {
		t.Fatal("expected an error in the renew response for a malformed CSR")
	}

	srvRec, ok := a.store.get(id)
	if !ok || srvRec.CertSerial == "" {
		t.Fatal("server's original certificate serial should be untouched after a failed renewal")
	}
}
