package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// testCSR generates a throwaway ECDSA CSR, mirroring what
// apps/agent/register.go's generateKeyAndCSR produces — the control plane
// never trusts anything in the CSR's requested subject, only the caller-
// supplied server_id, so the CommonName here is deliberately wrong/unused
// to prove that.
func testCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "not-trusted-by-the-ca"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

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

func TestRenewAgentCertIssuesFreshCertBoundToServerID(t *testing.T) {
	gw, st := newTestGateway(t)
	id, _, err := st.createServer("web-renew-1", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(id, "1000") // simulate the cert issued at registration

	resp := gw.renewAgentCert(id, "1000", &proto.RenewRequest{CSRPEM: string(testCSR(t))})
	if resp.Error != "" {
		t.Fatalf("renewAgentCert returned error: %s", resp.Error)
	}
	if resp.CertPEM == "" || resp.CAPEM == "" {
		t.Fatal("renewAgentCert response missing cert_pem/ca_pem")
	}

	block, _ := pem.Decode([]byte(resp.CertPEM))
	if block == nil {
		t.Fatal("renewed cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if cert.Subject.CommonName != id {
		t.Fatalf("renewed cert CommonName = %q, want %q (server_id, not the CSR's requested subject)", cert.Subject.CommonName, id)
	}
	newSerial := cert.SerialNumber.String()
	if newSerial == "1000" {
		t.Fatal("renewed cert must have a new serial, not reuse the old one")
	}

	rec, ok := st.get(id)
	if !ok || rec.CertSerial != newSerial {
		t.Fatalf("store cert_serial = %+v, want %q", rec, newSerial)
	}

	// Old cert must not be revoked yet — only once the agent is actually
	// seen using the new one.
	if st.isRevoked("1000") {
		t.Fatal("old serial should not be revoked immediately after renewal")
	}
	st.promotePendingRevocation(id, newSerial)
	if !st.isRevoked("1000") {
		t.Fatal("old serial should be revoked once the agent connects with the new one")
	}

	found := false
	for _, e := range st.auditLog() {
		if e.Action == "agent.cert_renewed" && strings.Contains(e.Detail, newSerial) {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an agent.cert_renewed audit entry naming the new serial")
	}
}

func TestRenewAgentCertRejectsMalformedCSR(t *testing.T) {
	gw, st := newTestGateway(t)
	id, _, err := st.createServer("web-renew-2", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(id, "2000")

	resp := gw.renewAgentCert(id, "2000", &proto.RenewRequest{CSRPEM: "not a real CSR"})
	if resp.Error == "" {
		t.Fatal("expected an error for a malformed CSR")
	}
	if resp.CertPEM != "" {
		t.Fatal("no certificate should be issued for a malformed CSR")
	}

	rec, ok := st.get(id)
	if !ok || rec.CertSerial != "2000" {
		t.Fatalf("cert_serial should be unchanged after a rejected renewal, got %+v", rec)
	}
}
