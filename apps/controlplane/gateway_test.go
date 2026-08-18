package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"
)

func newTestCSR(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// TestHandleRenewIssuesCertBoundToSessionIdentity verifies that renewal
// binds the new certificate's CommonName to the serverID the caller passes
// in (which gateway.handleConn derives from the session's already-verified
// mTLS peer certificate) rather than to whatever CommonName the CSR itself
// requests — otherwise a compromised agent could renew its way into a
// different server's identity.
func TestHandleRenewIssuesCertBoundToSessionIdentity(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	serverID, _, err := st.createServer("web-1", "", nil, time.Minute, "tester@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(serverID, "1")
	st.setConnected(serverID, true)

	csrPEM := newTestCSR(t, "attacker-claimed-identity")
	resp := gw.handleRenew(serverID, csrPEM)
	if resp.Error != "" {
		t.Fatalf("handleRenew returned error: %s", resp.Error)
	}
	if resp.CertPEM == "" {
		t.Fatal("handleRenew returned no certificate")
	}

	block, _ := pem.Decode([]byte(resp.CertPEM))
	if block == nil {
		t.Fatal("issued certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if cert.Subject.CommonName != serverID {
		t.Fatalf("issued certificate CommonName = %q, want %q (the CSR-requested name must be ignored)", cert.Subject.CommonName, serverID)
	}
	if time.Until(cert.NotAfter) < agentCertTTL-time.Minute {
		t.Fatalf("issued certificate NotAfter too soon: %s", cert.NotAfter)
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record disappeared")
	}
	if rec.CertSerial != cert.SerialNumber.String() {
		t.Fatalf("store cert_serial = %q, want %q", rec.CertSerial, cert.SerialNumber.String())
	}
	if rec.Status != statusConnected {
		t.Fatalf("renewal must not disturb a live connection's status: got %q, want %q", rec.Status, statusConnected)
	}
}

// TestHandleRenewRejectsInvalidCSR verifies malformed input is reported as
// an error, not a panic or a silently-issued certificate.
func TestHandleRenewRejectsInvalidCSR(t *testing.T) {
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)

	serverID, _, err := st.createServer("web-2", "", nil, time.Minute, "tester@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	resp := gw.handleRenew(serverID, "not a csr")
	if resp.Error == "" {
		t.Fatal("expected an error for an invalid CSR, got none")
	}
	if resp.CertPEM != "" {
		t.Fatal("must not issue a certificate for an invalid CSR")
	}
}
