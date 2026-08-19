package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCSR(t *testing.T, requestedCN string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: requestedCN}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("issued certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	return cert
}

// TestAgentCannotChooseItsOwnIdentity is the key CSR guarantee: the CA
// stamps the CommonName from the validated server_id, so an agent cannot
// impersonate a different server by crafting its CSR subject.
func TestAgentCannotChooseItsOwnIdentity(t *testing.T) {
	ca, err := newAgentCA()
	if err != nil {
		t.Fatalf("newAgentCA: %v", err)
	}

	csr := testCSR(t, "srv_victim_server")
	certPEM, _, err := ca.signAgentCSR(csr, "srv_real_identity", time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}

	cert := parseCert(t, certPEM)
	if cert.Subject.CommonName != "srv_real_identity" {
		t.Errorf("issued CommonName = %q, want the server_id the CA was given (%q) — the CSR's requested subject must be ignored",
			cert.Subject.CommonName, "srv_real_identity")
	}
}

func TestSignAgentCSRRejectsGarbage(t *testing.T) {
	ca, _ := newAgentCA()
	for _, bad := range [][]byte{
		nil,
		[]byte("not pem at all"),
		[]byte("-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----\n"),
	} {
		if _, _, err := ca.signAgentCSR(bad, "srv_x", time.Hour); err == nil {
			t.Errorf("signAgentCSR accepted invalid CSR %q", string(bad))
		}
	}
}

// TestIssuedAgentCertIsClientAuthOnly stops an agent certificate from
// doubling as a server certificate.
func TestIssuedAgentCertIsClientAuthOnly(t *testing.T) {
	ca, _ := newAgentCA()
	certPEM, _, err := ca.signAgentCSR(testCSR(t, "x"), "srv_a", time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	cert := parseCert(t, certPEM)

	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("agent cert ExtKeyUsage = %v, want exactly [ClientAuth]", cert.ExtKeyUsage)
	}
	if cert.IsCA {
		t.Error("agent certificate is marked as a CA")
	}
}

func TestIssuedAgentCertHonoursTTL(t *testing.T) {
	ca, _ := newAgentCA()
	const ttl = 30 * 24 * time.Hour

	certPEM, _, _ := ca.signAgentCSR(testCSR(t, "x"), "srv_a", ttl)
	cert := parseCert(t, certPEM)

	got := time.Until(cert.NotAfter)
	if got > ttl+time.Minute || got < ttl-time.Hour {
		t.Errorf("certificate lifetime = %v, want about %v", got, ttl)
	}
}

func TestIssuedSerialsAreUnique(t *testing.T) {
	ca, _ := newAgentCA()
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		_, serial, err := ca.signAgentCSR(testCSR(t, "x"), "srv_a", time.Hour)
		if err != nil {
			t.Fatalf("signAgentCSR: %v", err)
		}
		if seen[serial.String()] {
			t.Fatalf("serial %s issued twice", serial)
		}
		seen[serial.String()] = true
	}
}

// TestGatewayCertCoversIPAndDNS pins the IP-SAN fix: agents dial the
// gateway by bare IP before any DNS exists, which fails verification if
// the certificate only carries DNS names.
func TestGatewayCertCoversIPAndDNS(t *testing.T) {
	ca, _ := newAgentCA()
	certPEM, _, err := ca.signServerCert([]string{"localhost", "127.0.0.1", "cp.example.test"})
	if err != nil {
		t.Fatalf("signServerCert: %v", err)
	}
	cert := parseCert(t, certPEM)

	if len(cert.IPAddresses) == 0 {
		t.Error("gateway certificate has no IP SANs; dialing by bare IP would fail verification")
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("gateway certificate does not verify for 127.0.0.1: %v", err)
	}
	if err := cert.VerifyHostname("cp.example.test"); err != nil {
		t.Errorf("gateway certificate does not verify for its DNS name: %v", err)
	}
}

// TestCAPersistsAcrossRestart covers the most serious bug found during
// integration testing: a CA regenerated on every start silently
// invalidates every already-registered agent's certificate.
func TestCAPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "agent-ca-cert.pem")
	keyPath := filepath.Join(dir, "agent-ca-key.pem")

	ca1, err := loadOrCreateAgentCA(certPath, keyPath, 1)
	if err != nil {
		t.Fatalf("first loadOrCreateAgentCA: %v", err)
	}
	agentCertPEM, _, err := ca1.signAgentCSR(testCSR(t, "x"), "srv_a", time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}

	// Simulate a control-plane restart.
	ca2, err := loadOrCreateAgentCA(certPath, keyPath, 1)
	if err != nil {
		t.Fatalf("second loadOrCreateAgentCA: %v", err)
	}

	// The certificate issued before the restart must still verify against
	// the reloaded CA — that is exactly what a reconnecting agent needs.
	roots := ca2.certPool()
	cert := parseCert(t, agentCertPEM)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("certificate issued before restart no longer verifies after reload: %v", err)
	}
}

// TestCAReseedsSerialsAboveKnownMax stops a reloaded CA from reissuing a
// serial that already appears in the revocation list.
func TestCAReseedsSerialsAboveKnownMax(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	if _, err := loadOrCreateAgentCA(certPath, keyPath, 1); err != nil {
		t.Fatalf("create CA: %v", err)
	}
	reloaded, err := loadOrCreateAgentCA(certPath, keyPath, 5000)
	if err != nil {
		t.Fatalf("reload CA: %v", err)
	}

	_, serial, err := reloaded.signAgentCSR(testCSR(t, "x"), "srv_a", time.Hour)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	if serial.Int64() < 5000 {
		t.Errorf("reloaded CA issued serial %s, below the known-max seed of 5000 — could collide with a revoked serial", serial)
	}
}

func TestCAKeyFileIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "agent-ca-key.pem")
	if _, err := loadOrCreateAgentCA(filepath.Join(dir, "agent-ca-cert.pem"), keyPath, 1); err != nil {
		t.Fatalf("create CA: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat CA key: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("CA private key mode = %04o, want no group/other access", perm)
	}
}
