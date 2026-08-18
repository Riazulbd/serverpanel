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

// testCSR builds a throwaway PKCS#10 CSR requesting commonName as its
// Subject — used only to exercise renewAgentCert/signAgentCSR's own identity
// binding, since both are expected to ignore this requested Subject in favor
// of the server ID the caller already authenticated out of band.
func testCSR(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// registeredServer creates a server record and walks it through the same
// token-redeem + CSR-sign + markIssuedCert sequence handleRegister performs,
// returning its ID and initial cert serial, so renewal tests start from a
// realistic "already registered" state rather than a bare store row.
func registeredServer(t *testing.T, st *store, ca *agentCA) (serverID, initialSerial string) {
	t.Helper()
	_, token, err := st.createServer("test-server", "", nil, time.Minute, "tester@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	serverID, err = st.redeemToken(token)
	if err != nil {
		t.Fatalf("redeemToken: %v", err)
	}
	_, serial, err := ca.signAgentCSR(testCSR(t, "pending-registration"), serverID, agentCertTTL)
	if err != nil {
		t.Fatalf("signAgentCSR: %v", err)
	}
	st.markIssuedCert(serverID, serial.String())
	return serverID, serial.String()
}

func newTestCA(t *testing.T) *agentCA {
	t.Helper()
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	return ca
}

func TestRenewAgentCertIssuesFreshCertBoundToSameServerID(t *testing.T) {
	st := newTestStore(t)
	ca := newTestCA(t)
	gw := newGateway(ca, st)

	serverID, initialSerial := registeredServer(t, st, ca)

	newCertPEM, newSerial, err := gw.renewAgentCert(serverID, testCSR(t, "attacker-supplied-name"))
	if err != nil {
		t.Fatalf("renewAgentCert: %v", err)
	}
	if newSerial == initialSerial {
		t.Fatalf("renewal returned the same serial %q, expected a fresh one", newSerial)
	}

	block, _ := pem.Decode(newCertPEM)
	if block == nil {
		t.Fatal("renewed certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed certificate: %v", err)
	}
	// The CSR's requested Subject ("attacker-supplied-name") must be
	// completely ignored: the issued CommonName is always the session's
	// already-authenticated server ID.
	if cert.Subject.CommonName != serverID {
		t.Fatalf("renewed cert CommonName = %q, want %q (CSR's requested subject must be ignored)", cert.Subject.CommonName, serverID)
	}
	if got, want := time.Until(cert.NotAfter), agentCertTTL; got < want-time.Minute || got > want+time.Minute {
		t.Fatalf("renewed cert TTL = %s, want ~%s", got, want)
	}
}

func TestRenewAgentCertUpdatesStoreAndLeavesOldSerialUnrevoked(t *testing.T) {
	st := newTestStore(t)
	ca := newTestCA(t)
	gw := newGateway(ca, st)

	serverID, initialSerial := registeredServer(t, st, ca)

	_, newSerial, err := gw.renewAgentCert(serverID, testCSR(t, "pending-renewal"))
	if err != nil {
		t.Fatalf("renewAgentCert: %v", err)
	}

	rec, ok := st.get(serverID)
	if !ok {
		t.Fatal("server record disappeared")
	}
	if rec.CertSerial != newSerial {
		t.Fatalf("store's cert_serial = %q after renewal, want the new serial %q", rec.CertSerial, newSerial)
	}

	// The overlap window (see gateway.renewAgentCert's doc comment): the
	// previous cert must remain usable until it naturally expires, not be
	// revoked the instant a replacement is issued.
	if st.isRevoked(initialSerial) {
		t.Fatal("previous cert serial was revoked immediately on renewal; expected an overlap window instead")
	}
}

func TestRenewAgentCertRejectsUnknownServer(t *testing.T) {
	st := newTestStore(t)
	ca := newTestCA(t)
	gw := newGateway(ca, st)

	if _, _, err := gw.renewAgentCert("srv_does_not_exist", testCSR(t, "pending-renewal")); err == nil {
		t.Fatal("expected renewal for an unknown server_id to fail")
	}
}

func TestRenewAgentCertProducesUsableCertForFurtherRenewal(t *testing.T) {
	// Simulates two successive renewal cycles, proving the second renewal
	// works off the first renewal's state (not just the original
	// registration) — the kind of thing that would silently break if
	// renewAgentCert accidentally depended on registration-only fields.
	st := newTestStore(t)
	ca := newTestCA(t)
	gw := newGateway(ca, st)

	serverID, first := registeredServer(t, st, ca)

	_, second, err := gw.renewAgentCert(serverID, testCSR(t, "pending-renewal"))
	if err != nil {
		t.Fatalf("first renewal: %v", err)
	}
	_, third, err := gw.renewAgentCert(serverID, testCSR(t, "pending-renewal"))
	if err != nil {
		t.Fatalf("second renewal: %v", err)
	}

	if first == second || second == third || first == third {
		t.Fatalf("expected three distinct serials, got %q, %q, %q", first, second, third)
	}
	rec, _ := st.get(serverID)
	if rec.CertSerial != third {
		t.Fatalf("store's cert_serial = %q, want the latest serial %q", rec.CertSerial, third)
	}
}
