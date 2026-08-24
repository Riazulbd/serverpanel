package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedCert builds a certificate with a chosen validity window, so the
// renewal threshold can be tested against real parsed certificates rather
// than a stubbed clock.
func selfSignedCert(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "srv_test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertNeedsRenewalTracksRemainingValidity(t *testing.T) {
	issued := time.Now().Add(-20 * 24 * time.Hour)
	expires := issued.Add(30 * 24 * time.Hour) // 10 days left of a 30-day cert

	freshCert := selfSignedCert(t, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	if certNeedsRenewal(freshCert, time.Now()) {
		t.Fatal("a freshly issued certificate should not be renewed yet")
	}

	// Either side of the 1/3-remaining threshold. Not tested at the exact
	// boundary: x509 truncates NotBefore/NotAfter to whole seconds, so the
	// parsed validity window differs from the requested one by up to a
	// second and an exact-edge assertion would be flaky rather than
	// meaningful.
	cert := selfSignedCert(t, issued, expires)
	if certNeedsRenewal(cert, expires.Add(-11*24*time.Hour)) {
		t.Fatal("a certificate with 11 of 30 days left should not renew yet")
	}
	if !certNeedsRenewal(cert, expires.Add(-9*24*time.Hour)) {
		t.Fatal("a certificate with only 9 of 30 days left should renew")
	}

	expired := selfSignedCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	if !certNeedsRenewal(expired, time.Now()) {
		t.Fatal("an already-expired certificate should be treated as needing renewal")
	}

	if certNeedsRenewal([]byte("not a certificate"), time.Now()) {
		t.Fatal("an unparseable certificate should not trigger a renewal request")
	}
}

func TestNewRenewalCSRProducesAFreshUsableKeypair(t *testing.T) {
	csrPEM, keyPEM, err := newRenewalCSR()
	if err != nil {
		t.Fatalf("newRenewalCSR: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR is not valid PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify: %v", err)
	}

	// Each renewal must rotate the private key, not just the expiry date.
	_, secondKeyPEM, err := newRenewalCSR()
	if err != nil {
		t.Fatalf("newRenewalCSR (second): %v", err)
	}
	if string(keyPEM) == string(secondKeyPEM) {
		t.Fatal("two renewals produced the same private key; renewal must rotate the key")
	}
}

func writeInitialIdentity(t *testing.T, dir string) {
	t.Helper()
	certPath, keyPath, caPath, metaPath := identityPaths(dir)
	for path, content := range map[string]string{
		certPath: "OLD CERT", keyPath: "OLD KEY", caPath: "CA",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	meta, _ := json.Marshal(identityMeta{
		ServerID: "srv_1", GatewayAddr: "gw:9443", CertFile: legacyCertFile, KeyFile: legacyKeyFile,
	})
	if err := os.WriteFile(metaPath, meta, 0600); err != nil {
		t.Fatalf("write identity.json: %v", err)
	}
}

func TestPersistRenewedIdentitySwitchesOverAtomically(t *testing.T) {
	dir := t.TempDir()
	writeInitialIdentity(t, dir)

	before, err := loadIdentity(dir)
	if err != nil {
		t.Fatalf("loadIdentity (before): %v", err)
	}
	if string(before.CertPEM) != "OLD CERT" || string(before.KeyPEM) != "OLD KEY" {
		t.Fatalf("unexpected initial identity: %q / %q", before.CertPEM, before.KeyPEM)
	}

	if err := persistRenewedIdentity(dir, "srv_1", "gw:9443", "201",
		[]byte("NEW CERT"), []byte("NEW KEY"), []byte("NEW CA")); err != nil {
		t.Fatalf("persistRenewedIdentity: %v", err)
	}

	after, err := loadIdentity(dir)
	if err != nil {
		t.Fatalf("loadIdentity (after): %v", err)
	}
	if string(after.CertPEM) != "NEW CERT" || string(after.KeyPEM) != "NEW KEY" {
		t.Fatalf("identity did not switch over: %q / %q", after.CertPEM, after.KeyPEM)
	}
	if string(after.CAPEM) != "NEW CA" {
		t.Fatalf("CA was not updated: %q", after.CAPEM)
	}
	if after.ServerID != "srv_1" || after.GatewayAddr != "gw:9443" {
		t.Fatalf("renewal lost identity metadata: %+v", after)
	}

	// The superseded pair must be cleaned up, and only after the pointer
	// switch — so what's left is exactly the new pair plus the non-identity
	// files.
	if _, err := os.Stat(filepath.Join(dir, legacyCertFile)); !os.IsNotExist(err) {
		t.Fatal("the superseded certificate file was left behind")
	}
	if _, err := os.Stat(filepath.Join(dir, legacyKeyFile)); !os.IsNotExist(err) {
		t.Fatal("the superseded key file was left behind")
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-cert-201.pem")); err != nil {
		t.Fatalf("the renewed certificate file is missing: %v", err)
	}
}

// A crash between writing the new files and committing the pointer must
// leave the previous identity fully usable — this is what lets the gateway
// safely keep the superseded certificate unrevoked.
func TestIdentitySurvivesACrashBeforeThePointerIsCommitted(t *testing.T) {
	dir := t.TempDir()
	writeInitialIdentity(t, dir)

	// Simulate the state after the new pair is written but before the
	// atomic rename of identity.json lands.
	if err := os.WriteFile(filepath.Join(dir, "agent-cert-301.pem"), []byte("NEW CERT"), 0600); err != nil {
		t.Fatalf("write partial cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent-key-301.pem"), []byte("NEW KEY"), 0600); err != nil {
		t.Fatalf("write partial key: %v", err)
	}
	meta, _ := json.Marshal(identityMeta{ServerID: "srv_1", GatewayAddr: "gw:9443",
		CertFile: "agent-cert-301.pem", KeyFile: "agent-key-301.pem"})
	if err := os.WriteFile(filepath.Join(dir, "identity.json.new"), meta, 0600); err != nil {
		t.Fatalf("write uncommitted pointer: %v", err)
	}

	id, err := loadIdentity(dir)
	if err != nil {
		t.Fatalf("loadIdentity after simulated crash: %v", err)
	}
	if string(id.CertPEM) != "OLD CERT" || string(id.KeyPEM) != "OLD KEY" {
		t.Fatalf("an uncommitted renewal took effect: %q / %q", id.CertPEM, id.KeyPEM)
	}
}

// An agent installed before renewal existed has no cert_file/key_file in
// its identity.json; it must keep working after an upgrade.
func TestLoadIdentityFallsBackToLegacyFilenames(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, caPath, metaPath := identityPaths(dir)
	os.WriteFile(certPath, []byte("CERT"), 0600)
	os.WriteFile(keyPath, []byte("KEY"), 0600)
	os.WriteFile(caPath, []byte("CA"), 0600)
	os.WriteFile(metaPath, []byte(`{"server_id":"srv_legacy","gateway_addr":"gw:9443"}`), 0600)

	id, err := loadIdentity(dir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if id.ServerID != "srv_legacy" || string(id.CertPEM) != "CERT" || string(id.KeyPEM) != "KEY" {
		t.Fatalf("legacy identity did not load correctly: %+v", id)
	}
}

// A renewal deliberately drops the connection so the new certificate takes
// effect at once. If the new certificate still read as near-expiry (a badly
// skewed clock, or a TTL shorter than the renewal threshold), that would
// become renew → reconnect → renew forever — a request flood against the
// gateway from a single misconfigured server. The gate bounds it.
func TestRenewalGateBoundsRepeatedAttempts(t *testing.T) {
	gate := newRenewalGate(6 * time.Hour)
	start := time.Now()

	if !gate.allow(start) {
		t.Fatal("the first renewal attempt should be allowed")
	}
	// The immediate reconnect after a renewal must not renew again.
	if gate.allow(start.Add(time.Millisecond)) {
		t.Fatal("a second renewal immediately after the first was allowed; this is the reconnect-loop failure mode")
	}
	if gate.allow(start.Add(5 * time.Hour)) {
		t.Fatal("a renewal well inside the minimum interval was allowed")
	}
	if !gate.allow(start.Add(6*time.Hour + time.Minute)) {
		t.Fatal("a renewal past the minimum interval should be allowed again")
	}
	// The window restarts from the attempt that was just allowed.
	if gate.allow(start.Add(6*time.Hour + 2*time.Minute)) {
		t.Fatal("the gate did not restart its window after allowing an attempt")
	}
}
