package capabilities

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseCertbotCertificatesSingleCert(t *testing.T) {
	out := `Saved the following certificates:
  Certificate Name: example.com
    Serial Number: 3ddeadbeef
    Key Type: ECDSA
    Domains: example.com www.example.com
    Expiry Date: 2026-11-23 10:15:32+00:00 (VALID: 89 days)
    Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem
`
	certs := parseCertbotCertificates(out)
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	c := certs[0]
	if c.Name != "example.com" {
		t.Errorf("Name = %q, want example.com", c.Name)
	}
	if len(c.Domains) != 2 || c.Domains[0] != "example.com" || c.Domains[1] != "www.example.com" {
		t.Errorf("Domains = %v, want [example.com www.example.com]", c.Domains)
	}
	if !c.Valid {
		t.Error("Valid = false, want true (output said VALID)")
	}
	want := time.Date(2026, 11, 23, 10, 15, 32, 0, time.UTC)
	if !c.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", c.ExpiresAt, want)
	}
}

func TestParseCertbotCertificatesMultipleCertsAndExpired(t *testing.T) {
	out := `Found the following certs:
  Certificate Name: a.example.com
    Domains: a.example.com
    Expiry Date: 2020-01-01 00:00:00+00:00 (INVALID: EXPIRED)
    Certificate Path: /etc/letsencrypt/live/a.example.com/fullchain.pem

  Certificate Name: b.example.com
    Domains: b.example.com
    Expiry Date: 2027-01-01 00:00:00+00:00 (VALID: 120 days)
    Certificate Path: /etc/letsencrypt/live/b.example.com/fullchain.pem
`
	certs := parseCertbotCertificates(out)
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	if certs[0].Valid {
		t.Error("first cert Valid = true, want false (output said INVALID)")
	}
	if !certs[1].Valid {
		t.Error("second cert Valid = false, want true")
	}
}

func TestParseCertbotCertificatesNoCerts(t *testing.T) {
	certs := parseCertbotCertificates("No certificates found.\n")
	if len(certs) != 0 {
		t.Fatalf("got %d certs, want 0", len(certs))
	}
}

func TestAnnotateExpiryMatchesDomainCaseInsensitively(t *testing.T) {
	out := `  Certificate Name: example.com
    Domains: Example.com
    Expiry Date: 2026-11-23 10:15:32+00:00 (VALID: 89 days)
`
	result := &sslResult{Domain: "example.com"}
	if !annotateExpiry(result, out) {
		t.Fatal("annotateExpiry returned false, want true")
	}
	if result.Status != "active" {
		t.Errorf("Status = %q, want active", result.Status)
	}
	if result.DaysLeft <= 0 {
		t.Errorf("DaysLeft = %d, want > 0 for a cert expiring in 2026", result.DaysLeft)
	}
}

func TestAnnotateExpiryNoMatchReturnsFalse(t *testing.T) {
	out := `  Certificate Name: other.com
    Domains: other.com
    Expiry Date: 2026-11-23 10:15:32+00:00 (VALID: 89 days)
`
	result := &sslResult{Domain: "example.com", Status: "unknown"}
	if annotateExpiry(result, out) {
		t.Fatal("annotateExpiry returned true, want false (no matching domain)")
	}
	if result.Status != "unknown" {
		t.Errorf("Status was mutated to %q on a non-match", result.Status)
	}
}

// selfSignedCert generates an in-memory ECDSA self-signed cert/key pair
// expiring at notAfter, for exercising validateCertKeyPair without shelling
// out to openssl or touching the filesystem.
func selfSignedCert(t *testing.T, notAfter time.Time) (certPEM, keyPEM string, priv *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, priv
}

func TestValidateCertKeyPairAcceptsMatchingPair(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	certPEM, keyPEM, _ := selfSignedCert(t, notAfter)

	got, err := validateCertKeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("validateCertKeyPair: %v", err)
	}
	if got.Sub(notAfter).Abs() > time.Second {
		t.Errorf("NotAfter = %v, want ~%v", got, notAfter)
	}
}

func TestValidateCertKeyPairRejectsMismatchedKey(t *testing.T) {
	certPEM, _, _ := selfSignedCert(t, time.Now().Add(90*24*time.Hour))
	_, otherKeyPEM, _ := selfSignedCert(t, time.Now().Add(90*24*time.Hour))

	if _, err := validateCertKeyPair(certPEM, otherKeyPEM); err == nil {
		t.Fatal("expected a mismatched cert/key pair to be rejected")
	}
}

func TestValidateCertKeyPairRejectsExpiredCert(t *testing.T) {
	certPEM, keyPEM, _ := selfSignedCert(t, time.Now().Add(-24*time.Hour))

	_, err := validateCertKeyPair(certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected an already-expired certificate to be rejected")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %q, want it to mention expiry", err.Error())
	}
}

func TestHandleSSLIssueLetsEncryptRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{
		"domain": "not a domain; rm -rf /", "email": "ops@example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLIssueLetsEncryptRejectsMissingEmail(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{
		"domain": "example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected a missing email to be rejected")
	}
	if !strings.Contains(err.Error(), "email is required") {
		t.Fatalf("error = %q, want it to mention email", err.Error())
	}
}

func TestHandleSSLCheckRenewalRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLCheckRenewal(context.Background(), map[string]any{
		"domain": "../../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLInstallCustomRejectsInvalidDomain(t *testing.T) {
	certPEM, keyPEM, _ := selfSignedCert(t, time.Now().Add(90*24*time.Hour))
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "not a domain", "cert_pem": certPEM, "key_pem": keyPEM,
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLInstallCustomRejectsMismatchedPairBeforeTouchingFilesystem(t *testing.T) {
	certPEM, _, _ := selfSignedCert(t, time.Now().Add(90*24*time.Hour))
	_, otherKeyPEM, _ := selfSignedCert(t, time.Now().Add(90*24*time.Hour))

	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "example.com", "cert_pem": certPEM, "key_pem": otherKeyPEM,
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a mismatched cert/key pair to be rejected")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error = %q, want it to mention validation failure", err.Error())
	}
}

func TestHandleSSLInstallCustomRejectsMissingParams(t *testing.T) {
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected missing cert_pem/key_pem to be rejected")
	}
}
