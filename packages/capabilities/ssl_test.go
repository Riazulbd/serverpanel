package capabilities

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateSelfSignedCert returns PEM-encoded cert/key bytes for a throwaway
// leaf certificate, so tests can exercise cert-parsing/matching logic
// without touching a real CA or the filesystem paths the agent uses on a
// live server. The certificate is signed by its own key (Issuer == Subject
// == commonName), matching how crypto/x509 actually reports a self-signed
// leaf regardless of the template's Issuer field.
func generateSelfSignedCert(t *testing.T, commonName string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// generateCertSignedBy issues a leaf certificate for commonName signed by a
// distinct CA key/cert, so its Issuer differs from its Subject — needed to
// actually exercise parseCertExpiry's issuer extraction.
func generateCertSignedBy(t *testing.T, commonName string, notAfter time.Time, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (certPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func generateCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return caCert, priv
}

func TestParseCertExpiryReadsRealExpiryAndIssuer(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	caCert, caKey := generateCA(t, "ServerPanel Test CA")
	certPEM := generateCertSignedBy(t, "example.com", notAfter, caCert, caKey)

	path := filepath.Join(t.TempDir(), "fullchain.pem")
	if err := os.WriteFile(path, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	got, issuer, err := parseCertExpiry(path)
	if err != nil {
		t.Fatalf("parseCertExpiry: %v", err)
	}
	if !got.Equal(notAfter) {
		t.Fatalf("parseCertExpiry expiry = %v, want %v", got, notAfter)
	}
	if issuer != "ServerPanel Test CA" {
		t.Fatalf("parseCertExpiry issuer = %q, want %q", issuer, "ServerPanel Test CA")
	}
}

func TestParseCertExpiryRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fullchain.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if _, _, err := parseCertExpiry(path); err == nil {
		t.Fatal("expected an error parsing a non-PEM file")
	}
}

func TestParseCertExpiryRejectsMissingFile(t *testing.T) {
	if _, _, err := parseCertExpiry(filepath.Join(t.TempDir(), "does-not-exist.pem")); err == nil {
		t.Fatal("expected an error for a missing certificate file")
	}
}

// TestHandleSSLInstallCustomRejectsMismatchedKey guards the fix in
// handleSSLInstallCustom: a certificate/key pair that don't match must be
// rejected *before* anything is written to disk or nginx is touched, so a
// bad upload never leaves a site half-configured with an unusable cert.
func TestHandleSSLInstallCustomRejectsMismatchedKey(t *testing.T) {
	certPEM, _ := generateSelfSignedCert(t, "a.example.com", time.Now().Add(90*24*time.Hour))
	_, otherKeyPEM := generateSelfSignedCert(t, "b.example.com", time.Now().Add(90*24*time.Hour))

	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "a.example.com", "cert_pem": string(certPEM), "key_pem": string(otherKeyPEM),
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a mismatched cert/key pair to be rejected")
	}
	if !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("error = %q, want it to mention the cert/key mismatch", err.Error())
	}
	// And nothing should have been written for a domain that was never
	// successfully installed.
	if _, statErr := os.Stat(customCertPath("a.example.com")); statErr == nil {
		os.RemoveAll(filepath.Dir(customCertPath("a.example.com")))
		t.Fatal("handleSSLInstallCustom wrote files to disk despite the mismatch")
	}
}

func TestHandleSSLInstallCustomRejectsMissingParams(t *testing.T) {
	if _, err := handleSSLInstallCustom(context.Background(), map[string]any{"domain": "example.com"}, func(string) {}); err == nil {
		t.Fatal("expected missing cert_pem/key_pem to be rejected")
	}
}

func TestHandleSSLInstallCustomRejectsInvalidDomain(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t, "x", time.Now().Add(time.Hour))
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "not a domain", "cert_pem": string(certPEM), "key_pem": string(keyPEM),
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLStatusReportsNoCertificateForUnknownDomain(t *testing.T) {
	_, err := handleSSLStatus(context.Background(), map[string]any{
		"domain": "never-issued-anything-for-this.example.invalid",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error when no certificate exists for the domain")
	}
	if !strings.Contains(err.Error(), "no certificate found") {
		t.Fatalf("error = %q, want it to say no certificate was found", err.Error())
	}
}

func TestHandleSSLStatusRejectsInvalidDomain(t *testing.T) {
	if _, err := handleSSLStatus(context.Background(), map[string]any{"domain": "../../etc/passwd"}, func(string) {}); err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLIssueLetsEncryptRejectsMissingEmail(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{"domain": "example.com"}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "email is required") {
		t.Fatalf("expected missing email to be rejected, got err=%v", err)
	}
}

// sslResult.json round-trips cleanly, since apps/controlplane parses it
// back with encoding/json against the same field names.
func TestSSLResultJSONShape(t *testing.T) {
	r := sslResult{Domain: "example.com", Source: "letsencrypt", ExpiresAt: "2030-01-01T00:00:00Z", Issuer: "R3"}
	got := r.json()
	for _, want := range []string{`"domain":"example.com"`, `"source":"letsencrypt"`, `"expires_at":"2030-01-01T00:00:00Z"`, `"issuer":"R3"`} {
		if !strings.Contains(got, want) {
			t.Errorf("sslResult.json() = %s, want it to contain %s", got, want)
		}
	}
}

// tls.X509KeyPair is exercised transitively above; this test documents the
// direct expectation it relies on (a matching pair parses cleanly) so a
// future refactor of handleSSLInstallCustom can't silently drop the check.
func TestMatchingCertAndKeyValidate(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t, "match.example.com", time.Now().Add(time.Hour))
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("expected a genuinely matching cert/key pair to validate: %v", err)
	}
}
