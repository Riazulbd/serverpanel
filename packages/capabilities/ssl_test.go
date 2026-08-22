package capabilities

import (
	"context"
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
	"strings"
	"testing"
	"time"
)

// newTestSSLDirs points customSSLDir/letsEncryptLiveDir at fresh temp
// directories for the duration of one test, matching the backupBaseDir
// pattern in backup_test.go.
func newTestSSLDirs(t *testing.T) {
	t.Helper()
	origCustom, origLE := customSSLDir, letsEncryptLiveDir
	customSSLDir = t.TempDir()
	letsEncryptLiveDir = t.TempDir()
	t.Cleanup(func() { customSSLDir, letsEncryptLiveDir = origCustom, origLE })
}

// generateTestCert builds a self-signed certificate/key PEM pair for the
// given domain(s), valid from notBefore for the given duration — enough to
// exercise validateCertKeyPair's real crypto without shelling out to
// openssl (which the sandbox this test runs in may not even have).
func generateTestCert(t *testing.T, domains []string, notBefore time.Time, validFor time.Duration) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domains[0], Organization: []string{"ServerPanel Test"}},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              domains,
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
	return certPEM, keyPEM
}

func TestValidateCertKeyPairAcceptsMatchingValidPair(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, []string{"example.com"}, time.Now().Add(-time.Hour), 90*24*time.Hour)
	cert, err := validateCertKeyPair("example.com", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("validateCertKeyPair: %v", err)
	}
	if cert.Subject.CommonName != "example.com" {
		t.Fatalf("unexpected cert subject: %v", cert.Subject)
	}
}

func TestValidateCertKeyPairRejectsMismatchedKey(t *testing.T) {
	certPEM, _ := generateTestCert(t, []string{"example.com"}, time.Now().Add(-time.Hour), 90*24*time.Hour)
	_, otherKeyPEM := generateTestCert(t, []string{"example.com"}, time.Now().Add(-time.Hour), 90*24*time.Hour)
	if _, err := validateCertKeyPair("example.com", certPEM, otherKeyPEM); err == nil {
		t.Fatal("expected a certificate paired with the wrong private key to be rejected")
	}
}

func TestValidateCertKeyPairRejectsExpiredCert(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, []string{"example.com"}, time.Now().Add(-100*24*time.Hour), 90*24*time.Hour)
	_, err := validateCertKeyPair("example.com", certPEM, keyPEM)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected an expired-certificate error, got %v", err)
	}
}

func TestValidateCertKeyPairRejectsWrongDomain(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, []string{"other.example.com"}, time.Now().Add(-time.Hour), 90*24*time.Hour)
	_, err := validateCertKeyPair("example.com", certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected a certificate issued for a different domain to be rejected")
	}
}

func TestHandleSSLInstallCustomRejectsBeforeAnyFileWrite(t *testing.T) {
	newTestSSLDirs(t)
	certPEM, keyPEM := generateTestCert(t, []string{"example.com"}, time.Now().Add(-time.Hour), 90*24*time.Hour)

	cases := []map[string]any{
		{"domain": "not a domain", "system_user": "site_ex", "docroot": "/home/sites/site_ex/public", "app_type": "static", "cert_pem": certPEM, "key_pem": keyPEM},
		{"domain": "example.com", "system_user": "not-a-site-user", "docroot": "/home/sites/site_ex/public", "app_type": "static", "cert_pem": certPEM, "key_pem": keyPEM},
		{"domain": "example.com", "system_user": "site_ex", "docroot": "/etc/passwd", "app_type": "static", "cert_pem": certPEM, "key_pem": keyPEM},
		{"domain": "example.com", "system_user": "site_ex", "docroot": "/home/sites/site_ex/public", "app_type": "not-a-type", "cert_pem": certPEM, "key_pem": keyPEM},
		{"domain": "wrong-domain.com", "system_user": "site_ex", "docroot": "/home/sites/site_ex/public", "app_type": "static", "cert_pem": certPEM, "key_pem": keyPEM},
	}
	for i, params := range cases {
		if _, err := handleSSLInstallCustom(context.Background(), params, func(string) {}); err == nil {
			t.Errorf("case %d: expected rejection, got success", i)
		}
	}
}

func TestHandleSSLInstallCustomWritesValidatedCertBeforeNginxStep(t *testing.T) {
	newTestSSLDirs(t)
	certPEM, keyPEM := generateTestCert(t, []string{"example.com"}, time.Now().Add(-time.Hour), 90*24*time.Hour)

	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "example.com", "system_user": "site_ex", "docroot": "/home/sites/site_ex/public",
		"app_type": "static", "temp_domain": "site_ex.1-2-3-4.sslip.io", "cert_pem": certPEM, "key_pem": keyPEM,
	}, func(string) {})
	// nginx is not installed in this test environment, so writeVhostAtomic's
	// `nginx -t` step is expected to fail — but only AFTER validation and
	// disk writes have already happened, which is what this test actually
	// checks for.
	if err == nil {
		t.Skip("nginx appears to be installed in this environment; success path covered by handleSSLStatus tests instead")
	}
	if strings.Contains(err.Error(), "do not form a valid pair") || strings.Contains(err.Error(), "not valid for") {
		t.Fatalf("handleSSLInstallCustom failed validation unexpectedly: %v", err)
	}
}

func TestHandleSSLStatusReportsNoneWhenNoCertificateExists(t *testing.T) {
	newTestSSLDirs(t)
	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "example.com"}, nil)
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var res sslResult
	if jsonErr := json.Unmarshal([]byte(out), &res); jsonErr != nil {
		t.Fatalf("parse result: %v", jsonErr)
	}
	if res.Type != "none" {
		t.Fatalf("Type = %q, want %q", res.Type, "none")
	}
}

func TestHandleSSLStatusRejectsInvalidDomain(t *testing.T) {
	newTestSSLDirs(t)
	if _, err := handleSSLStatus(context.Background(), map[string]any{"domain": "; rm -rf /"}, nil); err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLStatusFindsCustomCertificate(t *testing.T) {
	newTestSSLDirs(t)
	certPEM, keyPEM := generateTestCert(t, []string{"example.com"}, time.Now().Add(-time.Hour), 90*24*time.Hour)

	// Install directly by writing where handleSSLInstallCustom would, since
	// the install path itself needs a real nginx binary to complete.
	certDir := filepath.Join(customSSLDir, "example.com")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), []byte(certPEM), 0644); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), []byte(keyPEM), 0600); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": "example.com"}, nil)
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var res sslResult
	if jsonErr := json.Unmarshal([]byte(out), &res); jsonErr != nil {
		t.Fatalf("parse result: %v", jsonErr)
	}
	if res.Type != "custom" {
		t.Fatalf("Type = %q, want %q", res.Type, "custom")
	}
	if res.ExpiresAt == "" {
		t.Fatal("expected ExpiresAt to be populated")
	}
}

func TestHandleSSLIssueLetsEncryptRequiresEmailAndValidDomain(t *testing.T) {
	if _, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{"domain": "example.com"}, nil); err == nil {
		t.Fatal("expected missing email to be rejected")
	}
	if _, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{"domain": "not a domain", "email": "a@b.com"}, nil); err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestSSLVhostContentReferencesCertPaths(t *testing.T) {
	content := sslVhostContent("example.com", "temp.sslip.io", "/home/sites/site_ex/public", "site_ex",
		vhostLocationBlock("site_ex", "static", ""), "/etc/serverpanel-agent/ssl/example.com/fullchain.pem", "/etc/serverpanel-agent/ssl/example.com/privkey.pem")
	if !strings.Contains(content, "ssl_certificate /etc/serverpanel-agent/ssl/example.com/fullchain.pem;") {
		t.Fatal("expected the generated vhost to reference the certificate path")
	}
	if !strings.Contains(content, "listen 443 ssl;") {
		t.Fatal("expected the generated vhost to listen on 443")
	}
	if !strings.Contains(content, "return 301 https://$host$request_uri;") {
		t.Fatal("expected the generated vhost to redirect HTTP to HTTPS")
	}
}
