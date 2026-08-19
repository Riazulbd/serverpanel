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

// testCert mints a real certificate/key pair for the given hostname and
// validity window, so the validation path is exercised against genuine
// X.509 material rather than fixtures that only look like it.
func testCert(t *testing.T, host string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestValidateCertificateMaterialAcceptsAMatchingPair(t *testing.T) {
	certPEM, keyPEM := testCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	leaf, err := validateCertificateMaterial(certPEM, keyPEM, "example.com")
	if err != nil {
		t.Fatalf("validateCertificateMaterial: %v", err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Fatalf("leaf CommonName = %q", leaf.Subject.CommonName)
	}
}

// TestValidateCertificateMaterialRejectsMismatchedKey is the important one:
// a certificate paired with someone else's key passes any well-formedness
// check and only fails when nginx reloads, by which point the site is down.
func TestValidateCertificateMaterialRejectsMismatchedKey(t *testing.T) {
	certPEM, _ := testCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	_, otherKeyPEM := testCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	if _, err := validateCertificateMaterial(certPEM, otherKeyPEM, "example.com"); err == nil {
		t.Fatal("expected a mismatched certificate/key pair to be rejected")
	}
}

func TestValidateCertificateMaterialRejectsExpiredCert(t *testing.T) {
	certPEM, keyPEM := testCert(t, "example.com", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	_, err := validateCertificateMaterial(certPEM, keyPEM, "example.com")
	if err == nil {
		t.Fatal("expected an already-expired certificate to be rejected")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %q, want it to say the certificate expired", err)
	}
}

func TestValidateCertificateMaterialRejectsWrongDomain(t *testing.T) {
	certPEM, keyPEM := testCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if _, err := validateCertificateMaterial(certPEM, keyPEM, "attacker.example.net"); err == nil {
		t.Fatal("expected a certificate that doesn't cover the domain to be rejected")
	}
}

// TestValidateCertificateMaterialNeverEchoesKeyMaterial guards the property
// that makes it safe to surface these errors through the API and into the
// audit log.
func TestValidateCertificateMaterialNeverEchoesKeyMaterial(t *testing.T) {
	certPEM, keyPEM := testCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	_, otherKeyPEM := testCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	for _, tc := range []struct{ name, cert, key, domain string }{
		{"mismatched key", certPEM, otherKeyPEM, "example.com"},
		{"garbage key", certPEM, "-----BEGIN EC PRIVATE KEY-----\nSUPERSECRET\n-----END EC PRIVATE KEY-----", "example.com"},
		{"wrong domain", certPEM, keyPEM, "attacker.example.net"},
	} {
		_, err := validateCertificateMaterial(tc.cert, tc.key, tc.domain)
		if err == nil {
			t.Fatalf("%s: expected an error", tc.name)
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "SUPERSECRET") {
			t.Errorf("%s: error message contains key material: %q", tc.name, err)
		}
	}
}

func TestSSLInstallCustomRejectsBadInput(t *testing.T) {
	certPEM, keyPEM := testCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	base := map[string]any{
		"domain": "example.com", "system_user": "site_example_com",
		"docroot": "/home/sites/site_example_com/public", "app_type": "php",
		"php_version": "8.3", "cert_pem": certPEM, "key_pem": keyPEM,
	}

	cases := map[string]map[string]any{
		"invalid domain":       {"domain": "not a domain"},
		"missing docroot":      {"docroot": ""},
		"missing cert":         {"cert_pem": ""},
		"missing key":          {"key_pem": ""},
		"traversing sys user":  {"system_user": "site_../../../../etc/nginx/sites-enabled/evil"},
		"non-site sys user":    {"system_user": "root"},
		"empty sys user":       {"system_user": ""},
		"sys user with slash":  {"system_user": "site_a/b"},
		"sys user with a dot":  {"system_user": "site_a.b"},
		"certificate mismatch": {"cert_pem": certPEM, "key_pem": "not a key"},
	}
	for name, overrides := range cases {
		params := map[string]any{}
		for k, v := range base {
			params[k] = v
		}
		for k, v := range overrides {
			params[k] = v
		}
		if _, err := handleSSLInstallCustom(context.Background(), params, func(string) {}); err == nil {
			t.Errorf("%s: expected rejection, got nil error", name)
		}
	}
}

// TestValidSystemUser is a regression test for a path-traversal defect:
// system_user is interpolated straight into nginx/php-fpm/TLS config paths,
// and the previous validation was only a "site_" prefix check — which
// "site_../.." satisfies while still escaping the directory, turning a
// config write or delete into an arbitrary one, as root.
func TestValidSystemUser(t *testing.T) {
	valid := []string{"site_example_com", "site_a", "site_" + strings.Repeat("a", 28)}
	for _, s := range valid {
		if !validSystemUser(s) {
			t.Errorf("validSystemUser(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"", "root", "site_", "site_..", "site_../..",
		"site_../../../../etc/nginx/sites-enabled/evil",
		"site_a/b", "site_a.b", "site_a-b", "site_A", "site_a b",
		"site_" + strings.Repeat("a", 29), // one over the cap
		"../site_a", "/site_a", "site_a\x00b",
	}
	for _, s := range invalid {
		if validSystemUser(s) {
			t.Errorf("validSystemUser(%q) = true, want false", s)
		}
	}

	// Every name the agent itself generates must pass its own validation,
	// or site.create would produce sites no later operation can address.
	for _, domain := range []string{
		"example.com", "a.very-long-subdomain.example.co.uk", "x.io",
		strings.Repeat("a", 40) + ".com",
	} {
		if u := systemUserForDomain(domain); !validSystemUser(u) {
			t.Errorf("systemUserForDomain(%q) = %q, which its own validation rejects", domain, u)
		}
	}
}

func TestSiteSetStatusRejectsTraversingSystemUser(t *testing.T) {
	_, err := handleSiteSetStatus(context.Background(), map[string]any{
		"system_user": "site_../../../../etc/nginx/sites-enabled/evil", "status": "disabled",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a traversing system_user to be rejected before any filesystem operation")
	}
}
