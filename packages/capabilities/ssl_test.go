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

// selfSignedCert generates a throwaway ECDSA certificate/key pair valid for
// the given hostname, entirely in-memory — used to exercise the
// cert/key-matching and hostname-validation logic in handleSSLInstallCustom
// without touching a real filesystem or CA.
func selfSignedCert(t *testing.T, host string, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestHandleSSLStatusRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLStatus(context.Background(), map[string]any{"domain": "not a domain"}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestReadCertStatusReportsNoneWhenNothingIsInstalled(t *testing.T) {
	res := readCertStatus("no-such-domain-in-this-test.example")
	if res.Source != "none" {
		t.Fatalf("Source = %q, want none", res.Source)
	}
	if res.NotAfter != "" {
		t.Fatalf("NotAfter should be empty when no certificate exists, got %q", res.NotAfter)
	}
}

func TestHandleSSLIssueLetsEncryptRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{
		"domain": "example.com; rm -rf /", "email": "ops@example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected before shelling out to certbot")
	}
}

func TestHandleSSLIssueLetsEncryptRequiresEmail(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{"domain": "example.com"}, nil)
	if err == nil {
		t.Fatal("expected a missing email to be rejected")
	}
}

func TestHandleSSLInstallCustomRejectsInvalidDomain(t *testing.T) {
	certPEM, keyPEM := selfSignedCert(t, "example.com", time.Now().Add(90*24*time.Hour))
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "../../etc/passwd", "cert_pem": certPEM, "key_pem": keyPEM,
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected before any file is written")
	}
}

func TestHandleSSLInstallCustomRejectsMismatchedKey(t *testing.T) {
	certPEM, _ := selfSignedCert(t, "example.com", time.Now().Add(90*24*time.Hour))
	_, otherKeyPEM := selfSignedCert(t, "example.com", time.Now().Add(90*24*time.Hour))

	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "example.com", "cert_pem": certPEM, "key_pem": otherKeyPEM,
	}, nil)
	if err == nil {
		t.Fatal("expected a certificate/key mismatch to be rejected before any file is written")
	}
	if !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("error = %q, want a certificate/key mismatch message", err.Error())
	}
}

func TestHandleSSLInstallCustomRejectsWrongHostname(t *testing.T) {
	certPEM, keyPEM := selfSignedCert(t, "other-domain.example", time.Now().Add(90*24*time.Hour))
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "example.com", "cert_pem": certPEM, "key_pem": keyPEM,
	}, nil)
	if err == nil {
		t.Fatal("expected a certificate that doesn't cover the requested domain to be rejected")
	}
}

func TestHandleSSLInstallCustomRejectsExpiredCert(t *testing.T) {
	certPEM, keyPEM := selfSignedCert(t, "example.com", time.Now().Add(-24*time.Hour))
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "example.com", "cert_pem": certPEM, "key_pem": keyPEM,
	}, nil)
	if err == nil {
		t.Fatal("expected an already-expired certificate to be rejected")
	}
}

func TestInjectHTTPSListenAddsListenAndCertDirectives(t *testing.T) {
	vhost := "server {\n    listen 80;\n    listen [::]:80;\n    server_name example.com;\n    root /home/sites/x/public;\n}\n"
	updated, changed := injectHTTPSListen(vhost, "/etc/serverpanel-agent/ssl/example.com/fullchain.pem", "/etc/serverpanel-agent/ssl/example.com/privkey.pem")
	if !changed {
		t.Fatal("expected the vhost to be changed")
	}
	for _, want := range []string{"listen 443 ssl;", "listen [::]:443 ssl;", "ssl_certificate     /etc/serverpanel-agent/ssl/example.com/fullchain.pem;", "ssl_certificate_key /etc/serverpanel-agent/ssl/example.com/privkey.pem;"} {
		if !strings.Contains(updated, want) {
			t.Fatalf("updated vhost missing %q:\n%s", want, updated)
		}
	}
	// The original http listen/location content must be preserved verbatim.
	if !strings.Contains(updated, "server_name example.com;") || !strings.Contains(updated, "root /home/sites/x/public;") {
		t.Fatalf("updated vhost lost existing content:\n%s", updated)
	}
}

func TestInjectHTTPSListenIsIdempotentAndUpdatesInPlace(t *testing.T) {
	vhost := "server {\n    listen 80;\n    server_name example.com;\n    root /x;\n}\n"
	first, changed := injectHTTPSListen(vhost, "/old/fullchain.pem", "/old/privkey.pem")
	if !changed {
		t.Fatal("expected the first install to change the vhost")
	}

	// Re-running with the exact same paths (a retried/no-op call) should
	// report no change...
	again, changed := injectHTTPSListen(first, "/old/fullchain.pem", "/old/privkey.pem")
	if changed {
		t.Fatal("expected re-running with identical cert paths to be a no-op")
	}
	if strings.Count(again, "ssl_certificate     /old") != 1 {
		t.Fatalf("expected exactly one ssl_certificate directive, got:\n%s", again)
	}

	// ...but installing a renewed/replaced certificate at a new path
	// updates the existing directive rather than appending a duplicate one
	// (which would fail nginx -t with "duplicate ssl_certificate directive").
	renewed, changed := injectHTTPSListen(again, "/new/fullchain.pem", "/new/privkey.pem")
	if !changed {
		t.Fatal("expected a new cert path to be recognized as a change")
	}
	if strings.Count(renewed, "ssl_certificate     ") != 1 || !strings.Contains(renewed, "/new/fullchain.pem") {
		t.Fatalf("expected the certificate directive to be updated in place, not duplicated:\n%s", renewed)
	}
	if strings.Contains(renewed, "listen 443 ssl;\n    listen 443 ssl;") {
		t.Fatalf("listen directive was duplicated:\n%s", renewed)
	}
}

func TestInjectHTTPSListenLeavesUnrecognizedVhostsAlone(t *testing.T) {
	vhost := "server {\n    server_name example.com;\n}\n"
	updated, changed := injectHTTPSListen(vhost, "/c.pem", "/k.pem")
	if changed || updated != vhost {
		t.Fatal("expected a vhost without a \"listen 80;\" line to be left untouched rather than guessed at")
	}
}
