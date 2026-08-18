package capabilities

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestParseCertbotCertificatesSingleCert(t *testing.T) {
	out := `Saved certs:

Certificate Name: example.com
  Serial Number: 1234567890abcdef
  Key Type: ECDSA
  Domains: example.com www.example.com
  Expiry Date: 2026-11-10 12:34:56+00:00 (VALID: 84 days)
  Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
  Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem`

	certs := parseCertbotCertificates(out)
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if certs[0].Name != "example.com" {
		t.Errorf("Name = %q, want example.com", certs[0].Name)
	}
	want := time.Date(2026, 11, 10, 12, 34, 56, 0, time.UTC)
	if !certs[0].ExpiryDate.Equal(want) {
		t.Errorf("ExpiryDate = %v, want %v", certs[0].ExpiryDate, want)
	}
}

func TestParseCertbotCertificatesMultipleCerts(t *testing.T) {
	out := `Certificate Name: a.example.com
  Expiry Date: 2026-01-01 00:00:00+00:00 (VALID: 30 days)
Certificate Name: b.example.com
  Expiry Date: 2026-06-15 08:00:00+00:00 (VALID: 200 days)`

	certs := parseCertbotCertificates(out)
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	if certs[0].Name != "a.example.com" || certs[1].Name != "b.example.com" {
		t.Fatalf("unexpected cert names: %+v", certs)
	}
}

func TestParseCertbotCertificatesEmptyOutput(t *testing.T) {
	for _, out := range []string{"", "No certificates found.", "  \n  \n"} {
		if certs := parseCertbotCertificates(out); len(certs) != 0 {
			t.Errorf("parseCertbotCertificates(%q) = %+v, want empty", out, certs)
		}
	}
}

func TestParseCertbotCertificatesIgnoresUnparsableExpiry(t *testing.T) {
	out := `Certificate Name: broken.example.com
  Expiry Date: not-a-date`
	certs := parseCertbotCertificates(out)
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if !certs[0].ExpiryDate.IsZero() {
		t.Errorf("ExpiryDate = %v, want zero value for unparsable date", certs[0].ExpiryDate)
	}
}

func TestSSLIssueLetsEncryptRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{
		"domain": "not a domain", "email": "a@example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestSSLIssueLetsEncryptRequiresEmail(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{
		"domain": "example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected a missing email to be rejected")
	}
	if !strings.Contains(err.Error(), "email is required") {
		t.Fatalf("error = %q, want it to mention the missing email", err.Error())
	}
}

func TestSSLInstallCustomRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "../../etc/passwd", "cert_pem": "x", "key_pem": "y",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestSSLInstallCustomRequiresCertAndKey(t *testing.T) {
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain": "example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected missing cert_pem/key_pem to be rejected")
	}
}

func TestSSLStatusRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLStatus(context.Background(), map[string]any{
		"domain": "example.com; rm -rf /",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

// TestSSLStatusFailsClosedWithoutCertbot exercises the real handler (no
// mocking of exec) on a host that has no certbot installed — true for this
// test environment and most CI runners alike — asserting it fails with a
// clear, actionable error rather than a panic or a false "no certificate"
// result that would be indistinguishable from "certbot works but this
// domain has no cert".
func TestSSLStatusFailsClosedWithoutCertbot(t *testing.T) {
	if _, err := run(context.Background(), "which", "certbot"); err == nil {
		t.Skip("certbot is installed on this host; the not-installed path isn't exercised here")
	}
	_, err := handleSSLStatus(context.Background(), map[string]any{
		"domain": "example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected an error when certbot is not installed")
	}
	if !strings.Contains(err.Error(), "certbot is not installed") {
		t.Fatalf("error = %q, want it to mention certbot is not installed", err.Error())
	}
}
