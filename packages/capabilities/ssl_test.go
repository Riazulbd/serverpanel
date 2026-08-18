package capabilities

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestParseCertbotCertificatesExtractsDomainsAndExpiry(t *testing.T) {
	// A representative excerpt of `certbot certificates`' real output
	// format for two managed certificates.
	output := `Saving debug log to /var/log/letsencrypt/letsencrypt.log

Found the following certs:
  Certificate Name: example.com
    Serial Number: 1234abcd
    Domains: example.com www.example.com
    Expiry Date: 2026-11-15 03:04:05+00:00 (VALID: 89 days)
    Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem
  Certificate Name: expired.example.com
    Serial Number: 5678efgh
    Domains: expired.example.com
    Expiry Date: 2020-01-01 00:00:00+00:00 (INVALID: EXPIRED)
    Certificate Path: /etc/letsencrypt/live/expired.example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/expired.example.com/privkey.pem
`
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	certs := parseCertbotCertificates(output, now)

	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want 2: %+v", len(certs), certs)
	}

	if certs[0].Domain != "example.com" {
		t.Errorf("certs[0].Domain = %q, want example.com", certs[0].Domain)
	}
	if !certs[0].Valid {
		t.Errorf("certs[0].Valid = false, want true (expiry is in the future)")
	}
	if certs[0].DaysRemaining <= 0 {
		t.Errorf("certs[0].DaysRemaining = %d, want > 0", certs[0].DaysRemaining)
	}
	if certs[0].ExpiresAt == "" {
		t.Errorf("certs[0].ExpiresAt is empty, want a parsed RFC3339 timestamp")
	}

	if certs[1].Domain != "expired.example.com" {
		t.Errorf("certs[1].Domain = %q, want expired.example.com", certs[1].Domain)
	}
	if certs[1].Valid {
		t.Errorf("certs[1].Valid = true, want false (expiry is in the past)")
	}
	if certs[1].DaysRemaining >= 0 {
		t.Errorf("certs[1].DaysRemaining = %d, want negative (already expired)", certs[1].DaysRemaining)
	}
}

func TestParseCertbotCertificatesHandlesNoCertificates(t *testing.T) {
	got := parseCertbotCertificates("Saving debug log to /var/log/letsencrypt/letsencrypt.log\nNo certificates found.\n", time.Now())
	if len(got) != 0 {
		t.Fatalf("got %d certificates from empty output, want 0: %+v", len(got), got)
	}
}

func TestParseCertbotCertificatesToleratesUnrecognizedLines(t *testing.T) {
	output := "some unexpected preamble\nDomains: only-one.example.com\nsome trailing noise with no Expiry Date line\n"
	got := parseCertbotCertificates(output, time.Now())
	if len(got) != 1 || got[0].Domain != "only-one.example.com" {
		t.Fatalf("got %+v, want a single entry for only-one.example.com with no expiry parsed", got)
	}
	if got[0].ExpiresAt != "" {
		t.Errorf("ExpiresAt = %q, want empty (no Expiry Date line was present)", got[0].ExpiresAt)
	}
}

func TestHandleSSLRenewalStatusFailsCleanlyWithoutCertbot(t *testing.T) {
	// This test runs in an environment without certbot installed, which is
	// itself the case the handler must fail on cleanly (a clear error
	// rather than a confusing exec failure) rather than the case being
	// simulated.
	if _, err := run(context.Background(), "which", "certbot"); err == nil {
		t.Skip("certbot is installed in this test environment; the not-installed path isn't exercised")
	}
	_, err := handleSSLRenewalStatus(context.Background(), nil, func(string) {})
	if err == nil {
		t.Fatal("expected an error when certbot is not installed, got nil")
	}
	if !strings.Contains(err.Error(), "certbot is not installed") {
		t.Fatalf("error = %q, want it to mention certbot is not installed", err.Error())
	}
}

func TestHandleSSLIssueLetsEncryptRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{
		"domain": "not a domain; rm -rf /",
		"email":  "ops@example.com",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an invalid domain, got nil")
	}
}

func TestHandleSSLIssueLetsEncryptRequiresEmail(t *testing.T) {
	_, err := handleSSLIssueLetsEncrypt(context.Background(), map[string]any{
		"domain": "example.com",
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "email is required") {
		t.Fatalf("err = %v, want an error requiring email", err)
	}
}

func TestHandleSSLInstallCustomRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLInstallCustom(context.Background(), map[string]any{
		"domain":   "../../etc/passwd",
		"cert_pem": "x",
		"key_pem":  "y",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an invalid domain, got nil")
	}
}
