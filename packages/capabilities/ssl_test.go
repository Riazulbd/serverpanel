package capabilities

import (
	"context"
	"strings"
	"testing"
	"time"
)

const sampleCertbotOutput = `Saved Certificates:
  Certificate Name: example.com
    Serial Number: 0123456789abcdef
    Key Type: ECDSA
    Domains: example.com www.example.com
    Expiry Date: 2026-11-10 12:00:00+00:00 (VALID: 83 days)
    Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem
  Certificate Name: staging.example.com
    Serial Number: fedcba9876543210
    Key Type: RSA
    Domains: staging.example.com
    Expiry Date: 2026-08-25 09:30:00+00:00 (VALID: 6 days)
    Certificate Path: /etc/letsencrypt/live/staging.example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/staging.example.com/privkey.pem
`

func TestParseCertbotCertificates(t *testing.T) {
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	certs := parseCertbotCertificates(sampleCertbotOutput, now)

	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want 2", len(certs))
	}

	first := certs[0]
	if first.Name != "example.com" {
		t.Errorf("first.Name = %q, want %q", first.Name, "example.com")
	}
	if want := []string{"example.com", "www.example.com"}; !equalStrings(first.Domains, want) {
		t.Errorf("first.Domains = %v, want %v", first.Domains, want)
	}
	if !first.DaysLeftOK {
		t.Fatal("first.DaysLeftOK = false, want true (expiry date should have parsed)")
	}
	if first.DaysLeft != 83 {
		t.Errorf("first.DaysLeft = %d, want 83", first.DaysLeft)
	}
	if first.ExpiresAt == "" {
		t.Error("first.ExpiresAt is empty, want an RFC3339 timestamp")
	}

	second := certs[1]
	if second.Name != "staging.example.com" {
		t.Errorf("second.Name = %q, want %q", second.Name, "staging.example.com")
	}
	if second.DaysLeft != 6 {
		t.Errorf("second.DaysLeft = %d, want 6", second.DaysLeft)
	}
}

func TestParseCertbotCertificatesEmptyOutput(t *testing.T) {
	certs := parseCertbotCertificates("No certificates found.", time.Now())
	if len(certs) != 0 {
		t.Fatalf("got %d certificates from output with none, want 0", len(certs))
	}
}

func TestParseCertbotCertificatesUnparseableExpiryDoesNotDropCert(t *testing.T) {
	out := "Certificate Name: broken.example.com\n" +
		"    Domains: broken.example.com\n" +
		"    Expiry Date: not-a-real-date\n"
	certs := parseCertbotCertificates(out, time.Now())
	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1 (unparseable expiry should not drop the record)", len(certs))
	}
	if certs[0].DaysLeftOK {
		t.Error("DaysLeftOK = true for an unparseable expiry date, want false")
	}
	if certs[0].ExpiresAt != "" {
		t.Errorf("ExpiresAt = %q, want empty for an unparseable expiry date", certs[0].ExpiresAt)
	}
	if certs[0].ExpiryRaw != "not-a-real-date" {
		t.Errorf("ExpiryRaw = %q, want the raw text preserved even when unparseable", certs[0].ExpiryRaw)
	}
}

// TestSSLRenewalStatusRequiresCertbot exercises the capability's precondition
// check the same way every other SSL/stack capability guards itself: the
// test environment has no certbot installed, so this also proves the
// handler fails fast with a clear message rather than shelling out blind.
func TestSSLRenewalStatusRequiresCertbot(t *testing.T) {
	_, err := handleSSLRenewalStatus(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("expected an error when certbot is not installed")
	}
	if !strings.Contains(err.Error(), "certbot is not installed") {
		t.Fatalf("error = %q, want it to mention certbot is not installed", err.Error())
	}
}

func TestDispatchSSLRenewalStatusIsRegistered(t *testing.T) {
	r := Default()
	if _, ok := r[CapSSLRenewalStatus]; !ok {
		t.Fatalf("%s is not registered in the default capability registry", CapSSLRenewalStatus)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
