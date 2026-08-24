package capabilities

import "testing"

const sampleCertbotOutput = `Saved certificates:
  Certificate Name: example.com
    Serial Number: 1234567890abcdef1234567890abcdef123
    Key Type: ECDSA
    Domains: example.com www.example.com
    Expiry Date: 2026-11-20 03:14:00+00:00 (VALID: 88 days)
    Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem
  Certificate Name: staging.example.net
    Serial Number: abcdef1234567890abcdef1234567890abc
    Key Type: ECDSA
    Domains: staging.example.net
    Expiry Date: 2026-08-30 03:14:00+00:00 (VALID: 6 days)
    Certificate Path: /etc/letsencrypt/live/staging.example.net/fullchain.pem
    Private Key Path: /etc/letsencrypt/live/staging.example.net/privkey.pem
`

func TestParseCertbotCertificatesExtractsDomainsAndExpiry(t *testing.T) {
	certs := parseCertbotCertificates(sampleCertbotOutput)
	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want 2", len(certs))
	}

	if got, want := certs[0].Domains, []string{"example.com", "www.example.com"}; !equalStrings(got, want) {
		t.Errorf("cert[0].Domains = %v, want %v", got, want)
	}
	if certs[0].ExpiryDate != "2026-11-20 03:14:00+00:00" {
		t.Errorf("cert[0].ExpiryDate = %q, want %q", certs[0].ExpiryDate, "2026-11-20 03:14:00+00:00")
	}
	if certs[0].DaysLeft != 88 {
		t.Errorf("cert[0].DaysLeft = %d, want 88", certs[0].DaysLeft)
	}

	if got, want := certs[1].Domains, []string{"staging.example.net"}; !equalStrings(got, want) {
		t.Errorf("cert[1].Domains = %v, want %v", got, want)
	}
	if certs[1].DaysLeft != 6 {
		t.Errorf("cert[1].DaysLeft = %d, want 6 (soon-to-expire certs must still parse correctly for alerting)", certs[1].DaysLeft)
	}
}

func TestParseCertbotCertificatesHandlesNoCertificates(t *testing.T) {
	certs := parseCertbotCertificates("No certificates found.")
	if len(certs) != 0 {
		t.Errorf("got %d certificates from empty output, want 0", len(certs))
	}
}

func TestParseCertbotCertificatesHandlesExpiredCert(t *testing.T) {
	out := `Saved certificates:
  Certificate Name: expired.example.com
    Domains: expired.example.com
    Expiry Date: 2026-01-01 03:14:00+00:00 (INVALID: EXPIRED)
`
	// certbot renders an already-expired cert's line without a "VALID: N
	// days" suffix at all — the days-remaining regexp simply won't match,
	// which must not panic or misattribute an expiry match meant for a
	// different certificate.
	certs := parseCertbotCertificates(out)
	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1", len(certs))
	}
	if certs[0].ExpiryDate != "" || certs[0].DaysLeft != 0 {
		t.Errorf("expired cert should have no parsed expiry/days, got %+v", certs[0])
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
