package capabilities

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHandleSSLStatusRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLStatus(context.Background(), map[string]any{
		"domain": "not a domain; rm -rf /",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected before any file access")
	}
}

// TestHandleSSLStatusReportsNoneWhenNoCertificateExists exercises the real
// disk-lookup path (no root/certbot needed: a domain no cert was ever
// issued for simply won't have anything at /etc/letsencrypt/live/<domain>
// or the custom cert path) and checks the JSON shape the control plane
// depends on to persist "no certificate installed" rather than erroring.
func TestHandleSSLStatusReportsNoneWhenNoCertificateExists(t *testing.T) {
	domain := "definitely-not-installed.example.invalid.test"
	out, err := handleSSLStatus(context.Background(), map[string]any{"domain": domain}, nil)
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var res sslStatusResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if res.Installed {
		t.Fatalf("expected Installed=false for a domain with no certificate, got %+v", res)
	}
	if res.Source != "none" {
		t.Fatalf("Source = %q, want \"none\"", res.Source)
	}
}

func TestHandleSSLRenewRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLRenew(context.Background(), map[string]any{
		"domain": "../../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLRenewRejectsDomainWithNoCertificate(t *testing.T) {
	_, err := handleSSLRenew(context.Background(), map[string]any{
		"domain": "no-cert-here.example.invalid.test",
	}, nil)
	if err == nil {
		t.Fatal("expected renew to refuse a domain with no installed Let's Encrypt certificate")
	}
	if !strings.Contains(err.Error(), "no Let's Encrypt certificate") {
		t.Fatalf("error = %q, want it to explain no certificate is installed", err.Error())
	}
}

func TestHandleSSLUninstallRejectsInvalidDomain(t *testing.T) {
	_, err := handleSSLUninstall(context.Background(), map[string]any{
		"domain": "not a domain", "system_user": "site_example", "docroot": "/home/sites/site_example/public", "app_type": "static",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected")
	}
}

func TestHandleSSLUninstallRejectsInvalidSystemUser(t *testing.T) {
	_, err := handleSSLUninstall(context.Background(), map[string]any{
		"domain": "example.com", "system_user": "root", "docroot": "/home/sites/site_example/public", "app_type": "static",
	}, nil)
	if err == nil {
		t.Fatal("expected a system_user outside the site_* namespace to be rejected")
	}
}

func TestHandleSSLUninstallRejectsMissingDocroot(t *testing.T) {
	_, err := handleSSLUninstall(context.Background(), map[string]any{
		"domain": "example.com", "system_user": "site_example", "app_type": "static",
	}, nil)
	if err == nil {
		t.Fatal("expected a missing docroot to be rejected")
	}
}

func TestCertInfoParsesOpensslEnddateFormat(t *testing.T) {
	// Guards the exact layout string certInfo passes to time.Parse.
	// openssl's `-enddate` uses asctime-style day padding: a single-digit
	// day gets a literal extra space ("Jan  2", two spaces), a two-digit
	// day doesn't ("Dec 15", one space). Getting this layout wrong doesn't
	// fail loudly — it silently mis-parses the expiry date used for
	// renewal-monitoring alerts, so both forms are checked here.
	const layout = "Jan _2 15:04:05 2006 MST"

	single, err := time.Parse(layout, "Jan  2 15:04:05 2030 GMT")
	if err != nil {
		t.Fatalf("parse single-digit-day enddate: %v", err)
	}
	if single.Year() != 2030 || single.Month() != time.January || single.Day() != 2 {
		t.Fatalf("parsed %v, want 2030-01-02", single)
	}

	double, err := time.Parse(layout, "Dec 15 00:00:00 2030 GMT")
	if err != nil {
		t.Fatalf("parse double-digit-day enddate: %v", err)
	}
	if double.Year() != 2030 || double.Month() != time.December || double.Day() != 15 {
		t.Fatalf("parsed %v, want 2030-12-15", double)
	}
}
