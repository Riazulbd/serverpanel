package capabilities

import (
	"context"
	"strings"
	"testing"
)

func TestSystemUserForDomainIsSafeAndBounded(t *testing.T) {
	got := systemUserForDomain("Example.CO.UK")
	if got != "site_example_co_uk" {
		t.Fatalf("systemUserForDomain = %q, want site_example_co_uk", got)
	}
	long := systemUserForDomain(strings.Repeat("a", 100) + ".com")
	// "site_" prefix + at most 28 chars of the sanitized domain.
	if len(long) > len("site_")+28 {
		t.Fatalf("systemUserForDomain produced an unbounded name: %d chars", len(long))
	}
	if strings.ContainsAny(long, ".") {
		t.Fatalf("systemUserForDomain left a dot in %q, which breaks its use as a unix username", long)
	}
}

func TestDomainRegexAcceptsAndRejects(t *testing.T) {
	valid := []string{"example.com", "sub.example.com", "my-site.example.co.uk"}
	for _, d := range valid {
		if !domainRe.MatchString(d) {
			t.Errorf("domainRe rejected valid domain %q", d)
		}
	}
	invalid := []string{
		"", "localhost", "-example.com", "example-.com", "example..com",
		"example.com; rm -rf /", "exa mple.com", "../../../etc/passwd",
	}
	for _, d := range invalid {
		if domainRe.MatchString(d) {
			t.Errorf("domainRe accepted invalid domain %q", d)
		}
	}
}

func TestTempDomainForUsesSslip(t *testing.T) {
	got := tempDomainFor("site_example", "203.0.113.5")
	want := "site_example.203-0-113-5.sslip.io"
	if got != want {
		t.Fatalf("tempDomainFor = %q, want %q", got, want)
	}
}

func TestPHPFPMAndNginxPathsAreDeterministic(t *testing.T) {
	if got := phpFPMPoolPath("site_ex", "8.3"); got != "/etc/php/8.3/fpm/pool.d/site_ex.conf" {
		t.Fatalf("phpFPMPoolPath = %q", got)
	}
	if got := phpFPMSocketPath("site_ex", "8.3"); got != "/run/php/php8.3-fpm-site_ex.sock" {
		t.Fatalf("phpFPMSocketPath = %q", got)
	}
	if got := nginxVhostPath("site_ex"); got != "/etc/nginx/sites-available/site_ex.conf" {
		t.Fatalf("nginxVhostPath = %q", got)
	}
}

func TestHandleSiteCreateRejectsInvalidDomain(t *testing.T) {
	_, err := handleSiteCreate(context.Background(), map[string]any{
		"domain": "not a domain; rm -rf /", "app_type": "static",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid domain to be rejected before any system call is made")
	}
}
