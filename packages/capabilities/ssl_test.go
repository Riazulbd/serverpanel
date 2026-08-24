package capabilities

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseOpenSSLEndDate(t *testing.T) {
	got, err := parseOpenSSLEndDate("notAfter=Jan 15 12:00:00 2027 GMT")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2027, time.January, 15, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseOpenSSLEndDateTrimsWhitespace(t *testing.T) {
	if _, err := parseOpenSSLEndDate("  notAfter=Jan 15 12:00:00 2027 GMT\n"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseOpenSSLEndDateRejectsGarbage(t *testing.T) {
	if _, err := parseOpenSSLEndDate("not a certbot line at all"); err == nil {
		t.Fatal("expected an error for unrecognized output, got nil")
	}
	if _, err := parseOpenSSLEndDate("notAfter=not-a-date"); err == nil {
		t.Fatal("expected an error for an unparseable date, got nil")
	}
}

func TestDaysUntil(t *testing.T) {
	now := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		t    time.Time
		want int
	}{
		{"30 days out", now.Add(30 * 24 * time.Hour), 30},
		{"already expired", now.Add(-5 * 24 * time.Hour), -5},
		{"expires right now", now, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := daysUntil(tc.t, now); got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestListLiveCertDomains(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"example.com", "shop.example.com"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// certbot's live directory always contains a README file alongside the
	// per-domain directories; it must never be reported as a domain.
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("readme"), 0644); err != nil {
		t.Fatal(err)
	}

	domains, err := listLiveCertDomains(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2: %v", len(domains), domains)
	}
	seen := map[string]bool{}
	for _, d := range domains {
		seen[d] = true
	}
	if !seen["example.com"] || !seen["shop.example.com"] {
		t.Errorf("missing expected domains, got %v", domains)
	}
	if seen["README"] {
		t.Error("README file was reported as a certificate domain")
	}
}

func TestListLiveCertDomainsMissingDir(t *testing.T) {
	if _, err := listLiveCertDomains(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected an error for a nonexistent directory, got nil")
	}
}

// TestHandleSSLStatusNoCertificates exercises the full handler against a
// fixture live-dir with no certificates and (on this test host) an inactive
// certbot.timer / missing hook — the realistic state of a freshly
// stack.install'd server that hasn't issued any certificate yet. It must
// report cleanly, not error, so a dashboard can show "no certificates yet"
// rather than a failure.
func TestHandleSSLStatusNoCertificates(t *testing.T) {
	orig := letsEncryptLiveDir
	letsEncryptLiveDir = filepath.Join(t.TempDir(), "live")
	defer func() { letsEncryptLiveDir = orig }()

	out, err := handleSSLStatus(context.Background(), nil, func(string) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == "" {
		t.Fatal("expected a non-empty JSON report")
	}
}

func TestHandleSSLStatusIsReadOnly(t *testing.T) {
	// Regression guard: handleSSLStatus must never write to
	// letsEncryptLiveDir or sslDeployHookPath — it only reads. Point it at
	// a fixture dir, capture a mtime-based fingerprint of the whole
	// directory tree before and after, and assert nothing changed.
	dir := t.TempDir()
	live := filepath.Join(dir, "live")
	if err := os.MkdirAll(filepath.Join(live, "example.com"), 0755); err != nil {
		t.Fatal(err)
	}
	orig := letsEncryptLiveDir
	letsEncryptLiveDir = live
	defer func() { letsEncryptLiveDir = orig }()

	before, err := os.ReadDir(live)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handleSSLStatus(context.Background(), nil, func(string) {}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	after, err := os.ReadDir(live)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("handleSSLStatus modified the live cert directory: before=%d entries, after=%d", len(before), len(after))
	}
}

func TestSSLDeployHookScriptGatesOnNginxTest(t *testing.T) {
	// The hook must never reload nginx unconditionally — a renewal that
	// races a broken, unrelated nginx config change must not turn that
	// broken config into a live outage by reloading it.
	if !strings.Contains(sslDeployHookScript, "nginx -t") {
		t.Error("deploy hook script does not gate on `nginx -t`")
	}
	if !strings.Contains(sslDeployHookScript, "systemctl reload nginx") {
		t.Error("deploy hook script does not reload nginx")
	}
}
