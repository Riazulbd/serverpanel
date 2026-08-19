package capabilities

import (
	"context"
	"strings"
	"testing"
)

// TestIdentifierReRejectsInjection covers the database identifier
// allow-list. MySQL has no placeholder syntax for identifiers, so this
// regex is the only thing standing between a database name and a
// backtick-quoted interpolation into DDL — it has to be strict.
func TestIdentifierReRejectsInjection(t *testing.T) {
	bad := []string{
		"", " ", "1abc", "ABC", "a-b", "a.b", "a b",
		"wp`; DROP DATABASE mysql; --",
		"wp` UNION SELECT 1 --",
		"bad; DROP TABLE x;--",
		"a\\`b",
		"wp\nname",
		strings.Repeat("a", 32), // 31 max (1 + 30)
	}
	for _, name := range bad {
		if identifierRe.MatchString(name) {
			t.Errorf("identifierRe accepted unsafe identifier %q", name)
		}
	}

	good := []string{"wp", "wp_demo", "a", "wp_demo_2024", strings.Repeat("a", 31)}
	for _, name := range good {
		if !identifierRe.MatchString(name) {
			t.Errorf("identifierRe rejected legitimate identifier %q", name)
		}
	}
}

func TestDBCreateRejectsUnsafeNames(t *testing.T) {
	// These must fail validation before any connection to MariaDB is
	// attempted, which is also why this test can run without a database.
	cases := []map[string]any{
		{"name": "bad; DROP TABLE x;--", "owner_user": "ok_user", "owner_password": "sixteencharacters!!"},
		{"name": "ok_db", "owner_user": "bad-user", "owner_password": "sixteencharacters!!"},
		{"name": "ok_db", "owner_user": "ok_user", "owner_password": "tooshort"},
	}
	for i, params := range cases {
		if _, err := handleDBCreate(context.Background(), params, func(string) {}); err == nil {
			t.Errorf("case %d: db.create accepted unsafe params %v", i, params)
		}
	}
}

func TestDomainReRejectsMalformedDomains(t *testing.T) {
	bad := []string{
		"", "example", "-example.com", "example-.com", "exam ple.com",
		"example.com/../etc", "example.com;rm -rf /", "http://example.com",
		"example..com", ".example.com", "example.com.",
	}
	for _, d := range bad {
		if domainRe.MatchString(d) {
			t.Errorf("domainRe accepted malformed domain %q", d)
		}
	}

	good := []string{"example.com", "sub.example.com", "a-b.example.co.uk", "x1.test-site.io"}
	for _, d := range good {
		if !domainRe.MatchString(d) {
			t.Errorf("domainRe rejected legitimate domain %q", d)
		}
	}
}

func TestSiteCreateRejectsBadInput(t *testing.T) {
	cases := []map[string]any{
		{"domain": "not a domain", "app_type": "php"},
		{"domain": "example.com", "app_type": "nodejs"},                    // not a Phase 1 app type
		{"domain": "example.com", "app_type": "php", "php_version": "8.1"}, // unsupported version
		{"domain": "", "app_type": "static"},
	}
	for i, params := range cases {
		if _, err := handleSiteCreate(context.Background(), params, func(string) {}); err == nil {
			t.Errorf("case %d: site.create accepted bad params %v", i, params)
		}
	}
}

// TestWordPressInstallRefusesDocrootOutsideSite guards against a docroot
// param pointed somewhere other than the site's own isolated home, which
// would let one site's install scribble into another's files.
func TestWordPressInstallRefusesDocrootOutsideSite(t *testing.T) {
	params := map[string]any{
		"system_user": "site_a_com", "docroot": "/etc", "domain": "a.com",
		"db_name": "a", "db_user": "a", "db_password": "x",
		"admin_user": "admin", "admin_password": "x", "admin_email": "a@b.c",
	}
	if _, err := handleWordPressInstall(context.Background(), params, func(string) {}); err == nil {
		t.Error("app.wordpress_install accepted a docroot outside the site's home")
	}

	params["system_user"] = "notasite"
	params["docroot"] = siteHome("notasite")
	if _, err := handleWordPressInstall(context.Background(), params, func(string) {}); err == nil {
		t.Error("app.wordpress_install accepted a system_user outside the managed naming convention")
	}
}

func TestLogsTailRejectsBadSelectors(t *testing.T) {
	cases := []map[string]any{
		{"system_user": "root", "log_type": "access"},
		{"system_user": "../../etc/passwd", "log_type": "access"},
		{"system_user": "site_a_com", "log_type": "syslog"},
		{"system_user": "site_a_com", "log_type": "../../../var/log/auth"},
		{"system_user": "", "log_type": "error"},
	}
	for i, params := range cases {
		if _, err := handleLogsTail(context.Background(), params, func(string) {}); err == nil {
			t.Errorf("case %d: logs.tail accepted bad selectors %v", i, params)
		}
	}
}

// TestRedactStripsSecrets pins the log-redaction behaviour: these values
// must never reach the control plane, per the data-retention plan.
func TestRedactStripsSecrets(t *testing.T) {
	cases := []struct {
		in     string
		secret string
	}{
		{`GET /login?token=SUPERSECRET123&user=bob HTTP/1.1`, "SUPERSECRET123"},
		{`GET /x?password=hunter2 HTTP/1.1`, "hunter2"},
		{`GET /x?api_key=abc123def HTTP/1.1`, "abc123def"},
		{`GET /x?access_token=zzz999 HTTP/1.1`, "zzz999"},
		{`"Authorization: Bearer abc.def.ghijk"`, "abc.def.ghijk"},
		{`"Authorization: Basic dXNlcjpwYXNz"`, "dXNlcjpwYXNz"},
	}
	for _, c := range cases {
		got := redact(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("redact(%q) leaked %q: got %q", c.in, c.secret, got)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("redact(%q) did not mark a redaction: got %q", c.in, got)
		}
	}
}

// TestRedactPreservesOrdinaryLines makes sure redaction isn't so eager
// that it destroys the log's usefulness.
func TestRedactPreservesOrdinaryLines(t *testing.T) {
	line := `192.168.1.6 - - [14/Aug/2026:13:00:01 +0000] "GET /about HTTP/1.1" 200 128`
	if got := redact(line); got != line {
		t.Errorf("redact() altered an ordinary log line:\n in: %q\nout: %q", line, got)
	}
}

func TestSystemUserForDomainIsSafeAndBounded(t *testing.T) {
	cases := []string{
		"example.com",
		"a-very-long-subdomain-name.that-keeps-going.example.co.uk",
		"UPPER.EXAMPLE.COM",
		"a.io",
		strings.Repeat("x", 60) + ".com",
	}
	for _, domain := range cases {
		user := systemUserForDomain(domain)
		if !strings.HasPrefix(user, "site_") {
			t.Errorf("systemUserForDomain(%q) = %q, missing site_ prefix", domain, user)
		}
		// useradd on Ubuntu rejects (does not truncate) longer names.
		if len(user) > maxSystemUserLen {
			t.Errorf("systemUserForDomain(%q) = %q (%d chars), exceeds the %d-char useradd limit",
				domain, user, len(user), maxSystemUserLen)
		}
		for _, r := range user {
			isSafe := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
			if !isSafe {
				t.Errorf("systemUserForDomain(%q) = %q contains unsafe rune %q", domain, user, r)
			}
		}
	}
}

// TestSystemUserForDomainIsCollisionFree is an isolation test, not a
// naming-style test. Two sites that share a system user share a PHP-FPM
// pool and file ownership, so a collision here silently removes the
// boundary between two customers' sites.
//
// The pairs below are the two ways collisions arise: separator folding
// ("." and "-" both become "_") and truncation of long domains.
func TestSystemUserForDomainIsCollisionFree(t *testing.T) {
	pairs := [][2]string{
		{"foo-bar.com", "foo.bar.com"},
		{"a-b-c.com", "a.b.c.com"},
		{
			"a-very-long-subdomain-name.that-keeps-going.alpha.com",
			"a-very-long-subdomain-name.that-keeps-going.beta.com",
		},
		{strings.Repeat("x", 40) + ".alpha.com", strings.Repeat("x", 40) + ".beta.com"},
	}
	for _, p := range pairs {
		u1, u2 := systemUserForDomain(p[0]), systemUserForDomain(p[1])
		if u1 == u2 {
			t.Errorf("distinct domains %q and %q both map to system user %q — these sites would share a Linux user and lose isolation",
				p[0], p[1], u1)
		}
	}
}

// TestSystemUserForDomainIsStable pins determinism: the same domain must
// always resolve to the same user, or a second site.create (or any later
// operation that recomputes the name) would not find the existing site.
func TestSystemUserForDomainIsStable(t *testing.T) {
	for _, domain := range []string{"example.com", "Example.COM ", "sub.example.co.uk"} {
		if a, b := systemUserForDomain(domain), systemUserForDomain(domain); a != b {
			t.Errorf("systemUserForDomain(%q) not deterministic: %q vs %q", domain, a, b)
		}
	}
	// Case and surrounding whitespace must not produce a different user.
	if a, b := systemUserForDomain("Example.COM"), systemUserForDomain("example.com"); a != b {
		t.Errorf("case affected the derived user name: %q vs %q", a, b)
	}
}

func TestBackupRunRejectsBadScopeAndPaths(t *testing.T) {
	cases := []map[string]any{
		{"scope": "everything", "db_name": "ok_db"},
		{"scope": "files", "site_root": "/etc"},
		{"scope": "db", "db_name": "bad; DROP DATABASE x"},
		{"scope": "", "db_name": "ok_db"},
	}
	for i, params := range cases {
		if _, err := handleBackupRun(context.Background(), params, func(string) {}); err == nil {
			t.Errorf("case %d: backup.run accepted bad params %v", i, params)
		}
	}
}

func TestSSLRejectsBadInput(t *testing.T) {
	if _, err := handleSSLIssueLetsEncrypt(context.Background(),
		map[string]any{"domain": "not a domain", "email": "a@b.c"}, func(string) {}); err == nil {
		t.Error("ssl.issue_letsencrypt accepted an invalid domain")
	}
	if _, err := handleSSLIssueLetsEncrypt(context.Background(),
		map[string]any{"domain": "example.com", "email": ""}, func(string) {}); err == nil {
		t.Error("ssl.issue_letsencrypt accepted an empty email")
	}
	if _, err := handleSSLInstallCustom(context.Background(),
		map[string]any{"domain": "example.com", "cert_pem": "", "key_pem": ""}, func(string) {}); err == nil {
		t.Error("ssl.install_custom accepted empty cert/key")
	}
}
