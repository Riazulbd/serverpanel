package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These only exercise the validation paths, which return before ever
// dialing MariaDB (see mariaDBConn's doc comment) — the same reasoning
// TestHandleSiteCreateRejectsInvalidDomain uses in site_test.go. Actual
// database/user creation against a live MariaDB instance is documented as
// manually verified in TESTING.md, matching how the rest of this package's
// system-service-dependent capabilities are covered.

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "not a name; DROP TABLE users;--", "owner_user": "owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected before any system call is made")
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "owner`; GRANT ALL", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected before any system call is made")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "app_owner", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected a short owner_password to be rejected before any system call is made")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "../../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected before any system call is made")
	}
}

func TestHandleDBDeleteRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "bad owner",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected before any system call is made")
	}
}

func TestIdentifierRegexAcceptsAndRejects(t *testing.T) {
	valid := []string{"a", "app_db", "site1_wp", "a" + strings.Repeat("0", 30)} // 31 chars, at the limit
	for _, v := range valid {
		if !identifierRe.MatchString(v) {
			t.Errorf("identifierRe rejected valid identifier %q", v)
		}
	}
	invalid := []string{
		"", "1abc", "Abc", "app-db", "app db", "app;db", "app.db",
		"a" + strings.Repeat("0", 31), // 32 chars, one over the limit
	}
	for _, v := range invalid {
		if identifierRe.MatchString(v) {
			t.Errorf("identifierRe accepted invalid identifier %q", v)
		}
	}
}
