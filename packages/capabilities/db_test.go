package capabilities

import (
	"context"
	"testing"
)

// These tests exercise only the identifier/password validation that runs
// before handleDBCreate/handleDBDelete ever open a MariaDB connection —
// the same "no live MariaDB in this environment" boundary backup_test.go
// documents for the db/full backup scope. A real create/delete round trip
// against MariaDB is manually verified (see docs/TESTING.md); the
// SQL-injection-relevant validation logic itself is what's covered here.

func TestHandleDBCreateRejectsInvalidIdentifiers(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"bad database name", map[string]any{"name": "not valid!", "owner_user": "owner", "owner_password": "0123456789abcdef"}},
		{"database name starting with digit", map[string]any{"name": "1db", "owner_user": "owner", "owner_password": "0123456789abcdef"}},
		{"bad owner_user", map[string]any{"name": "gooddb", "owner_user": "bad user", "owner_password": "0123456789abcdef"}},
		{"owner_user with sql metacharacters", map[string]any{"name": "gooddb", "owner_user": "a`b", "owner_password": "0123456789abcdef"}},
		{"short password", map[string]any{"name": "gooddb", "owner_user": "owner", "owner_password": "short"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handleDBCreate(context.Background(), tc.params, func(string) {})
			if err == nil {
				t.Fatalf("expected a validation error, got none")
			}
		})
	}
}

func TestHandleDBDeleteRejectsInvalidIdentifiers(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "not valid!"}, func(string) {})
	if err == nil {
		t.Fatalf("expected a validation error for an invalid database name")
	}

	_, err = handleDBDelete(context.Background(), map[string]any{"name": "gooddb", "owner_user": "bad user"}, func(string) {})
	if err == nil {
		t.Fatalf("expected a validation error for an invalid owner_user")
	}
}

func TestIdentifierRegexAllowsOnlySafeNames(t *testing.T) {
	allowed := []string{"db", "app_db1", "a123456789"}
	rejected := []string{"", "1db", "DB", "db-name", "db name", "db;drop", "db`name", "a" + string(make([]byte, 40))}

	for _, n := range allowed {
		if !identifierRe.MatchString(n) {
			t.Errorf("expected %q to be allowed", n)
		}
	}
	for _, n := range rejected {
		if identifierRe.MatchString(n) {
			t.Errorf("expected %q to be rejected", n)
		}
	}
}
