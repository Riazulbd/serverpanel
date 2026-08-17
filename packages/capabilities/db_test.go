package capabilities

import (
	"context"
	"testing"
)

// These tests cover only the validation path of the db.* handlers — the
// allow-listed identifier charset and the minimum password length — which
// runs entirely before any MariaDB connection is attempted. A real
// create/delete/list round trip requires a live MariaDB instance (Unix
// socket, root auth) and is documented as manually verified in
// docs/TESTING.md, the same pattern already used for backup.run/restore's
// db/full scope.

func TestValidIdentifierMatchesHandlerRules(t *testing.T) {
	valid := []string{"a", "app_db", "wp_example_1", "n2345678901234567890123456789a"} // 31 chars
	for _, v := range valid {
		if !ValidIdentifier(v) {
			t.Errorf("ValidIdentifier(%q) = false, want true", v)
		}
	}
	invalid := []string{"", "1abc", "Abc", "has-dash", "has space", "has.dot", "n23456789012345678901234567890ab", "'; DROP TABLE x;--"}
	for _, v := range invalid {
		if ValidIdentifier(v) {
			t.Errorf("ValidIdentifier(%q) = true, want false", v)
		}
	}
}

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Not Valid", "owner_user": "owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid database name, got nil")
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "valid_db", "owner_user": "not valid", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user, got nil")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "valid_db", "owner_user": "valid_owner", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for a password under 16 characters, got nil")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "not valid"}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid database name, got nil")
	}
}

func TestHandleDBDeleteRejectsInvalidOwner(t *testing.T) {
	// name alone is valid, but a malformed owner_user must still be rejected
	// rather than silently skipped or passed through to DROP USER.
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "valid_db", "owner_user": "not valid",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user, got nil")
	}
}
