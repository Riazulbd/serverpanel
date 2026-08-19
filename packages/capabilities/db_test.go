package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These tests cover the input validation that runs before handleDBCreate
// and handleDBDelete ever open a MariaDB connection (see the ordering in
// db.go: handleDBCreate validates name/owner_user/owner_password in full
// before dialing; handleDBDelete validates name before dialing, but its
// optional owner_user cleanup is validated only after the DROP DATABASE
// call, so it isn't covered here). Exercised without a live MariaDB
// instance; the actual CREATE/DROP DATABASE/USER/GRANT round trip remains
// manually verified against a real MariaDB host per TESTING.md, same as the
// rest of this file's DB-touching capabilities.

func noopProgress(string) {}

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Not Valid; DROP TABLE users", "owner_user": "app", "owner_password": "0123456789abcdef",
	}, noopProgress)
	if err == nil {
		t.Fatal("expected an error for an invalid database name, got nil")
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "not valid!", "owner_password": "0123456789abcdef",
	}, noopProgress)
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user, got nil")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "app_db", "owner_password": "tooshort",
	}, noopProgress)
	if err == nil {
		t.Fatal("expected an error for an owner_password under 16 characters, got nil")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "not valid",
	}, noopProgress)
	if err == nil {
		t.Fatal("expected an error for an invalid database name, got nil")
	}
}

func TestValidIdentifier(t *testing.T) {
	cases := map[string]bool{
		"app_db":                true,
		"a":                     true,
		strings.Repeat("a", 31): true,  // exactly the 31-char cap
		"App_db":                false, // must start lowercase
		"1app":                  false, // must start with a letter
		"not valid":             false, // no spaces
		"drop_table_users_--":   false, // no punctuation beyond underscore
		strings.Repeat("a", 32): false, // one over the 31-char cap
	}
	for name, want := range cases {
		if got := ValidIdentifier(name); got != want {
			t.Errorf("ValidIdentifier(%q) = %v, want %v", name, got, want)
		}
	}
}
