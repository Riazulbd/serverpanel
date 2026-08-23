package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These tests exercise handleDBCreate/handleDBDelete's input-validation
// boundary only — the identifier allow-list and password-length checks run
// before any MariaDB connection is attempted, so they're safe to run
// without a live database (this environment has none; see
// TESTING.md "what's manually verified vs automated").

func TestHandleDBCreateRejectsInvalidDatabaseName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "1bad-name; DROP TABLE users", "owner_user": "app", "owner_password": strings.Repeat("x", 20),
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid database name, got nil")
	}
	if !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("error = %v, want it to mention invalid database name", err)
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "not a valid user!", "owner_password": strings.Repeat("x", 20),
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid owner_user, got nil")
	}
	if !strings.Contains(err.Error(), "invalid owner_user") {
		t.Fatalf("error = %v, want it to mention invalid owner_user", err)
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "app_db", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected error for short owner_password, got nil")
	}
	if !strings.Contains(err.Error(), "owner_password must be at least") {
		t.Fatalf("error = %v, want it to mention the minimum password length", err)
	}
}

func TestHandleDBDeleteRejectsInvalidDatabaseName(t *testing.T) {
	// name is validated before any MariaDB connection is attempted, so this
	// is safe to run without a live database. owner_user, by contrast, is
	// only validated after the DROP DATABASE call succeeds — not covered
	// here, since exercising that branch needs a real MariaDB connection.
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid database name, got nil")
	}
	if !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("error = %v, want it to mention invalid database name", err)
	}
}
