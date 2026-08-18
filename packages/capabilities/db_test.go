package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These tests cover the identifier/password validation that runs before
// handleDBCreate/handleDBDelete ever open a MariaDB connection — the same
// "validate first, connect second" ordering that lets file_test.go and
// backup_test.go exercise real logic without a live database in this
// environment (see TESTING.md §What hasn't been verified for the
// real-MariaDB gap these tests deliberately don't attempt to close).

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "bad-name!", "owner_user": "app_owner", "owner_password": "0123456789abcdef",
	}, noopProgress)
	if err == nil || !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("err = %v, want an invalid-database-name error", err)
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "not a valid user", "owner_password": "0123456789abcdef",
	}, noopProgress)
	if err == nil || !strings.Contains(err.Error(), "invalid owner_user") {
		t.Fatalf("err = %v, want an invalid-owner_user error", err)
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "app_owner", "owner_password": "tooshort",
	}, noopProgress)
	if err == nil || !strings.Contains(err.Error(), "owner_password must be at least 16 characters") {
		t.Fatalf("err = %v, want a too-short-password error", err)
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "'; DROP TABLE users; --",
	}, noopProgress)
	if err == nil || !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("err = %v, want an invalid-database-name error", err)
	}
}

var noopProgress Progress = func(string) {}
