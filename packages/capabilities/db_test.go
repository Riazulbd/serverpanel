package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These tests cover only handleDBCreate/handleDBDelete's input validation,
// which runs and returns before any MariaDB connection is attempted — so
// they exercise the real code path without requiring a live database. The
// actual CREATE DATABASE/USER/GRANT round trip is verified manually against
// a real MariaDB instance (see TESTING.md), same as db.create's other
// db/full-scope siblings.

func TestHandleDBCreateRejectsInvalidDatabaseName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Not-Valid!", "owner_user": "appuser", "owner_password": "0123456789abcdef",
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("handleDBCreate with invalid name: err = %v, want an invalid-name error", err)
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "appdb", "owner_user": "Not Valid", "owner_password": "0123456789abcdef",
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "invalid owner_user") {
		t.Fatalf("handleDBCreate with invalid owner_user: err = %v, want an invalid-owner_user error", err)
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "appdb", "owner_user": "appuser", "owner_password": "tooshort",
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "owner_password must be at least") {
		t.Fatalf("handleDBCreate with short password: err = %v, want a password-length error", err)
	}
}

func TestHandleDBDeleteRejectsInvalidDatabaseName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "../etc/passwd",
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("handleDBDelete with invalid name: err = %v, want an invalid-name error", err)
	}
}

func TestHandleDBDeleteRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "appdb", "owner_user": "bad user",
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "invalid owner_user") {
		t.Fatalf("handleDBDelete with invalid owner_user: err = %v, want an invalid-owner_user error", err)
	}
}
