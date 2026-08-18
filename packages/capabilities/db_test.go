package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These tests cover handleDBCreate/handleDBDelete's parameter-validation
// boundary only (identifier allow-list, minimum password length) — the
// validation happens before any MariaDB connection is attempted, so it's
// exercised here without a real database, the same "test what's cheap for
// real, document the rest" split TESTING.md uses for the other MariaDB-
// backed capabilities (db.create's actual CREATE DATABASE/GRANT statements
// require a live MariaDB and are covered in TESTING.md's manual-verification
// section, not here).

func TestHandleDBCreateRejectsInvalidDatabaseName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "not valid; drop table", "owner_user": "app", "owner_password": "supersecretpassword1234",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("error = %q, want it to mention the invalid database name", err.Error())
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "bad user!", "owner_password": "supersecretpassword1234",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid owner_user") {
		t.Fatalf("error = %q, want it to mention the invalid owner_user", err.Error())
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "app_db", "owner_password": "tooshort",
	}, nil)
	if err == nil {
		t.Fatal("expected a too-short owner_password to be rejected")
	}
	if !strings.Contains(err.Error(), "at least 16 characters") {
		t.Fatalf("error = %q, want it to mention the minimum length", err.Error())
	}
}

func TestHandleDBDeleteRejectsInvalidDatabaseName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "bad;user",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid owner_user") {
		t.Fatalf("error = %q, want it to mention the invalid owner_user", err.Error())
	}
}
