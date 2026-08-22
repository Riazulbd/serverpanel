package capabilities

import (
	"context"
	"testing"
)

// These tests cover handleDBCreate/handleDBDelete's parameter-validation
// layer only — the identifier allow-list and password-length checks all run
// before mariaDBConn() is ever called, so they're exercisable without a real
// MariaDB instance (this environment has none — see db.go's doc comment and
// SYSTEM.md §23 for what remains manually-verified-only).

func TestHandleDBCreateRejectsInvalidDatabaseName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "DROP TABLE users;", "owner_user": "wp_example", "owner_password": "a-very-long-password-value",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "not valid!", "owner_password": "a-very-long-password-value",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "wp_example", "owner_password": "tooshort",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a password under 16 characters to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidDatabaseName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "; DROP DATABASE mysql;",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "not valid!",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}
