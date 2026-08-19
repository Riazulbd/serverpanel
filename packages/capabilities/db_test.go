package capabilities

import (
	"context"
	"testing"
)

// These tests exercise handleDBCreate/handleDBDelete's input validation,
// which runs before any MariaDB connection is attempted — so they run
// without a real database, the same way TestHandleBackupRunRejectsBadScope
// covers backup.run's validation without a real backup target. The actual
// CREATE DATABASE/CREATE USER/GRANT round trip against a live MariaDB
// remains manually verified (see docs/TESTING.md §5 item 1) — this
// environment has no MariaDB socket to connect to.

func TestHandleDBCreateRejectsInvalidDatabaseName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "not valid!", "owner_user": "app_owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "DROP TABLE", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "app_owner", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected a too-short owner_password to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidDatabaseName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "; DROP TABLE x"}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "app_db", "owner_user": "bad user"}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}
