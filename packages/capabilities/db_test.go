package capabilities

import (
	"context"
	"testing"
)

// These tests exercise db.create/db.delete's parameter validation only —
// the same boundary backup_test.go's scope-validation tests exercise for
// backups. A real round trip against MariaDB (CREATE DATABASE/USER, GRANT)
// requires a running MariaDB instance, which this environment doesn't have;
// that path is manually verified in a prior session (see TESTING.md §2) and
// tracked as BLOCKED_EXTERNAL for automated coverage, same as db.create's
// broader status in SERVERAVATAR_PARITY.md.

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Bad-Name", "owner_user": "owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "valid_name", "owner_user": "Bad-Owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "valid_name", "owner_user": "valid_owner", "owner_password": "tooshort",
	}, nil)
	if err == nil {
		t.Fatal("expected a short owner_password to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "Bad-Name"}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "valid_name", "owner_user": "Bad-Owner"}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}
