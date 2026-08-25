package capabilities

import (
	"context"
	"testing"
)

// These tests cover handleDBCreate/handleDBDelete's input validation, which
// runs — and must reject bad input — before any MariaDB connection is
// attempted. A real MariaDB round trip (CREATE DATABASE/USER, GRANT, DROP)
// is not exercised here: this sandboxed environment has no MariaDB, and
// that path remains manually-verified-only (see docs/SERVERAVATAR_PARITY.md
// DB-001, docs/TESTING.md).

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Not-Valid!", "owner_user": "wp_example", "owner_password": "0123456789abcdef01234567",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected before any DB connection is attempted")
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "Also-Invalid", "owner_password": "0123456789abcdef01234567",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected before any DB connection is attempted")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "wp_example", "owner_password": "tooshort",
	}, nil)
	if err == nil {
		t.Fatal("expected a short owner_password to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "Not-Valid!"}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected before any DB connection is attempted")
	}
}

func TestHandleDBDeleteRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "wp_example", "owner_user": "Also-Invalid"}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected before any DB connection is attempted")
	}
}
