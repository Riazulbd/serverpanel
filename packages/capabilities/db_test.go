package capabilities

import (
	"context"
	"testing"
)

// These cover the validation paths handleDBCreate/handleDBDelete/
// handleDBResetPassword must enforce before ever touching a MariaDB
// connection. The real CREATE DATABASE/USER round trip against a live
// MariaDB is BLOCKED_EXTERNAL in this environment (no mysqld available —
// see docs/SERVERAVATAR_PARITY.md DB-001) and was manually verified in a
// prior session per TESTING.md.

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "not-a-valid-name!", "owner_user": "owner", "owner_password": "supersecretpassword123",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "validname", "owner_user": "Not Valid", "owner_password": "supersecretpassword123",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "validname", "owner_user": "owner", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected a too-short owner_password to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "DROP TABLE x"}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBResetPasswordRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBResetPassword(context.Background(), map[string]any{
		"owner_user": "bad owner", "owner_password": "supersecretpassword123",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestHandleDBResetPasswordRejectsShortPassword(t *testing.T) {
	_, err := handleDBResetPassword(context.Background(), map[string]any{
		"owner_user": "owner", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected a too-short owner_password to be rejected")
	}
}
