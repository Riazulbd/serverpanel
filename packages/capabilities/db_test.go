package capabilities

import (
	"context"
	"testing"
)

// These tests cover the validation branches of the db.* handlers only —
// every one of them returns before ever attempting a MariaDB connection,
// so they run in any environment (including this one, which has no
// MariaDB installed). The real CREATE DATABASE/USER/GRANT round trip is
// verified manually against a live MariaDB 10.11 instance (see
// docs/TESTING.md), the same environment limitation BAK-001/BAK-002
// document for their db/full-scope paths.

func TestHandleDBCreateRejectsBadName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Bad-Name!", "owner_user": "app_owner", "owner_password": "a-very-long-password-value",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBCreateRejectsBadOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "Bad-Owner!", "owner_password": "a-very-long-password-value",
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
		t.Fatal("expected a short owner_password to be rejected")
	}
}

func TestHandleDBDeleteRejectsBadName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "Bad-Name!",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsBadOwnerUser(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "Bad-Owner!",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}
