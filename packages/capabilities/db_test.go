package capabilities

import (
	"context"
	"testing"
)

// These tests exercise only the input-validation path of the db.*
// capability handlers, which rejects malformed identifiers/passwords
// before ever attempting a MariaDB connection — so they run without a
// live database, unlike the create/delete happy paths (see
// SERVERAVATAR_PARITY.md DB-001 for the real-MariaDB verification note).

func TestHandleDBCreateRejectsBadName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Has-Upper", "owner_user": "wp_example", "owner_password": "a-very-long-password-1234",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBCreateRejectsBadOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "1starts_with_digit", "owner_password": "a-very-long-password-1234",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "wp_example", "owner_password": "tooshort",
	}, nil)
	if err == nil {
		t.Fatal("expected a too-short owner_password to be rejected")
	}
}

func TestHandleDBDeleteRejectsBadName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "Has-Upper"}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsBadOwner(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "has spaces",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}
