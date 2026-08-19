package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These tests cover handleDBCreate/handleDBDelete's input-validation
// boundary only. They deliberately never reach mariaDBConn's actual
// connection attempt (no MariaDB is available in this environment — see
// TESTING.md), which is safe because every validation check below runs
// before that call.

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Invalid-Name!", "owner_user": "valid_owner", "owner_password": strings.Repeat("x", 20),
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid database name")
	}
	if !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("error = %q, want it to mention the invalid name", err.Error())
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "valid_db", "owner_user": "Not Valid", "owner_password": strings.Repeat("x", 20),
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user")
	}
	if !strings.Contains(err.Error(), "invalid owner_user") {
		t.Fatalf("error = %q, want it to mention the invalid owner_user", err.Error())
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "valid_db", "owner_user": "valid_owner", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for a password under 16 characters")
	}
	if !strings.Contains(err.Error(), "owner_password") {
		t.Fatalf("error = %q, want it to mention owner_password", err.Error())
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "Invalid-Name!",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid database name")
	}
}

func TestHandleDBDeleteRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "valid_db", "owner_user": "Not Valid",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user")
	}
}
