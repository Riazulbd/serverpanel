package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These tests exercise handleDBCreate/handleDBDelete's validation boundary
// only — the code path up to (but never reaching) mariaDBConn(), so they
// run without a real MariaDB instance. The success path (an actual CREATE
// DATABASE/USER round trip) is verified manually against a real Ubuntu
// host, documented in docs/TESTING.md, matching the rest of this file's
// MariaDB-dependent capabilities.

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "not-valid; DROP TABLE users;", "owner_user": "app_user", "owner_password": "correcthorsebatterystaple",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("error = %q, want it to mention the invalid name", err.Error())
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "app'; --", "owner_password": "correcthorsebatterystaple",
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
		"name": "app_db", "owner_user": "app_user", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected a short owner_password to be rejected")
	}
	if !strings.Contains(err.Error(), "owner_password") {
		t.Fatalf("error = %q, want it to mention owner_password", err.Error())
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "../../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}
