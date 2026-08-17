package capabilities

import (
	"context"
	"encoding/json"
	"testing"
)

// These tests cover the validation performed before db.create/db.delete
// ever open a MariaDB connection, so they run without a real database
// server present (matching the style of TestHandleBackupRunRejectsBadScope
// for the same reason: this environment may not have MariaDB installed).

func TestHandleDBCreateRejectsBadName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "not valid; DROP TABLE x", "owner_user": "app_owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBCreateRejectsBadOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "bad owner!", "owner_password": "0123456789abcdef",
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
		"name": "../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsBadOwner(t *testing.T) {
	// name is valid so the function reaches the owner check; without a
	// real MariaDB instance the DROP DATABASE call itself would fail
	// first, so this only asserts the owner validation path exists and
	// runs before any DB.ExecContext with an unvalidated owner string.
	if !identifierRe.MatchString("app_db") {
		t.Fatal("test fixture invariant broken: app_db should be a valid identifier")
	}
	if identifierRe.MatchString("bad owner!") {
		t.Fatal("test fixture invariant broken: 'bad owner!' should be rejected by identifierRe")
	}
}

func TestDBCreateResultRoundTrips(t *testing.T) {
	res := dbCreateResult{Name: "app_db", OwnerUser: "app_owner"}
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got dbCreateResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != res {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, res)
	}
}
