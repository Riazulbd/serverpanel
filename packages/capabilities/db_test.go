package capabilities

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// These tests cover db.go's input-validation layer only — the part that
// runs before any connection to MariaDB is attempted. A real create/delete/
// set_password round trip needs a live MariaDB instance (root over the
// local Unix socket), which this environment does not have; that gap is
// tracked as BLOCKED_EXTERNAL in docs/SERVERAVATAR_PARITY.md (DB-001) and
// was manually verified against a real MariaDB 10.11 host in a prior
// session per docs/TESTING.md.

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "not-valid; DROP TABLE users;", "owner_user": "someuser", "owner_password": "a-very-long-password-1",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected before any DB connection is attempted")
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "validdb", "owner_user": "bad owner", "owner_password": "a-very-long-password-1",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected before any DB connection is attempted")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "validdb", "owner_user": "validowner", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected a short owner_password to be rejected before any DB connection is attempted")
	}
	if !strings.Contains(err.Error(), "16 characters") {
		t.Fatalf("expected error to explain the minimum length, got: %v", err)
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "`; DROP DATABASE mysql; --",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected before any DB connection is attempted")
	}
}

// TestHandleDBDeleteRejectsInvalidOwnerBeforeDropping is the regression test
// for the fix that moved owner_user validation ahead of the DROP DATABASE
// call: a caller-supplied owner_user that fails validation must never leave
// the database already dropped.
func TestHandleDBDeleteRejectsInvalidOwnerBeforeDropping(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "validdb", "owner_user": "bad owner; --",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
	if strings.Contains(err.Error(), "drop database") {
		t.Fatalf("owner_user validation must happen before any DROP DATABASE attempt, got: %v", err)
	}
}

func TestHandleDBSetPasswordRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBSetPassword(context.Background(), map[string]any{
		"owner_user": "bad owner", "new_password": "a-very-long-password-1",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected before any DB connection is attempted")
	}
}

func TestHandleDBSetPasswordRejectsShortPassword(t *testing.T) {
	_, err := handleDBSetPassword(context.Background(), map[string]any{
		"owner_user": "validowner", "new_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected a short new_password to be rejected before any DB connection is attempted")
	}
}

// TestDBCreateResultJSONShape locks the wire format the control plane's
// databases.go parses (Name/OwnerUser) so a future refactor of db.go can't
// silently break that contract without a test failing here first.
func TestDBCreateResultJSONShape(t *testing.T) {
	out, err := json.Marshal(dbCreateResult{Name: "mydb", OwnerUser: "mydb_owner"})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Name != "mydb" || parsed.OwnerUser != "mydb_owner" {
		t.Fatalf("unexpected JSON shape: %s", out)
	}
}
