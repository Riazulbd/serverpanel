package capabilities

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// These tests exercise handleDBCreate/handleDBDelete's parameter-validation
// path only. A real create/delete round trip needs a live MariaDB (unix
// socket, root auth) which this environment doesn't have — see
// docs/SERVERAVATAR_PARITY.md DB-001 for the BLOCKED_EXTERNAL note that
// already covers this same limitation for db.create/db.delete's happy path.
// Validation runs entirely before mariaDBConn() is ever called, so it's
// exercised here without needing a database connection at all.

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "not-valid;drop table x", "owner_user": "app_user", "owner_password": "0123456789abcdef",
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
		"name": "app_db", "owner_user": "root; --", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid owner_user") {
		t.Fatalf("error = %q, want it to mention the invalid owner", err.Error())
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
		"name": "; DROP DATABASE mysql", "owner_user": "app_user",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "root; --",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user on delete to be rejected")
	}
}

// TestDBCreateResultShapeMatchesControlPlaneExpectations pins the JSON shape
// apps/controlplane/databases.go's handleCreateDatabase unmarshals — a
// silent field-name mismatch here would compile fine on both sides yet
// break persistence at runtime, so the shape itself is worth locking down.
func TestDBCreateResultShapeMatchesControlPlaneExpectations(t *testing.T) {
	out, err := marshalDBResult(dbCreateResult{Name: "app_db", OwnerUser: "app_user"})
	if err != nil {
		t.Fatalf("marshalDBResult: %v", err)
	}
	var got struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Name != "app_db" || got.OwnerUser != "app_user" {
		t.Fatalf("got %+v, want name=app_db owner_user=app_user", got)
	}
}
