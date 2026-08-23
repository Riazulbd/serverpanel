package capabilities

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestIdentifierPatternMatchesIdentifierRe(t *testing.T) {
	// IdentifierPattern is exported for the control plane to reuse (see
	// apps/controlplane/databases.go) — this test guards against the two
	// ever drifting apart.
	if IdentifierPattern != identifierRe.String() {
		t.Fatalf("IdentifierPattern = %q, want it to match identifierRe.String() = %q", IdentifierPattern, identifierRe.String())
	}
}

func TestIdentifierRegexAcceptsAndRejects(t *testing.T) {
	valid := []string{"a", "wp_example", "db1", strings.Repeat("a", 31)}
	for _, id := range valid {
		if !identifierRe.MatchString(id) {
			t.Errorf("identifierRe rejected valid identifier %q", id)
		}
	}
	invalid := []string{
		"", "1abc", "Abc", "wp-example", "wp example", strings.Repeat("a", 32),
		"wp;drop table users", "`wp`", "wp.example",
	}
	for _, id := range invalid {
		if identifierRe.MatchString(id) {
			t.Errorf("identifierRe accepted invalid identifier %q", id)
		}
	}
}

func TestHandleDBCreateRejectsInvalidNameBeforeConnecting(t *testing.T) {
	// No MariaDB is available in this test environment; if validation didn't
	// run before mariaDBConn(), this would hang/fail on a connection error
	// instead of returning the specific validation error.
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp;drop table users", "owner_user": "wp_owner", "owner_password": "a-strong-password-value",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected before any connection is attempted")
	}
	if !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("error = %q, want it to mention the invalid name", err.Error())
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "Not-Valid", "owner_password": "a-strong-password-value",
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
		"name": "wp_example", "owner_user": "wp_example", "owner_password": "short",
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
		t.Fatal("expected an invalid database name to be rejected before any connection is attempted")
	}
}

func TestDBResultRoundTripsThroughJSON(t *testing.T) {
	// This is the wire contract handleCreateDatabase (control plane) relies
	// on to parse db.create's TaskEvent detail — see
	// apps/controlplane/databases.go.
	want := dbResult{Name: "wp_example", OwnerUser: "wp_owner"}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got dbResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got != want {
		t.Fatalf("dbResult round trip = %+v, want %+v", got, want)
	}
}
