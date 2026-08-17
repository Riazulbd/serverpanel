package capabilities

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// These tests cover only the validation paths of handleDBCreate/
// handleDBDelete/handleDBList that reject before ever dialing MariaDB over
// the local Unix socket — this environment has no MariaDB running, matching
// how backup_test.go and TESTING.md handle capabilities that need a real
// database server (manually verified in a prior session against a live
// MariaDB 10.11 instance; see docs/SERVERAVATAR_PARITY.md DB-001).

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Invalid-Name!", "owner_user": "app_user", "owner_password": strings.Repeat("x", 20),
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "not a valid user", "owner_password": strings.Repeat("x", 20),
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "app_user", "owner_password": "tooshort",
	}, nil)
	if err == nil {
		t.Fatal("expected a short owner_password to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "../etc/passwd"}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "app_db", "owner_user": "bad owner"}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestIdentifierRe(t *testing.T) {
	valid := []string{"app_db", "a", "app_db_2"}
	invalid := []string{"", "App_Db", "2apps", "app-db", "app db", strings.Repeat("a", 32)}
	for _, v := range valid {
		if !IdentifierRe.MatchString(v) {
			t.Errorf("expected %q to be a valid identifier", v)
		}
	}
	for _, v := range invalid {
		if IdentifierRe.MatchString(v) {
			t.Errorf("expected %q to be rejected as an identifier", v)
		}
	}
}

// dbResultJSONShape locks in the wire format the control plane parses
// (apps/controlplane/databases.go) — a regression here would silently break
// database creation persistence without any test failing on the agent side
// alone, since handleDBCreate itself can't be exercised end-to-end without a
// real MariaDB.
func TestDBResultJSONShape(t *testing.T) {
	b, err := json.Marshal(dbResult{Name: "app_db", Owner: "app_user", Host: "localhost"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"name", "owner_user", "host"} {
		if _, ok := got[key]; !ok {
			t.Errorf("expected dbResult JSON to have key %q, got %v", key, got)
		}
	}
	if _, ok := got["password"]; ok {
		t.Error("dbResult JSON must never include a password field")
	}
}
