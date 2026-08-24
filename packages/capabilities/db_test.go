package capabilities

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// These tests cover db.create/db.delete's validation layer only — the layer
// that runs before any MariaDB connection is attempted. A real
// create/grant/drop round trip needs a live MariaDB instance (see
// mariaDBConn) and is verified manually per docs/TESTING.md, not here.

func TestIdentifierRegexAcceptsAndRejects(t *testing.T) {
	valid := []string{"wp_example", "a", "app123", strings.Repeat("a", 31)}
	for _, id := range valid {
		if !identifierRe.MatchString(id) {
			t.Errorf("identifierRe rejected valid identifier %q", id)
		}
	}
	invalid := []string{"", "1abc", "has space", "has-dash", "DROP TABLE", "a; DROP TABLE users;--", strings.Repeat("a", 32)}
	for _, id := range invalid {
		if identifierRe.MatchString(id) {
			t.Errorf("identifierRe accepted invalid identifier %q", id)
		}
	}
}

func TestHandleDBCreateRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"bad database name", map[string]any{"name": "1bad", "owner_user": "owner1", "owner_password": strings.Repeat("x", 20)}},
		{"bad owner user", map[string]any{"name": "gooddb", "owner_user": "bad user", "owner_password": strings.Repeat("x", 20)}},
		{"short password", map[string]any{"name": "gooddb", "owner_user": "owner1", "owner_password": "short"}},
		{"sql injection attempt in name", map[string]any{"name": "a`; DROP TABLE mysql.user; --", "owner_user": "owner1", "owner_password": strings.Repeat("x", 20)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := handleDBCreate(context.Background(), c.params, func(string) {})
			if err == nil {
				t.Fatalf("handleDBCreate(%+v) succeeded, want a validation error (must fail before any DB connection attempt)", c.params)
			}
		})
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "not a valid name"}, func(string) {})
	if err == nil {
		t.Fatal("handleDBDelete with an invalid name succeeded, want a validation error")
	}
}

func TestDBResultRoundTripsAsJSON(t *testing.T) {
	res := dbResult{Name: "wp_example", Owner: "wp_example_owner"}
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal dbResult: %v", err)
	}
	var got dbResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal dbResult: %v", err)
	}
	if got != res {
		t.Fatalf("dbResult round trip = %+v, want %+v", got, res)
	}
}
