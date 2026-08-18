package capabilities

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestIdentifierRegexAcceptsAndRejects(t *testing.T) {
	valid := []string{"a", "wp_example", "site1", strings.Repeat("a", 31)}
	for _, n := range valid {
		if !identifierRe.MatchString(n) {
			t.Errorf("identifierRe rejected valid identifier %q", n)
		}
	}
	invalid := []string{
		"", "1abc", "UPPER", "has space", "has-dash", "has.dot",
		strings.Repeat("a", 32), "drop table users;", "../../etc/passwd",
	}
	for _, n := range invalid {
		if identifierRe.MatchString(n) {
			t.Errorf("identifierRe accepted invalid identifier %q", n)
		}
	}
}

// These validation failures happen before handleDBCreate ever opens a
// MariaDB connection, so they're safe to exercise without a real database
// server present (this environment has none — see db.go's mariaDBConn).
func TestHandleDBCreateRejectsInvalidInputBeforeConnecting(t *testing.T) {
	noopProgress := func(string) {}

	cases := []struct {
		name   string
		params map[string]any
	}{
		{"bad database name", map[string]any{"name": "DROP TABLE", "owner_user": "u1", "owner_password": "01234567890123456789"}},
		{"bad owner_user", map[string]any{"name": "wp_example", "owner_user": "Robert'); DROP TABLE Students;--", "owner_password": "01234567890123456789"}},
		{"short password", map[string]any{"name": "wp_example", "owner_user": "wp_u", "owner_password": "short"}},
		{"empty everything", map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handleDBCreate(context.Background(), tc.params, noopProgress)
			if err == nil {
				t.Fatalf("expected an error for %s, got none", tc.name)
			}
		})
	}
}

func TestHandleDBDeleteRejectsInvalidDatabaseName(t *testing.T) {
	noopProgress := func(string) {}
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "bad name"}, noopProgress)
	if err == nil {
		t.Fatal("expected an error for an invalid database name")
	}
}

func TestDBResultJSONRoundTrips(t *testing.T) {
	res := dbResult{Name: "wp_example", Owner: "wp_example_u1a2b3"}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got dbResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != res {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, res)
	}
}
