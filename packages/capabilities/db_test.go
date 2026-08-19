package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These tests cover the validation paths of the db.* handlers that run
// before any MariaDB connection is attempted (identifier allow-listing,
// password-length checks). A real create/delete round trip against
// MariaDB is verified manually in an environment that has it — see
// docs/TESTING.md — since this environment has no MariaDB socket to
// connect to.

func TestHandleDBCreateRejectsBadIdentifiers(t *testing.T) {
	noop := func(string) {}

	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"bad db name", map[string]any{"name": "DROP TABLE", "owner_user": "owner", "owner_password": strings.Repeat("x", 20)}, "invalid database name"},
		{"bad owner", map[string]any{"name": "app_db", "owner_user": "bad user", "owner_password": strings.Repeat("x", 20)}, "invalid owner_user"},
		{"short password", map[string]any{"name": "app_db", "owner_user": "owner", "owner_password": "short"}, "at least 16 characters"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := handleDBCreate(context.Background(), c.params, noop)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("handleDBCreate(%v) error = %v, want containing %q", c.params, err, c.want)
			}
		})
	}
}

func TestHandleDBCreateUserRejectsBadIdentifiers(t *testing.T) {
	noop := func(string) {}

	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"bad db name", map[string]any{"db_name": "; DROP", "username": "reader", "password": strings.Repeat("x", 20)}, "invalid db_name"},
		{"bad username", map[string]any{"db_name": "app_db", "username": "Reader!", "password": strings.Repeat("x", 20)}, "invalid username"},
		{"short password", map[string]any{"db_name": "app_db", "username": "reader", "password": "short"}, "at least 16 characters"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := handleDBCreateUser(context.Background(), c.params, noop)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("handleDBCreateUser(%v) error = %v, want containing %q", c.params, err, c.want)
			}
		})
	}
}

func TestHandleDBDeleteRejectsBadIdentifier(t *testing.T) {
	noop := func(string) {}
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "not valid!"}, noop)
	if err == nil || !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("handleDBDelete error = %v, want invalid database name", err)
	}
}

func TestHandleDBDeleteUserRejectsBadIdentifier(t *testing.T) {
	noop := func(string) {}
	_, err := handleDBDeleteUser(context.Background(), map[string]any{"username": "not valid!"}, noop)
	if err == nil || !strings.Contains(err.Error(), "invalid username") {
		t.Fatalf("handleDBDeleteUser error = %v, want invalid username", err)
	}
}
