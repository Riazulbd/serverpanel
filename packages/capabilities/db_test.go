package capabilities

import (
	"context"
	"strings"
	"testing"
)

// These cover only handleDBCreate/handleDBDelete's validation paths, which
// run and return before ever opening a MariaDB connection (see db.go) — so
// they're safe to run in any environment, including this one, which has no
// MariaDB installed. The real CREATE DATABASE/CREATE USER/GRANT/DROP SQL
// these handlers issue past validation remains manually-verified-only; see
// TESTING.md.

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Not-Valid!", "owner_user": "ok_user", "owner_password": strings.Repeat("x", 16),
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an invalid database name")
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "ok_name", "owner_user": "Not-Valid!", "owner_password": strings.Repeat("x", 16),
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "ok_name", "owner_user": "ok_user", "owner_password": "short",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for a password under 16 characters")
	}
}

func TestHandleDBCreateRejectsOversizedName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "a" + strings.Repeat("b", 40), "owner_user": "ok_user", "owner_password": strings.Repeat("x", 16),
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for a database name over the identifier length limit")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "'; DROP TABLE users; --",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an invalid database name")
	}
}

func TestIdentifierRegexRejectsSQLInjectionShapedInput(t *testing.T) {
	badInputs := []string{
		"", "1abc", "ABC", "abc def", "abc;drop", "abc`--", "abc'or'1'='1",
	}
	for _, in := range badInputs {
		if identifierRe.MatchString(in) {
			t.Errorf("identifierRe unexpectedly matched %q", in)
		}
	}
	goodInputs := []string{"a", "abc123", "wp_myapp_2", strings.Repeat("a", 31)}
	for _, in := range goodInputs {
		if !identifierRe.MatchString(in) {
			t.Errorf("identifierRe unexpectedly rejected %q", in)
		}
	}
}
