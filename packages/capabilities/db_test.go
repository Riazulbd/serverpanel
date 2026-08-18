package capabilities

import (
	"context"
	"testing"
)

// These tests cover handleDBCreate/handleDBDelete's parameter validation,
// which runs and returns an error before anything ever touches a MariaDB
// connection — so they run without a live database, unlike the real
// CREATE DATABASE/CREATE USER round trip (manually verified in a prior
// session against a real Ubuntu host; see docs/TESTING.md).

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Bad-Name!", "owner_user": "app_owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "not a valid user", "owner_password": "0123456789abcdef",
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
		t.Fatal("expected a too-short owner_password to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "Not Valid"}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "app_db", "owner_user": "Not Valid",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestIdentifierRegexAllowsExpectedNames(t *testing.T) {
	valid := []string{"a", "app_db", "wp_example123", "u_9f3a2b1c"}
	for _, v := range valid {
		if !identifierRe.MatchString(v) {
			t.Errorf("expected %q to be a valid identifier", v)
		}
	}
	invalid := []string{"", "Bad", "1leadingdigit", "has space", "has-dash", "semi;colon", "`backtick`"}
	for _, v := range invalid {
		if identifierRe.MatchString(v) {
			t.Errorf("expected %q to be rejected as an identifier", v)
		}
	}
}
