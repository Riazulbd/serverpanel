package capabilities

import (
	"context"
	"testing"
)

// These tests cover handleDBCreate/handleDBDelete's validation layer only —
// the identifier allow-list and password-length check that run before any
// MariaDB connection is attempted. The actual CREATE DATABASE/CREATE
// USER/GRANT round trip requires a real MariaDB instance (none is
// available in this environment) and remains manually verified, the same
// documented gap TESTING.md already calls out for db.create/delete's happy
// path.

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "; DROP TABLE users;", "owner_user": "wp_owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for a database name outside identifierRe")
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "not a valid user", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an owner_user outside identifierRe")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "wp_owner", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for a password under 16 characters")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "not valid",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for a database name outside identifierRe")
	}
}

// Note: handleDBDelete only validates owner_user *after* the DROP DATABASE
// call has already succeeded (see db.go) — that path can't be exercised
// without a live MariaDB connection, so it isn't covered here; the name
// check above runs before any connection is made and is the one guaranteed
// safe to test in an environment with no MariaDB.
