package capabilities

import (
	"context"
	"testing"
)

// These tests cover db.create/db.delete's input-validation boundary only —
// the identifier allow-list and password-length checks all return before
// mariaDBConn() is ever called, so they run without a real MariaDB instance
// (see TESTING.md for what still requires one and is manually verified).

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Not-Valid; DROP TABLE", "owner_user": "wp_e", "owner_password": "a-very-long-password-value",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an invalid database name")
	}
}

func TestHandleDBCreateRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_e", "owner_user": "also invalid", "owner_password": "a-very-long-password-value",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_e", "owner_user": "wp_e", "owner_password": "tooshort",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for a password shorter than 16 characters")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "Not-Valid; DROP TABLE",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an invalid database name")
	}
}

func TestHandleDBDeleteRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "wp_e", "owner_user": "also invalid",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user")
	}
}
