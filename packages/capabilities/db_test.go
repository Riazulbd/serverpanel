package capabilities

import (
	"context"
	"testing"
)

// These tests only exercise validation that happens before any MariaDB
// connection is opened, so they run without a live database — the same
// constraint backup_test.go's scope-validation tests operate under. A real
// CREATE/DROP DATABASE round trip is verified manually against a live
// MariaDB instance (see docs/TESTING.md); it is not exercised by `go test`
// in this environment.

func TestValidDBIdentifier(t *testing.T) {
	valid := []string{"wp_example", "a", "app_2024", "n1234567890123456789012345678"}
	for _, v := range valid {
		if !ValidDBIdentifier(v) {
			t.Errorf("ValidDBIdentifier(%q) = false, want true", v)
		}
	}
	invalid := []string{"", "Wp_Example", "1leading_digit", "has space", "has-dash", "has;semicolon", "toolongtoolongtoolongtoolongtoolong"}
	for _, v := range invalid {
		if ValidDBIdentifier(v) {
			t.Errorf("ValidDBIdentifier(%q) = true, want false", v)
		}
	}
}

func TestHandleDBCreateRejectsInvalidName(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Bad-Name", "owner_user": "owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected before any DB connection is attempted")
	}
}

func TestHandleDBCreateRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "gooddb", "owner_user": "Bad Owner", "owner_password": "0123456789abcdef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}

func TestHandleDBCreateRejectsShortPassword(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "gooddb", "owner_user": "gooduser", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected a too-short owner_password to be rejected")
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "Bad-Name"}, nil)
	if err == nil {
		t.Fatal("expected an invalid database name to be rejected before any DB connection is attempted")
	}
}

func TestHandleDBDeleteRejectsInvalidOwner(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{"name": "gooddb", "owner_user": "Bad Owner"}, nil)
	if err == nil {
		t.Fatal("expected an invalid owner_user to be rejected")
	}
}
