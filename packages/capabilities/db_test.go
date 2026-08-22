package capabilities

import (
	"context"
	"testing"
)

func noopProgress(string) {}

func TestHandleDBCreateRejectsInvalidIdentifiers(t *testing.T) {
	cases := []struct {
		name  string
		owner string
		pass  string
	}{
		{"Bad-Name", "owner", "12345678901234567890"},
		{"good_name", "Bad-Owner", "12345678901234567890"},
		{"good_name", "good_owner", "short"},
	}
	for _, c := range cases {
		_, err := handleDBCreate(context.Background(), map[string]any{
			"name": c.name, "owner_user": c.owner, "owner_password": c.pass,
		}, noopProgress)
		if err == nil {
			t.Fatalf("expected rejection for name=%q owner=%q pass_len=%d", c.name, c.owner, len(c.pass))
		}
	}
}

func TestHandleDBDeleteRejectsInvalidIdentifiers(t *testing.T) {
	if _, err := handleDBDelete(context.Background(), map[string]any{
		"name": "Not Valid",
	}, noopProgress); err == nil {
		t.Fatal("expected rejection for an invalid database name")
	}
	if _, err := handleDBDelete(context.Background(), map[string]any{
		"name": "valid_name", "owner_user": "Also Not Valid",
	}, noopProgress); err == nil {
		t.Fatal("expected rejection for an invalid owner_user")
	}
}
