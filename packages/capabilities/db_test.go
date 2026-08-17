package capabilities

import (
	"context"
	"testing"
)

func TestIdentifierRegexAcceptsAndRejects(t *testing.T) {
	valid := []string{"wp_example", "a", "app123", "my_db_1"}
	for _, id := range valid {
		if !identifierRe.MatchString(id) {
			t.Errorf("identifierRe rejected valid identifier %q", id)
		}
	}
	invalid := []string{
		"", "Wp_Example", "1abc", "-abc", "a b", "a;drop table x", "a.b",
		"a`b", "toolongtoolongtoolongtoolongtoolong",
	}
	for _, id := range invalid {
		if identifierRe.MatchString(id) {
			t.Errorf("identifierRe accepted invalid identifier %q", id)
		}
	}
}

func TestHandleDBCreateRejectsInvalidNameBeforeTouchingMariaDB(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "Not-Valid!", "owner_user": "wp_example", "owner_password": "a-long-enough-password",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid database name")
	}
}

func TestHandleDBCreateRejectsInvalidOwnerBeforeTouchingMariaDB(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "Not-Valid!", "owner_password": "a-long-enough-password",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user")
	}
}

func TestHandleDBCreateRejectsShortPasswordBeforeTouchingMariaDB(t *testing.T) {
	_, err := handleDBCreate(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "wp_example", "owner_password": "short",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an owner_password shorter than 16 characters")
	}
}

func TestHandleDBDeleteRejectsInvalidNameBeforeTouchingMariaDB(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "Not-Valid!",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid database name")
	}
}

func TestHandleDBDeleteRejectsInvalidOwnerBeforeTouchingMariaDB(t *testing.T) {
	_, err := handleDBDelete(context.Background(), map[string]any{
		"name": "wp_example", "owner_user": "Not-Valid!",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for an invalid owner_user")
	}
}
