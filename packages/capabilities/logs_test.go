package capabilities

import (
	"context"
	"strings"
	"testing"
)

func TestRedactStripsSecretsFromLogLines(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{
			`GET /reset?token=abc123XYZ&next=/ HTTP/1.1`,
			`GET /reset?token=[redacted]&next=/ HTTP/1.1`,
		},
		{
			`Authorization: Bearer sk-super-secret-value`,
			`Authorization: Bearer [redacted]`,
		},
		{
			`Authorization: Basic dXNlcjpwYXNz`,
			`Authorization: Basic [redacted]`,
		},
	}
	for _, c := range cases {
		got := redact(c.line)
		if got != c.want {
			t.Errorf("redact(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestRedactLeavesOrdinaryLinesUntouched(t *testing.T) {
	line := `127.0.0.1 - - [14/Aug/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 512`
	if got := redact(line); got != line {
		t.Errorf("redact modified an ordinary log line: got %q", got)
	}
}

func TestHandleLogsTailRejectsInvalidSystemUser(t *testing.T) {
	_, err := handleLogsTail(context.Background(), map[string]any{
		"system_user": "root", "log_type": "access",
	}, nil)
	if err == nil {
		t.Fatal("expected a system_user without the site_ prefix to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid system_user") {
		t.Fatalf("error = %q, want it to mention invalid system_user", err.Error())
	}
}

func TestHandleLogsTailRejectsInvalidLogType(t *testing.T) {
	_, err := handleLogsTail(context.Background(), map[string]any{
		"system_user": "site_example", "log_type": "../../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid log_type to be rejected")
	}
}
