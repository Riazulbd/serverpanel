package capabilities

import (
	"context"
	"strings"
	"testing"
)

func TestValidCronScheduleAcceptsAndRejects(t *testing.T) {
	valid := []string{"* * * * *", "0 3 * * *", "*/15 * * * *", "0,30 9-17 * * 1-5"}
	for _, s := range valid {
		if _, err := validCronSchedule(s); err != nil {
			t.Errorf("validCronSchedule(%q) = %v, want valid", s, err)
		}
	}
	invalid := []string{
		"", "* * * *", "* * * * * *",
		"* * * * *; rm -rf /", "@daily",
	}
	for _, s := range invalid {
		if _, err := validCronSchedule(s); err == nil {
			t.Errorf("validCronSchedule(%q) accepted, want rejected", s)
		}
	}
}

func TestValidCronCommandRejectsNewlinesAndEmpty(t *testing.T) {
	if err := validCronCommand(""); err == nil {
		t.Error("empty command accepted")
	}
	if err := validCronCommand("php /home/sites/site_ex/artisan schedule:run\n# extra"); err == nil {
		t.Error("command with embedded newline accepted — this could inject an extra crontab line")
	}
	if err := validCronCommand(strings.Repeat("a", 2001)); err == nil {
		t.Error("2001-char command accepted, want rejected as too long")
	}
	if err := validCronCommand("php /home/sites/site_ex/artisan schedule:run"); err != nil {
		t.Errorf("valid command rejected: %v", err)
	}
}

func TestCronLineAndParseCrontabRoundTrip(t *testing.T) {
	job := cronJob{ID: "cron_abc123", Schedule: "*/5 * * * *", Command: "php /home/sites/site_ex/artisan schedule:run"}
	line := cronLine(job)

	raw := "SHELL=/bin/sh\n# a human's own comment\n0 4 * * * /usr/bin/some-other-job\n" + line + "\n"
	got := parseCrontab(raw)
	if len(got) != 1 {
		t.Fatalf("parseCrontab found %d managed jobs, want 1 (raw=%q)", len(got), raw)
	}
	if got[0] != job {
		t.Fatalf("parseCrontab round-trip = %+v, want %+v", got[0], job)
	}
}

func TestParseCrontabIgnoresUnmanagedLines(t *testing.T) {
	raw := "0 4 * * * /usr/bin/some-other-job\n# a plain comment\n\n"
	got := parseCrontab(raw)
	if len(got) != 0 {
		t.Fatalf("parseCrontab found %d jobs in a crontab with none of ours, want 0", len(got))
	}
}

func TestCronMarkerSurvivesAsShellComment(t *testing.T) {
	// The marker is appended after the command on the same line. Whether or
	// not the cron daemon itself treats a mid-line "#" as a comment, the
	// whole line's command portion (everything after the 5 schedule fields)
	// is what gets handed to `sh -c` — and in POSIX sh, a "#" preceded by
	// whitespace starts a comment to end of line, so the marker can never
	// become part of what actually executes.
	job := cronJob{ID: "cron_x", Schedule: "* * * * *", Command: "true"}
	line := cronLine(job)
	commandAndMarker := strings.SplitN(line, " ", 6)[5]
	if !strings.HasPrefix(commandAndMarker, "true "+cronMarker) {
		t.Fatalf("expected marker to trail the command separated by whitespace, got %q", commandAndMarker)
	}
}

func TestHandleCronCreateRejectsInvalidSystemUser(t *testing.T) {
	_, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": "root", "id": "cron_1", "schedule": "* * * * *", "command": "true",
	}, nil)
	if err == nil {
		t.Fatal("expected an out-of-scope system_user (root) to be rejected before any crontab is touched")
	}
}

func TestHandleCronCreateRejectsInvalidID(t *testing.T) {
	_, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": "site_example_com", "id": "not valid; injected", "schedule": "* * * * *", "command": "true",
	}, nil)
	if err == nil {
		t.Fatal("expected a malformed id to be rejected")
	}
}

func TestHandleCronDeleteRejectsInvalidSystemUser(t *testing.T) {
	_, err := handleCronDelete(context.Background(), map[string]any{
		"system_user": "www-data", "id": "cron_1",
	}, nil)
	if err == nil {
		t.Fatal("expected an out-of-scope system_user to be rejected")
	}
}

func TestHandleCronListRejectsInvalidSystemUser(t *testing.T) {
	_, err := handleCronList(context.Background(), map[string]any{
		"system_user": "../../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected a path-traversal-shaped system_user to be rejected")
	}
}
