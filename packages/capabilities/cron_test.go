package capabilities

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func requireCrontab(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("crontab"); err != nil {
		t.Skipf("crontab not available in this environment: %v", err)
	}
}

func TestValidateCronScheduleAcceptsAndRejects(t *testing.T) {
	valid := []string{"* * * * *", "0 0 * * *", "*/5 * * * *", "0,30 9-17 * * 1-5"}
	for _, s := range valid {
		if err := validateCronSchedule(s); err != nil {
			t.Errorf("validateCronSchedule(%q) rejected a valid schedule: %v", s, err)
		}
	}
	invalid := []string{"", "* * * *", "* * * * * *", "@daily", "* * * * MON", "* * * * *; rm -rf /"}
	for _, s := range invalid {
		if err := validateCronSchedule(s); err == nil {
			t.Errorf("validateCronSchedule(%q) accepted an invalid schedule", s)
		}
	}
}

func TestValidateCronCommandRejectsInjectionAttempts(t *testing.T) {
	if _, err := validateCronCommand(""); err == nil {
		t.Error("empty command should be rejected")
	}
	if _, err := validateCronCommand("php artisan schedule:run # serverpanel-cron:evil"); err == nil {
		t.Error("command containing '#' should be rejected (breaks the trailing marker)")
	}
	if _, err := validateCronCommand("echo hi\n* * * * * echo injected"); err == nil {
		t.Error("command containing a newline (extra crontab line injection) should be rejected")
	}
	if _, err := validateCronCommand(strings.Repeat("a", 2001)); err == nil {
		t.Error("overlong command should be rejected")
	}
	got, err := validateCronCommand("  php artisan schedule:run  ")
	if err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	if got != "php artisan schedule:run" {
		t.Errorf("validateCronCommand did not trim: %q", got)
	}
}

func TestValidateCronUserRejectsNonSiteAccounts(t *testing.T) {
	if err := validateCronUser("root"); err == nil {
		t.Error("root must never be an allowed cron system_user")
	}
	if err := validateCronUser(""); err == nil {
		t.Error("empty system_user must be rejected")
	}
	if err := validateCronUser("site_example_com"); err != nil {
		t.Errorf("valid site_ user rejected: %v", err)
	}
}

func TestCronLineIDRoundTrip(t *testing.T) {
	id, ok := cronLineID("* * * * * echo hi # serverpanel-cron:abc123")
	if !ok || id != "abc123" {
		t.Fatalf("cronLineID = %q, %v; want abc123, true", id, ok)
	}
	if _, ok := cronLineID("* * * * * echo hi"); ok {
		t.Fatal("a line with no marker must report ok=false")
	}
}

// TestCronLifecycle exercises create -> disable -> enable -> delete
// against a real system user's real crontab (via the real `crontab`
// binary), verifying the managed line is added, toggled, and removed
// without disturbing an unrelated line already present in that user's
// crontab.
func TestCronLifecycle(t *testing.T) {
	requireCrontab(t)
	user := "site_crontest"
	ensureTestSystemUser(t, user)
	ctx := context.Background()

	preexisting := "0 3 * * * /usr/bin/true"
	if err := writeCrontabLines(ctx, user, []string{preexisting}); err != nil {
		t.Fatalf("seeding pre-existing crontab entry: %v", err)
	}

	if _, err := handleCronCreate(ctx, map[string]any{
		"system_user": user, "schedule": "*/5 * * * *", "command": "/usr/bin/true --deploy", "id": "job1",
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronCreate: %v", err)
	}

	lines, err := readCrontabLines(ctx, user)
	if err != nil {
		t.Fatalf("readCrontabLines: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 crontab lines after create (1 pre-existing + 1 managed), got %d: %v", len(lines), lines)
	}
	found := false
	for _, l := range lines {
		if l == preexisting {
			found = true
		}
	}
	if !found {
		t.Fatalf("pre-existing crontab line was disturbed: %v", lines)
	}

	// Duplicate id must be rejected.
	if _, err := handleCronCreate(ctx, map[string]any{
		"system_user": user, "schedule": "* * * * *", "command": "/usr/bin/true", "id": "job1",
	}, func(string) {}); err == nil {
		t.Fatal("creating a cron job with a duplicate id should fail")
	}

	// Disable, verify the schedule/command survive as a recognizable
	// comment (not deleted, not garbled).
	if _, err := handleCronSetEnabled(ctx, map[string]any{
		"system_user": user, "id": "job1", "enabled": false,
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronSetEnabled(disable): %v", err)
	}
	lines, _ = readCrontabLines(ctx, user)
	var disabledLine string
	for _, l := range lines {
		if id, ok := cronLineID(l); ok && id == "job1" {
			disabledLine = l
		}
	}
	if !strings.HasPrefix(disabledLine, cronDisabledPrefix) {
		t.Fatalf("expected disabled line to carry the disabled prefix, got %q", disabledLine)
	}
	if !strings.Contains(disabledLine, "*/5 * * * * /usr/bin/true --deploy") {
		t.Fatalf("disabling must preserve schedule/command, got %q", disabledLine)
	}

	// Re-enable.
	if _, err := handleCronSetEnabled(ctx, map[string]any{
		"system_user": user, "id": "job1", "enabled": true,
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronSetEnabled(enable): %v", err)
	}
	lines, _ = readCrontabLines(ctx, user)
	for _, l := range lines {
		if id, ok := cronLineID(l); ok && id == "job1" && strings.HasPrefix(l, cronDisabledPrefix) {
			t.Fatalf("re-enabled line still carries the disabled prefix: %q", l)
		}
	}

	// Delete, verify only the managed line is gone.
	if _, err := handleCronDelete(ctx, map[string]any{"system_user": user, "id": "job1"}, func(string) {}); err != nil {
		t.Fatalf("handleCronDelete: %v", err)
	}
	lines, _ = readCrontabLines(ctx, user)
	if len(lines) != 1 || lines[0] != preexisting {
		t.Fatalf("expected only the pre-existing line to remain, got %v", lines)
	}

	// Deleting again (already gone) must fail, not silently succeed.
	if _, err := handleCronDelete(ctx, map[string]any{"system_user": user, "id": "job1"}, func(string) {}); err == nil {
		t.Fatal("deleting a nonexistent cron job should fail")
	}
}

func TestCronRejectsNonSiteUserBeforeTouchingCrontab(t *testing.T) {
	// No requireCrontab/ensureTestSystemUser here on purpose: validation
	// must reject "root" before any crontab binary is ever invoked.
	if _, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": "root", "schedule": "* * * * *", "command": "/usr/bin/true", "id": "job1",
	}, func(string) {}); err == nil {
		t.Fatal("cron.create must refuse to touch root's crontab")
	}
}
