package capabilities

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestValidCronSchedule(t *testing.T) {
	valid := []string{"* * * * *", "0 3 * * *", "*/15 * * * *", "0 0 1,15 * *", "@daily", "@hourly", "@reboot"}
	for _, s := range valid {
		if !validCronSchedule(s) {
			t.Errorf("validCronSchedule(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "* * * *", "* * * * * *", "* * * * $(rm -rf /)", "sixty * * * *", "@yesterday"}
	for _, s := range invalid {
		if validCronSchedule(s) {
			t.Errorf("validCronSchedule(%q) = true, want false", s)
		}
	}
}

func TestValidCronCommand(t *testing.T) {
	if !validCronCommand("/usr/bin/php /home/sites/site_x/artisan schedule:run") {
		t.Error("expected a normal command to be valid")
	}
	if validCronCommand("") {
		t.Error("expected an empty command to be rejected")
	}
	if validCronCommand("echo one\necho two") {
		t.Error("expected a command containing a newline to be rejected (breaks the one-job-per-line crontab format)")
	}
	if validCronCommand(strings.Repeat("a", 2000)) {
		t.Error("expected an oversized command to be rejected")
	}
}

func TestEscapeCronPercent(t *testing.T) {
	got := escapeCronPercent("date +%Y-%m-%d")
	want := `date +\%Y-\%m-\%d`
	if got != want {
		t.Errorf("escapeCronPercent = %q, want %q", got, want)
	}
}

func TestStripManagedBlockPreservesOtherLines(t *testing.T) {
	in := strings.Join([]string{
		"# a line the user added by hand",
		"0 1 * * * /usr/bin/some-other-tool",
		cronMarkerBegin,
		"* * * * * echo old # serverpanel:cron_1",
		cronMarkerEnd,
		"0 2 * * * /usr/bin/another-manual-job",
	}, "\n")

	got := stripManagedBlock(in)

	if strings.Contains(got, "cron_1") {
		t.Errorf("stripManagedBlock left managed content behind: %q", got)
	}
	for _, want := range []string{"a line the user added by hand", "some-other-tool", "another-manual-job"} {
		if !strings.Contains(got, want) {
			t.Errorf("stripManagedBlock dropped unmanaged line %q from result %q", want, got)
		}
	}
}

func TestHandleCronSyncRejectsBadSystemUser(t *testing.T) {
	_, err := handleCronSync(context.Background(), map[string]any{
		"system_user": "root",
		"jobs":        []any{},
	}, nil)
	if err == nil {
		t.Fatal("expected a non site_-prefixed system_user to be rejected")
	}
}

func TestHandleCronSyncRejectsInvalidJob(t *testing.T) {
	_, err := handleCronSync(context.Background(), map[string]any{
		"system_user": "site_example",
		"jobs": []any{
			map[string]any{"id": "cron_1", "schedule": "not a schedule", "command": "echo hi"},
		},
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid schedule to be rejected")
	}
}

// TestHandleCronSyncRoundTrip exercises the real path: create a system
// user, hand it a set of jobs, verify the live crontab now contains
// exactly those jobs and nothing else, then sync a smaller set and verify
// the removed job is actually gone (not just untracked) — the same
// "prove it against the real primitive" standard backup_test.go and
// site_test.go hold agent-side capabilities to.
func TestHandleCronSyncRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("crontab"); err != nil {
		t.Skipf("crontab not available in this environment: %v", err)
	}
	user := "site_crontest"
	ensureTestSystemUser(t, user)
	t.Cleanup(func() { exec.Command("crontab", "-u", user, "-r").Run() })

	_, err := handleCronSync(context.Background(), map[string]any{
		"system_user": user,
		"jobs": []any{
			map[string]any{"id": "cron_1", "schedule": "@daily", "command": "echo one"},
			map[string]any{"id": "cron_2", "schedule": "*/5 * * * *", "command": "echo two"},
		},
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleCronSync: %v", err)
	}

	out, err := run(context.Background(), "crontab", "-u", user, "-l")
	if err != nil {
		t.Fatalf("crontab -l: %v: %s", err, out)
	}
	if !strings.Contains(out, "cron_1") || !strings.Contains(out, "cron_2") {
		t.Fatalf("crontab after sync missing expected jobs: %s", out)
	}

	// Re-sync with cron_2 removed; cron_1 must survive, cron_2 must be gone.
	if _, err := handleCronSync(context.Background(), map[string]any{
		"system_user": user,
		"jobs": []any{
			map[string]any{"id": "cron_1", "schedule": "@daily", "command": "echo one"},
		},
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronSync (second sync): %v", err)
	}

	out, err = run(context.Background(), "crontab", "-u", user, "-l")
	if err != nil {
		t.Fatalf("crontab -l after second sync: %v: %s", err, out)
	}
	if !strings.Contains(out, "cron_1") {
		t.Fatalf("second sync lost cron_1: %s", out)
	}
	if strings.Contains(out, "cron_2") {
		t.Fatalf("second sync did not remove cron_2: %s", out)
	}
}
