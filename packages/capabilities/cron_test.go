package capabilities

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestValidateCronSchedule(t *testing.T) {
	valid := []string{"* * * * *", "0 3 * * *", "*/15 * * * *", "0,30 8-18 * * 1-5"}
	for _, s := range valid {
		if err := validateCronSchedule(s); err != nil {
			t.Errorf("expected %q to be valid, got %v", s, err)
		}
	}

	invalid := []string{
		"* * * *",             // only 4 fields
		"* * * * * *",         // 6 fields
		"* * * * $(rm -rf /)", // command substitution attempt
		"* * * * ; rm -rf /",  // shell metacharacter
		"",
	}
	for _, s := range invalid {
		if err := validateCronSchedule(s); err == nil {
			t.Errorf("expected %q to be rejected", s)
		}
	}
}

func TestValidateCronCommand(t *testing.T) {
	if err := validateCronCommand(""); err == nil {
		t.Error("expected empty command to be rejected")
	}
	if err := validateCronCommand(strings.Repeat("a", 2001)); err == nil {
		t.Error("expected an over-length command to be rejected")
	}
	if err := validateCronCommand("php /home/sites/site_example/artisan schedule:run\nrm -rf /"); err == nil {
		t.Error("expected a newline-smuggling command to be rejected")
	}
	if err := validateCronCommand("php /home/sites/site_example/artisan schedule:run >> /dev/null 2>&1"); err != nil {
		t.Errorf("expected an ordinary shell command line to be accepted, got %v", err)
	}
}

func TestValidCronSystemUserRejectsNonSiteUsers(t *testing.T) {
	if err := validCronSystemUser(context.Background(), "root"); err == nil {
		t.Error("expected root to be rejected as a cron target")
	}
	if err := validCronSystemUser(context.Background(), ""); err == nil {
		t.Error("expected an empty system_user to be rejected")
	}
}

func TestUpsertAndRemoveCronBlockPreservesUnrelatedContent(t *testing.T) {
	existing := "MAILTO=\"\"\n0 0 * * * /usr/local/bin/some-other-tool\n"

	withJob := upsertCronBlock(existing, "cron_abc", "*/5 * * * *", "wp cron event run --due-now", true)
	if !strings.Contains(withJob, "/usr/local/bin/some-other-tool") {
		t.Fatal("expected upsert to preserve a pre-existing, unrelated crontab line")
	}
	if !strings.Contains(withJob, cronMarkerPrefix+"cron_abc") {
		t.Fatal("expected a marker line for the new job")
	}
	if !strings.Contains(withJob, "*/5 * * * * wp cron event run --due-now") {
		t.Fatal("expected an active (uncommented) entry line")
	}

	disabled := upsertCronBlock(withJob, "cron_abc", "*/5 * * * *", "wp cron event run --due-now", false)
	if !strings.Contains(disabled, "#*/5 * * * * wp cron event run --due-now") {
		t.Fatal("expected disabling the job to comment out its entry line while keeping schedule/command intact")
	}

	removed := removeCronBlock(disabled, "cron_abc")
	if strings.Contains(removed, "cron_abc") {
		t.Fatal("expected removeCronBlock to fully remove the job's block")
	}
	if !strings.Contains(removed, "/usr/local/bin/some-other-tool") {
		t.Fatal("expected removeCronBlock to leave unrelated lines untouched")
	}
}

func TestHandleCronUpsertRejectsInvalidParams(t *testing.T) {
	if _, err := handleCronUpsert(context.Background(), map[string]any{
		"system_user": "root", "job_id": "cron_1", "schedule": "* * * * *", "command": "true",
	}, nil); err == nil {
		t.Error("expected handleCronUpsert to reject a non-site system_user before ever touching a real crontab")
	}
	if _, err := handleCronUpsert(context.Background(), map[string]any{
		"system_user": "site_example", "job_id": "not a valid id!", "schedule": "* * * * *", "command": "true",
	}, nil); err == nil {
		t.Error("expected handleCronUpsert to reject a malformed job_id")
	}
}

// TestCronRoundTripAgainstRealCrontab exercises handleCronUpsert/
// handleCronDelete against the real `crontab` binary and a real,
// disposable system user — skipped where either isn't available (e.g. an
// unprivileged CI container), matching ensureTestSystemUser's convention
// in backup_test.go.
func TestCronRoundTripAgainstRealCrontab(t *testing.T) {
	if _, err := exec.LookPath("crontab"); err != nil {
		t.Skipf("crontab not available in this environment: %v", err)
	}
	sysUser := "site_crontest"
	ensureTestSystemUser(t, sysUser)
	t.Cleanup(func() { exec.Command("crontab", "-u", sysUser, "-r").Run() })

	ctx := context.Background()

	out, err := handleCronUpsert(ctx, map[string]any{
		"system_user": sysUser, "job_id": "cron_1", "schedule": "*/5 * * * *", "command": "true", "enabled": true,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleCronUpsert (create): %v", err)
	}
	var res cronJobResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !res.Enabled || res.Schedule != "*/5 * * * *" {
		t.Fatalf("unexpected result: %+v", res)
	}

	crontab, err := readCrontab(ctx, sysUser)
	if err != nil {
		t.Fatalf("readCrontab: %v", err)
	}
	if !strings.Contains(crontab, "*/5 * * * * true") {
		t.Fatalf("expected the new job in the real crontab, got: %q", crontab)
	}

	if _, err := handleCronUpsert(ctx, map[string]any{
		"system_user": sysUser, "job_id": "cron_1", "schedule": "*/5 * * * *", "command": "true", "enabled": false,
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronUpsert (disable): %v", err)
	}
	crontab, _ = readCrontab(ctx, sysUser)
	if !strings.Contains(crontab, "#*/5 * * * * true") {
		t.Fatalf("expected the job to be commented out after disabling, got: %q", crontab)
	}

	if _, err := handleCronDelete(ctx, map[string]any{"system_user": sysUser, "job_id": "cron_1"}, func(string) {}); err != nil {
		t.Fatalf("handleCronDelete: %v", err)
	}
	crontab, _ = readCrontab(ctx, sysUser)
	if strings.Contains(crontab, "cron_1") {
		t.Fatalf("expected job to be gone after delete, got: %q", crontab)
	}
}
