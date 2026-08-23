package capabilities

import (
	"context"
	"strings"
	"testing"
)

func TestValidateCronScheduleAcceptsStandardForms(t *testing.T) {
	valid := []string{
		"* * * * *", "0 3 * * *", "*/15 * * * *", "0,30 9-17 * * 1-5",
		"@daily", "@hourly", "@weekly", "@reboot",
	}
	for _, s := range valid {
		if err := ValidateCronSchedule(s); err != nil {
			t.Errorf("ValidateCronSchedule(%q) = %v, want nil", s, err)
		}
	}
}

func TestValidateCronScheduleRejectsUnsafeOrMalformed(t *testing.T) {
	invalid := []string{
		"", "* * * *", "* * * * * *", "* * * * a",
		"* * * * *; rm -rf /", "$(whoami) * * * *", "* * * * */bin/sh",
		"@bogus",
	}
	for _, s := range invalid {
		if err := ValidateCronSchedule(s); err == nil {
			t.Errorf("ValidateCronSchedule(%q) = nil, want error", s)
		}
	}
}

func TestValidateCronCommandRejectsEmptyNewlinesAndOverlong(t *testing.T) {
	if err := ValidateCronCommand(""); err == nil {
		t.Error("empty command should be rejected")
	}
	if err := ValidateCronCommand("php /home/sites/site_example/artisan schedule:run\n0 0 * * * rm -rf /"); err == nil {
		t.Error("command with embedded newline should be rejected (crontab line injection)")
	}
	if err := ValidateCronCommand(strings.Repeat("a", maxCronCommandLen+1)); err == nil {
		t.Error("overlong command should be rejected")
	}
	if err := ValidateCronCommand("php /home/sites/site_example/artisan schedule:run >> /dev/null 2>&1"); err != nil {
		t.Errorf("ordinary command should be accepted, got %v", err)
	}
}

func TestBuildCrontabContentRendersEnabledAndDisabledJobs(t *testing.T) {
	jobs := []cronJobSpec{
		{Schedule: "* * * * *", Command: "php /home/sites/site_example/artisan schedule:run", Comment: "Laravel scheduler", Enabled: true},
		{Schedule: "@daily", Command: "wp cron event run --due-now", Comment: "", Enabled: false},
	}
	content, err := buildCrontabContent("site_example", jobs)
	if err != nil {
		t.Fatalf("buildCrontabContent: %v", err)
	}
	if !strings.Contains(content, "SHELL=/bin/sh") {
		t.Error("crontab must set SHELL explicitly")
	}
	if !strings.Contains(content, "# Laravel scheduler\n* * * * * php /home/sites/site_example/artisan schedule:run") {
		t.Errorf("enabled job not rendered as expected, got:\n%s", content)
	}
	if !strings.Contains(content, "#@daily wp cron event run --due-now") {
		t.Errorf("disabled job must be commented out, got:\n%s", content)
	}
}

func TestBuildCrontabContentRejectsInvalidJob(t *testing.T) {
	jobs := []cronJobSpec{{Schedule: "not a schedule", Command: "echo hi", Enabled: true}}
	if _, err := buildCrontabContent("site_example", jobs); err == nil {
		t.Error("expected an error for an invalid schedule in the job list")
	}
}

func TestOneLineCollapsesNewlines(t *testing.T) {
	if got := oneLine("first\nsecond\r\nthird"); got != "first second third" {
		t.Errorf("oneLine = %q", got)
	}
}

func TestHandleCronApplyRejectsUnscopedSystemUser(t *testing.T) {
	_, err := handleCronApply(context.Background(), map[string]any{
		"system_user": "root",
		"jobs":        []any{},
	}, func(string) {})
	if err == nil {
		t.Error("expected an error for a system_user outside the site_ namespace")
	}
}

func TestHandleCronApplyRejectsInvalidJobEntry(t *testing.T) {
	_, err := handleCronApply(context.Background(), map[string]any{
		"system_user": "site_example",
		"jobs":        []any{"not-a-map"},
	}, func(string) {})
	if err == nil {
		t.Error("expected an error for a malformed job entry")
	}
}
