package capabilities

import (
	"context"
	"strings"
	"testing"
)

func TestValidateCronScheduleAcceptsAndRejects(t *testing.T) {
	valid := []string{"* * * * *", "0 3 * * *", "*/15 * * * *", "0 0 1 1,7 *", "@daily", "@hourly", "@reboot"}
	for _, s := range valid {
		if err := validateCronSchedule(s); err != nil {
			t.Errorf("validateCronSchedule(%q) = %v, want accepted", s, err)
		}
	}
	invalid := []string{"", "* * * *", "* * * * * *", "* * * * MON", "0 3 * * *; rm -rf /", "@daily; rm -rf /"}
	for _, s := range invalid {
		if err := validateCronSchedule(s); err == nil {
			t.Errorf("validateCronSchedule(%q) accepted, want rejected", s)
		}
	}
}

func TestValidateCronCommandRejectsLineBreakingCharacters(t *testing.T) {
	if err := validateCronCommand("php /home/sites/site_x/artisan schedule:run"); err != nil {
		t.Errorf("expected a normal command to be accepted, got %v", err)
	}
	for _, c := range []string{"", strings.Repeat("a", 2001), "echo hi # rm -rf /", "echo hi\n* * * * * rm -rf /"} {
		if err := validateCronCommand(c); err == nil {
			t.Errorf("validateCronCommand(%q) accepted, want rejected", c)
		}
	}
}

func TestValidateCronIDRejectsUnboundedOrUnsafeValues(t *testing.T) {
	if err := validateCronID("cron_abc123"); err != nil {
		t.Errorf("expected a normal id to be accepted, got %v", err)
	}
	for _, id := range []string{"", "cron abc", "cron;rm", strings.Repeat("a", 65)} {
		if err := validateCronID(id); err == nil {
			t.Errorf("validateCronID(%q) accepted, want rejected", id)
		}
	}
}

func TestValidateCronUserRejectsNonManagedAccounts(t *testing.T) {
	// root always exists but its home directory is never under
	// /home/sites/, so it must never be schedulable as a cron target
	// regardless of what a caller passes in.
	if _, err := validateCronUser("root"); err == nil {
		t.Fatal("expected validateCronUser(\"root\") to be rejected")
	}
	if _, err := validateCronUser("this-user-should-not-exist-anywhere"); err == nil {
		t.Fatal("expected an unknown system user to be rejected")
	}
}

func TestFindCronLineMatchesEnabledAndDisabledEntries(t *testing.T) {
	lines := []string{
		"* * * * * /usr/bin/true # spcron:cron_a",
		cronDisabledPrefix + "0 3 * * * /usr/bin/true # spcron:cron_b",
		"@daily /usr/bin/true # spcron:cron_10",
	}
	if idx := findCronLine(lines, "cron_a"); idx != 0 {
		t.Errorf("findCronLine(cron_a) = %d, want 0", idx)
	}
	if idx := findCronLine(lines, "cron_b"); idx != 1 {
		t.Errorf("findCronLine(cron_b) = %d, want 1", idx)
	}
	// A shorter id must not accidentally match a longer id's line
	// (cron_1 must not match the "...cron_10" suffix).
	if idx := findCronLine(lines, "cron_1"); idx != -1 {
		t.Errorf("findCronLine(cron_1) = %d, want -1 (must not match cron_10's line)", idx)
	}
	if idx := findCronLine(lines, "cron_missing"); idx != -1 {
		t.Errorf("findCronLine(cron_missing) = %d, want -1", idx)
	}
}

// TestHandleCronCreateRejectsInvalidInputBeforeAnySystemCall guards the
// same property handleServiceControl/handleSiteCreate already test:
// invalid parameters must fail validation before the handler ever shells
// out to crontab(1) — an unknown/unmanaged user must never reach
// exec.Command regardless of how it's spelled.
func TestHandleCronCreateRejectsInvalidInputBeforeAnySystemCall(t *testing.T) {
	cases := []map[string]any{
		{"id": "cron_a", "user": "root", "schedule": "* * * * *", "command": "true"},
		{"id": "cron a", "user": "root", "schedule": "* * * * *", "command": "true"},
		{"id": "cron_a", "user": "root", "schedule": "not a schedule", "command": "true"},
		{"id": "cron_a", "user": "root", "schedule": "* * * * *", "command": ""},
		{"id": "cron_a", "user": "root", "schedule": "* * * * *", "command": "true # rm -rf /"},
	}
	for _, params := range cases {
		if _, err := handleCronCreate(context.Background(), params, nil); err == nil {
			t.Errorf("handleCronCreate(%v) succeeded, want rejected before any crontab call", params)
		}
	}
}

func TestHandleCronDeleteAndSetEnabledRejectNonManagedUser(t *testing.T) {
	if _, err := handleCronDelete(context.Background(), map[string]any{"id": "cron_a", "user": "root"}, nil); err == nil {
		t.Fatal("expected handleCronDelete to reject a non-managed user")
	}
	if _, err := handleCronSetEnabled(context.Background(), map[string]any{"id": "cron_a", "user": "root", "enabled": true}, nil); err == nil {
		t.Fatal("expected handleCronSetEnabled to reject a non-managed user")
	}
}
