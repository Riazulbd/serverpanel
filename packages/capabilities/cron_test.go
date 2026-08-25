package capabilities

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestValidateCronScheduleAcceptsPresetsAndCustomExpressions(t *testing.T) {
	for name, expr := range CronPresets {
		if err := validateCronSchedule(expr); err != nil {
			t.Errorf("preset %q (%q) rejected: %v", name, expr, err)
		}
	}
	valid := []string{
		"*/15 * * * *",
		"0 2 * * 1-5",
		"0,30 9-17 1,15 * *",
		"0 0 1 1,7 *",
	}
	for _, expr := range valid {
		if err := validateCronSchedule(expr); err != nil {
			t.Errorf("expected %q to be a valid schedule, got error: %v", expr, err)
		}
	}
}

func TestValidateCronScheduleRejectsGarbage(t *testing.T) {
	invalid := []string{
		"",
		"* * * *",             // only 4 fields
		"* * * * * *",         // 6 fields
		"60 * * * *",          // minute out of range
		"* 24 * * *",          // hour out of range
		"* * 32 * *",          // day-of-month out of range
		"* * * 13 *",          // month out of range
		"* * * * 8",           // day-of-week out of range
		"* * * * mon",         // names not supported
		"a * * * *",           // garbage token
		"5-2 * * * *",         // inverted range
		"* * * * *; rm -rf /", // shell injection attempt
		"*/0 * * * *",         // zero step
		"* * * * *,",          // trailing empty list segment
	}
	for _, expr := range invalid {
		if err := validateCronSchedule(expr); err == nil {
			t.Errorf("expected %q to be rejected as an invalid schedule", expr)
		}
	}
}

func TestValidateCronCommandAcceptsOrdinaryShellCommands(t *testing.T) {
	valid := []string{
		"/usr/bin/php /home/sites/site_x/artisan schedule:run",
		"cd /home/sites/site_x && /usr/bin/wp cron event run --due-now",
		`echo "a  b" >> /tmp/out.log`, // meaningful internal whitespace preserved
		"/usr/bin/curl -s https://example.com/cron.php | mail -s report ops@example.com",
	}
	for _, cmd := range valid {
		if err := validateCronCommand(cmd); err != nil {
			t.Errorf("expected ordinary shell command %q to be accepted, got: %v", cmd, err)
		}
	}
}

// TestValidateCronCommandRejectsCrontabInjection is the adversarial case the
// task calls out explicitly: a "command" field crafted to break out of its
// own crontab line and smuggle in an entirely separate, arbitrarily
// scheduled cron entry (or corrupt the serverpanel marker line above it).
func TestValidateCronCommandRejectsCrontabInjection(t *testing.T) {
	injections := []string{
		"echo hi\n* * * * * root touch /tmp/pwned",                      // real newline: new crontab line
		"echo hi\r\n* * * * * touch /tmp/pwned",                         // CRLF variant
		"echo hi\n# serverpanel-cron id=cron_evil enabled=true label=x", // forges a marker line
		"echo hi\x00 rm -rf /",                                          // NUL byte
		"echo hi % rm -rf / % more",                                     // unescaped '%' = literal newline to cron
	}
	for _, cmd := range injections {
		if err := validateCronCommand(cmd); err == nil {
			t.Errorf("expected crontab-injection attempt %q to be rejected", cmd)
		}
	}
}

func TestValidateCronCommandRejectsEmptyAndOversized(t *testing.T) {
	if err := validateCronCommand("   "); err == nil {
		t.Error("expected an empty/whitespace-only command to be rejected")
	}
	if err := validateCronCommand(strings.Repeat("a", maxCronCommandLen+1)); err == nil {
		t.Error("expected an oversized command to be rejected")
	}
}

func TestValidateCronCommandAcceptsEscapedPercent(t *testing.T) {
	if err := validateCronCommand(`echo 100\%`); err != nil {
		t.Errorf("expected an escaped '%%' to be accepted, got: %v", err)
	}
}

func TestValidateCronLabelRejectsNewlinesAndOversized(t *testing.T) {
	if err := validateCronLabel("Nightly\nbackup"); err == nil {
		t.Error("expected a label containing a newline to be rejected")
	}
	if err := validateCronLabel(strings.Repeat("x", maxCronLabelLen+1)); err == nil {
		t.Error("expected an oversized label to be rejected")
	}
	if err := validateCronLabel("Nightly backup"); err != nil {
		t.Errorf("expected an ordinary label to be accepted, got: %v", err)
	}
}

func TestParseCrontabPreservesForeignLinesVerbatim(t *testing.T) {
	content := "MAILTO=ops@example.com\n" +
		"# a hand-written comment\n" +
		"@reboot /usr/local/bin/warmup.sh\n" +
		"# serverpanel-cron id=cron_ab12 enabled=true label=Nightly backup\n" +
		"0 2 * * * /usr/bin/backup.sh\n" +
		"0 3 * * * /usr/bin/other-unmanaged-job.sh\n"

	segs := parseCrontab(content)
	entries := cronEntriesOf(segs)
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 managed entry, got %d: %+v", len(entries), entries)
	}
	if entries[0].ID != "cron_ab12" || entries[0].Schedule != "0 2 * * *" || entries[0].Command != "/usr/bin/backup.sh" || !entries[0].Enabled {
		t.Fatalf("unexpected parsed entry: %+v", entries[0])
	}

	rendered := renderCrontab(segs)
	if !strings.Contains(rendered, "MAILTO=ops@example.com") ||
		!strings.Contains(rendered, "# a hand-written comment") ||
		!strings.Contains(rendered, "@reboot /usr/local/bin/warmup.sh") ||
		!strings.Contains(rendered, "0 3 * * * /usr/bin/other-unmanaged-job.sh") {
		t.Fatalf("expected every foreign line to round-trip verbatim, got:\n%s", rendered)
	}
}

func TestParseCrontabPreservesCommandInternalWhitespace(t *testing.T) {
	content := "# serverpanel-cron id=cron_ws01 enabled=true label=\n" +
		"0 2 * * * echo \"a  b   c\"\n"
	entries := cronEntriesOf(parseCrontab(content))
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Command != `echo "a  b   c"` {
		t.Fatalf("command = %q, want internal whitespace preserved exactly", entries[0].Command)
	}
}

func TestCronCreateUpdateDeleteEnableDisableRoundTrip(t *testing.T) {
	var segs []cronSegment // empty crontab to start

	entry := cronEntry{ID: "cron_rt01", Label: "Nightly", Schedule: "0 2 * * *", Command: "/usr/bin/backup.sh", Enabled: true}
	segs = append(segs, cronSegment{entry: &entry})

	rendered := renderCrontab(segs)
	if strings.Contains(rendered, "\n#0 2 * * *") {
		t.Fatalf("newly created enabled entry should not be commented out:\n%s", rendered)
	}

	// Disable it: the entry must become a commented-out line but keep its
	// exact schedule/command, not be deleted.
	segs, err := cronSetEnabled(segs, "cron_rt01", false)
	if err != nil {
		t.Fatalf("cronSetEnabled(disable): %v", err)
	}
	rendered = renderCrontab(segs)
	reparsed := parseCrontab(rendered)
	got := cronFindEntry(reparsed, "cron_rt01")
	if got == nil {
		t.Fatal("expected the disabled entry to still be present after re-parsing")
	}
	if got.Enabled {
		t.Fatal("expected the entry to be disabled")
	}
	if got.Schedule != "0 2 * * *" || got.Command != "/usr/bin/backup.sh" {
		t.Fatalf("disabling must preserve schedule/command exactly, got: %+v", got)
	}
	if !strings.Contains(rendered, "#0 2 * * * /usr/bin/backup.sh") {
		t.Fatalf("expected the schedule/command line to be commented out, got:\n%s", rendered)
	}

	// Re-enable it.
	segs, err = cronSetEnabled(segs, "cron_rt01", true)
	if err != nil {
		t.Fatalf("cronSetEnabled(enable): %v", err)
	}
	got = cronFindEntry(segs, "cron_rt01")
	if !got.Enabled {
		t.Fatal("expected the entry to be enabled again")
	}

	// Update its schedule/command/label, enabled state must be untouched.
	segs, err = cronUpdateEntry(segs, "cron_rt01", "*/5 * * * *", "/usr/bin/other.sh", "Renamed")
	if err != nil {
		t.Fatalf("cronUpdateEntry: %v", err)
	}
	got = cronFindEntry(segs, "cron_rt01")
	if got.Schedule != "*/5 * * * *" || got.Command != "/usr/bin/other.sh" || got.Label != "Renamed" || !got.Enabled {
		t.Fatalf("unexpected entry after update: %+v", got)
	}

	// Delete it.
	segs, err = cronDeleteEntry(segs, "cron_rt01")
	if err != nil {
		t.Fatalf("cronDeleteEntry: %v", err)
	}
	if cronFindEntry(segs, "cron_rt01") != nil {
		t.Fatal("expected the entry to be gone after delete")
	}
	if len(cronEntriesOf(segs)) != 0 {
		t.Fatalf("expected no entries left, got %+v", cronEntriesOf(segs))
	}
}

func TestCronUpdateDeleteSetEnabledRejectUnknownID(t *testing.T) {
	entry := cronEntry{ID: "cron_real", Schedule: "* * * * *", Command: "/bin/true", Enabled: true}
	segs := []cronSegment{{entry: &entry}}

	if _, err := cronUpdateEntry(segs, "cron_missing", "* * * * *", "/bin/true", ""); err == nil {
		t.Error("expected updating an unknown id to be rejected")
	}
	if _, err := cronDeleteEntry(segs, "cron_missing"); err == nil {
		t.Error("expected deleting an unknown id to be rejected")
	}
	if _, err := cronSetEnabled(segs, "cron_missing", false); err == nil {
		t.Error("expected enabling/disabling an unknown id to be rejected")
	}
}

func TestMultipleManagedEntriesCoexistWithForeignLines(t *testing.T) {
	e1 := cronEntry{ID: "cron_a", Schedule: "* * * * *", Command: "/bin/one.sh", Enabled: true}
	e2 := cronEntry{ID: "cron_b", Schedule: "0 * * * *", Command: "/bin/two.sh", Enabled: false}
	segs := []cronSegment{
		{raw: "MAILTO=ops@example.com"},
		{entry: &e1},
		{raw: "@reboot /bin/three.sh"},
		{entry: &e2},
	}
	rendered := renderCrontab(segs)
	reparsed := parseCrontab(rendered)
	entries := cronEntriesOf(reparsed)
	if len(entries) != 2 {
		t.Fatalf("expected 2 managed entries to survive a render/parse round trip, got %d", len(entries))
	}
	if !strings.Contains(rendered, "MAILTO=ops@example.com") || !strings.Contains(rendered, "@reboot /bin/three.sh") {
		t.Fatalf("expected foreign lines interleaved between managed entries to survive, got:\n%s", rendered)
	}
}

func TestValidateManagedSystemUserRejectsBadPrefix(t *testing.T) {
	if _, err := validateManagedSystemUser(context.Background(), map[string]any{"system_user": "root"}); err == nil {
		t.Error("expected a non-site_ system_user to be rejected")
	}
	if _, err := validateManagedSystemUser(context.Background(), map[string]any{"system_user": ""}); err == nil {
		t.Error("expected an empty system_user to be rejected")
	}
	if _, err := validateManagedSystemUser(context.Background(), map[string]any{"system_user": "site_; rm -rf /"}); err == nil {
		t.Error("expected a system_user with shell metacharacters to be rejected")
	}
}

// --- real crontab round trip (skipped where the crontab binary isn't installed) ---

func ensureCrontabAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("crontab"); err != nil {
		t.Skipf("crontab is not installed in this environment: %v", err)
	}
}

func TestHandleCronCreateListDeleteAgainstARealCrontab(t *testing.T) {
	ensureCrontabAvailable(t)
	user := "site_crontest01"
	ensureTestSystemUser(t, user)
	t.Cleanup(func() { exec.Command("crontab", "-u", user, "-r").Run() })

	created, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": user, "schedule": "*/5 * * * *", "command": "/bin/true", "label": "test job",
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleCronCreate: %v", err)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(created), &entry); err != nil {
		t.Fatalf("parse create result: %v", err)
	}
	id, _ := entry["id"].(string)
	if id == "" {
		t.Fatal("expected a generated cron entry id")
	}

	listed, err := handleCronList(context.Background(), map[string]any{"system_user": user}, nil)
	if err != nil {
		t.Fatalf("handleCronList: %v", err)
	}
	if !strings.Contains(listed, id) {
		t.Fatalf("expected the created entry %q to appear in cron.list output: %s", id, listed)
	}

	if _, err := handleCronSetEnabled(context.Background(), map[string]any{
		"system_user": user, "id": id, "enabled": false,
	}, nil); err != nil {
		t.Fatalf("handleCronSetEnabled(disable): %v", err)
	}
	listed, _ = handleCronList(context.Background(), map[string]any{"system_user": user}, nil)
	if !strings.Contains(listed, `"enabled":false`) {
		t.Fatalf("expected the entry to show as disabled: %s", listed)
	}

	if _, err := handleCronDelete(context.Background(), map[string]any{"system_user": user, "id": id}, nil); err != nil {
		t.Fatalf("handleCronDelete: %v", err)
	}
	listed, _ = handleCronList(context.Background(), map[string]any{"system_user": user}, nil)
	if strings.Contains(listed, id) {
		t.Fatalf("expected the entry to be gone after delete: %s", listed)
	}
}

func TestHandleCronCreateRejectsInvalidScheduleAndCommandBeforeTouchingCrontab(t *testing.T) {
	// Runs unconditionally (unlike the real-crontab round-trip test above):
	// an invalid schedule against a nonexistent user must still fail, since
	// either check alone is enough to reject the request without ever
	// invoking the crontab binary.
	if _, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": "site_doesnotexist", "schedule": "bogus", "command": "/bin/true",
	}, nil); err == nil {
		t.Fatal("expected an invalid schedule to be rejected")
	}
}
