package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// newTestCronDir points cronDir at a temp directory for the duration of one
// test, restoring the real value afterward — the same pattern
// newTestBackupBaseDir uses for backupBaseDir.
func newTestCronDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := cronDir
	cronDir = dir
	t.Cleanup(func() { cronDir = orig })
	return dir
}

func TestValidateCronSchedule(t *testing.T) {
	valid := []string{"* * * * *", "0 0 * * *", "*/15 * * * *", "0,30 9-17 1,15 * 1-5"}
	for _, s := range valid {
		if err := validateCronSchedule(s); err != nil {
			t.Errorf("validateCronSchedule(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"",
		"* * * *",                     // only 4 fields
		"* * * * * *",                 // 6 fields
		"MON * * * *",                 // day names not supported
		"* * * * *\ntouch /tmp/pwned", // injection attempt via extra content
	}
	for _, s := range invalid {
		if err := validateCronSchedule(s); err == nil {
			t.Errorf("validateCronSchedule(%q) = nil, want an error", s)
		}
	}
}

func TestValidateCronCommandRejectsNewlines(t *testing.T) {
	if err := validateCronCommand("echo hi\n* * * * * root touch /tmp/pwned"); err == nil {
		t.Fatal("expected a command containing a newline to be rejected")
	}
}

func TestHandleCronListOnMissingFileReturnsEmpty(t *testing.T) {
	newTestCronDir(t)
	out, err := handleCronList(context.Background(), map[string]any{"system_user": "site_example"}, nil)
	if err != nil {
		t.Fatalf("handleCronList: %v", err)
	}
	var entries []cronEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries for a site with no cron file yet, got %v", entries)
	}
}

func TestHandleCronCreateRejectsInvalidUser(t *testing.T) {
	newTestCronDir(t)
	_, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": "root", "id": "cron_1", "schedule": "* * * * *", "command": "echo hi",
	}, nil)
	if err == nil {
		t.Fatal("expected a non-site_ system_user to be rejected")
	}
}

func TestHandleCronCreateAndListRoundTrip(t *testing.T) {
	newTestCronDir(t)
	sysUser := "site_cronuser"
	ensureTestSystemUser(t, sysUser)

	out, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": sysUser, "id": "cron_abc123", "schedule": "0 3 * * *", "command": "php /home/sites/" + sysUser + "/artisan schedule:run",
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleCronCreate: %v", err)
	}
	var created cronEntry
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("parse create result: %v", err)
	}
	if created.ID != "cron_abc123" || !created.Enabled {
		t.Fatalf("unexpected created entry: %+v", created)
	}

	listOut, err := handleCronList(context.Background(), map[string]any{"system_user": sysUser}, nil)
	if err != nil {
		t.Fatalf("handleCronList: %v", err)
	}
	var entries []cronEntry
	if err := json.Unmarshal([]byte(listOut), &entries); err != nil {
		t.Fatalf("parse list result: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "cron_abc123" || entries[0].Schedule != "0 3 * * *" {
		t.Fatalf("unexpected list result: %+v", entries)
	}
}

func TestHandleCronCreateRejectsDuplicateID(t *testing.T) {
	newTestCronDir(t)
	sysUser := "site_dupuser"
	ensureTestSystemUser(t, sysUser)
	params := map[string]any{"system_user": sysUser, "id": "cron_dup", "schedule": "* * * * *", "command": "echo hi"}

	if _, err := handleCronCreate(context.Background(), params, func(string) {}); err != nil {
		t.Fatalf("first handleCronCreate: %v", err)
	}
	if _, err := handleCronCreate(context.Background(), params, func(string) {}); err == nil {
		t.Fatal("expected a duplicate cron id to be rejected")
	}
}

func TestHandleCronSetEnabledTogglesAndPersists(t *testing.T) {
	newTestCronDir(t)
	sysUser := "site_toggleuser"
	ensureTestSystemUser(t, sysUser)

	if _, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": sysUser, "id": "cron_toggle", "schedule": "* * * * *", "command": "echo hi",
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronCreate: %v", err)
	}

	if _, err := handleCronSetEnabled(context.Background(), map[string]any{
		"system_user": sysUser, "id": "cron_toggle", "enabled": false,
	}, nil); err != nil {
		t.Fatalf("handleCronSetEnabled(disable): %v", err)
	}

	entries, err := readCronEntries(sysUser)
	if err != nil {
		t.Fatalf("readCronEntries: %v", err)
	}
	if len(entries) != 1 || entries[0].Enabled {
		t.Fatalf("expected the entry to be disabled, got %+v", entries)
	}
	// Command/schedule must survive the disable round trip unchanged.
	if entries[0].Schedule != "* * * * *" || entries[0].Command != "echo hi" {
		t.Fatalf("disabling mutated the entry's schedule/command: %+v", entries[0])
	}

	if _, err := handleCronSetEnabled(context.Background(), map[string]any{
		"system_user": sysUser, "id": "cron_toggle", "enabled": true,
	}, nil); err != nil {
		t.Fatalf("handleCronSetEnabled(enable): %v", err)
	}
	entries, _ = readCronEntries(sysUser)
	if len(entries) != 1 || !entries[0].Enabled {
		t.Fatalf("expected the entry to be re-enabled, got %+v", entries)
	}
}

func TestHandleCronDeleteRemovesEntry(t *testing.T) {
	newTestCronDir(t)
	sysUser := "site_deluser"
	ensureTestSystemUser(t, sysUser)

	if _, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": sysUser, "id": "cron_keep", "schedule": "* * * * *", "command": "echo keep",
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronCreate(keep): %v", err)
	}
	if _, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": sysUser, "id": "cron_del", "schedule": "0 0 * * *", "command": "echo del",
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronCreate(del): %v", err)
	}

	if _, err := handleCronDelete(context.Background(), map[string]any{"system_user": sysUser, "id": "cron_del"}, nil); err != nil {
		t.Fatalf("handleCronDelete: %v", err)
	}

	entries, err := readCronEntries(sysUser)
	if err != nil {
		t.Fatalf("readCronEntries: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "cron_keep" {
		t.Fatalf("expected only cron_keep to remain, got %+v", entries)
	}
}

func TestHandleCronDeleteLastEntryRemovesFile(t *testing.T) {
	newTestCronDir(t)
	sysUser := "site_lastuser"
	ensureTestSystemUser(t, sysUser)

	if _, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": sysUser, "id": "cron_only", "schedule": "* * * * *", "command": "echo hi",
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronCreate: %v", err)
	}
	if _, err := handleCronDelete(context.Background(), map[string]any{"system_user": sysUser, "id": "cron_only"}, nil); err != nil {
		t.Fatalf("handleCronDelete: %v", err)
	}

	entries, err := readCronEntries(sysUser)
	if err != nil {
		t.Fatalf("readCronEntries after deleting the only entry: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries left, got %v", entries)
	}
	if _, err := os.Stat(cronFilePath(sysUser)); !os.IsNotExist(err) {
		t.Fatal("expected the now-empty cron.d file to have been removed, not left empty on disk")
	}
}

func TestHandleCronDeleteUnknownIDFails(t *testing.T) {
	newTestCronDir(t)
	sysUser := "site_unknownuser"
	ensureTestSystemUser(t, sysUser)
	if _, err := handleCronDelete(context.Background(), map[string]any{"system_user": sysUser, "id": "cron_nope"}, nil); err == nil {
		t.Fatal("expected deleting an unknown cron id to fail")
	}
}
