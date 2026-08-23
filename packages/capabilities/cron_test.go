package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestCronDirs points cronDDir/cronMetaDir at temp directories for the
// duration of one test, restoring the real values afterward — the same
// pattern newTestBackupBaseDir uses for backupBaseDir.
func newTestCronDirs(t *testing.T) {
	t.Helper()
	origD, origMeta := cronDDir, cronMetaDir
	cronDDir = filepath.Join(t.TempDir(), "cron.d")
	cronMetaDir = filepath.Join(t.TempDir(), "cron-meta")
	t.Cleanup(func() { cronDDir, cronMetaDir = origD, origMeta })
}

func TestValidateCronSchedule(t *testing.T) {
	valid := []string{"* * * * *", "0 3 * * *", "*/15 * * * *", "0 0 1 1,6 *", "@daily", "@reboot"}
	for _, s := range valid {
		if err := validateCronSchedule(s); err != nil {
			t.Errorf("validateCronSchedule(%q) = %v, want nil", s, err)
		}
	}
	invalid := []string{
		"", "* * * *", "* * * * * *", "* * * * $(rm -rf /)",
		"* * * * *; rm -rf /", "@bogus", "* * * * *\n0 0 * * *",
	}
	for _, s := range invalid {
		if err := validateCronSchedule(s); err == nil {
			t.Errorf("validateCronSchedule(%q) = nil, want an error", s)
		}
	}
}

func TestValidateCronCommandEscapesPercentAndRejectsNewlines(t *testing.T) {
	got, err := validateCronCommand("php artisan schedule:run --date=%Y%m%d")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `php artisan schedule:run --date=\%Y\%m\%d`
	if got != want {
		t.Fatalf("validateCronCommand escaping = %q, want %q", got, want)
	}

	for _, bad := range []string{"", "  ", "echo hi\n0 0 * * * root rm -rf /", "echo\x00hi"} {
		if _, err := validateCronCommand(bad); err == nil {
			t.Errorf("validateCronCommand(%q) = nil, want an error", bad)
		}
	}
}

func TestValidateCronUserRejectsBadShapes(t *testing.T) {
	for _, bad := range []string{"", "root; rm -rf /", "-root", "Site_User", strings.Repeat("a", 40)} {
		if err := validateCronUser(bad); err == nil {
			t.Errorf("validateCronUser(%q) = nil, want an error", bad)
		}
	}
}

func TestCronCreateListDeleteRoundTrip(t *testing.T) {
	newTestCronDirs(t)
	user := "cptest_" + randHex(4)
	ensureTestSystemUser(t, user)

	created, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": user, "schedule": "0 3 * * *", "command": "/usr/bin/php /var/www/artisan schedule:run", "label": "nightly",
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleCronCreate: %v", err)
	}
	var job cronJob
	if err := json.Unmarshal([]byte(created), &job); err != nil {
		t.Fatalf("unmarshal created job: %v", err)
	}
	if job.ID == "" || !job.Enabled || job.Label != "nightly" {
		t.Fatalf("unexpected created job: %+v", job)
	}

	// The cron.d file must exist, be owned by the target user in its
	// generated line, and contain the exact schedule/command.
	dFile := cronDPath(user)
	data, err := os.ReadFile(dFile)
	if err != nil {
		t.Fatalf("read generated cron.d file: %v", err)
	}
	line := "0 3 * * * " + user + " /usr/bin/php /var/www/artisan schedule:run"
	if !strings.Contains(string(data), line) {
		t.Fatalf("cron.d file %q missing expected line %q, got:\n%s", dFile, line, data)
	}

	listed, err := handleCronList(context.Background(), map[string]any{"system_user": user}, nil)
	if err != nil {
		t.Fatalf("handleCronList: %v", err)
	}
	var jobs []cronJob
	if err := json.Unmarshal([]byte(listed), &jobs); err != nil {
		t.Fatalf("unmarshal listed jobs: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != job.ID {
		t.Fatalf("handleCronList = %+v, want one job with id %q", jobs, job.ID)
	}

	if _, err := handleCronSetEnabled(context.Background(), map[string]any{
		"system_user": user, "cron_id": job.ID, "enabled": false,
	}, nil); err != nil {
		t.Fatalf("handleCronSetEnabled(disable): %v", err)
	}
	data, _ = os.ReadFile(dFile)
	if strings.Contains(string(data), job.Command) {
		t.Fatalf("cron.d file still contains a disabled job's command:\n%s", data)
	}
	listed, _ = handleCronList(context.Background(), map[string]any{"system_user": user}, nil)
	jobs = nil
	json.Unmarshal([]byte(listed), &jobs)
	if len(jobs) != 1 || jobs[0].Enabled {
		t.Fatalf("disabled job should still be listed with Enabled=false, got %+v", jobs)
	}

	if _, err := handleCronDelete(context.Background(), map[string]any{
		"system_user": user, "cron_id": job.ID,
	}, nil); err != nil {
		t.Fatalf("handleCronDelete: %v", err)
	}
	listed, _ = handleCronList(context.Background(), map[string]any{"system_user": user}, nil)
	jobs = nil
	json.Unmarshal([]byte(listed), &jobs)
	if len(jobs) != 0 {
		t.Fatalf("expected no jobs after delete, got %+v", jobs)
	}

	if _, err := handleCronDelete(context.Background(), map[string]any{
		"system_user": user, "cron_id": "does-not-exist",
	}, nil); err == nil {
		t.Fatal("expected deleting an unknown cron_id to fail")
	}
}

func TestHandleCronCreateRejectsUnknownUser(t *testing.T) {
	newTestCronDirs(t)
	_, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": "definitely_not_a_real_user_xyz", "schedule": "@daily", "command": "echo hi",
	}, nil)
	if err == nil {
		t.Fatal("expected an error for a system_user that does not exist on this host")
	}
}

func TestHandleCronCreateRejectsInvalidSchedule(t *testing.T) {
	newTestCronDirs(t)
	user := "cpbad_" + randHex(4)
	ensureTestSystemUser(t, user)
	_, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": user, "schedule": "not a schedule", "command": "echo hi",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid schedule to be rejected")
	}
}
