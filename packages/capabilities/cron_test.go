package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newTestCronLogBaseDir points cronLogBaseDir at a temp directory for the
// duration of one test, matching newTestBackupBaseDir's pattern.
func newTestCronLogBaseDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := cronLogBaseDir
	cronLogBaseDir = dir
	t.Cleanup(func() { cronLogBaseDir = orig })
	return dir
}

func requireCrontab(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("crontab"); err != nil {
		t.Skipf("crontab not available in this environment: %v", err)
	}
}

func TestValidateCronScheduleAcceptsStandardForms(t *testing.T) {
	for _, sched := range []string{"* * * * *", "0 3 * * *", "*/15 * * * *", "0,30 9-17 * * 1-5"} {
		if _, err := validateCronSchedule(sched); err != nil {
			t.Errorf("validateCronSchedule(%q) = %v, want nil", sched, err)
		}
	}
}

func TestValidateCronScheduleRejectsBadForms(t *testing.T) {
	for _, sched := range []string{"", "* * * *", "@daily", "* * * * * *", "* * * * $(rm -rf /)"} {
		if _, err := validateCronSchedule(sched); err == nil {
			t.Errorf("validateCronSchedule(%q) = nil, want an error", sched)
		}
	}
}

// TestValidateCronScheduleRejectsEmbeddedNewline is the regression test for
// the injection this normalization closes: a schedule string containing a
// literal newline can still tokenize into exactly 5 individually-valid
// fields (strings.Fields splits on any whitespace, including "\n"), so the
// defense has to be "always write back the re-joined, single-space-
// separated fields," not "reject anything containing '\n'" — this test
// pins that the returned string is safe to place directly into a crontab
// line even for an input crafted to exploit that gap.
func TestValidateCronScheduleRejectsEmbeddedNewline(t *testing.T) {
	got, err := validateCronSchedule("0\n3 * * *")
	if err != nil {
		t.Fatalf("validateCronSchedule with an embedded newline = %v, want it to still validate (5 valid fields)", err)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("validateCronSchedule returned %q, want the embedded newline normalized away", got)
	}
	if got != "0 3 * * *" {
		t.Fatalf("validateCronSchedule returned %q, want \"0 3 * * *\"", got)
	}
}

func TestResolveCronBinaryRejectsUnknownName(t *testing.T) {
	if _, err := resolveCronBinary("bash"); err == nil {
		t.Fatal("expected a non-allow-listed binary name to be rejected")
	}
}

func TestHandleCronSyncRejectsNonSiteUser(t *testing.T) {
	newTestCronLogBaseDir(t)
	_, err := handleCronSync(context.Background(), map[string]any{
		"run_as_user": "root", "jobs": []any{},
	}, nil)
	if err == nil {
		t.Fatal("expected run_as_user=root to be rejected")
	}
	if !strings.Contains(err.Error(), "managed site system user") {
		t.Fatalf("error = %q, want it to mention the site-user requirement", err.Error())
	}
}

func TestHandleCronSyncRejectsUnknownUser(t *testing.T) {
	newTestCronLogBaseDir(t)
	_, err := handleCronSync(context.Background(), map[string]any{
		"run_as_user": "site_does_not_exist_xyz", "jobs": []any{},
	}, nil)
	if err == nil {
		t.Fatal("expected an unknown system user to be rejected")
	}
}

func TestHandleCronSyncRejectsBadSchedule(t *testing.T) {
	requireCrontab(t)
	newTestCronLogBaseDir(t)
	user := "site_crontest1"
	ensureTestSystemUser(t, user)

	_, err := handleCronSync(context.Background(), map[string]any{
		"run_as_user": user,
		"jobs": []any{
			map[string]any{"id": "cron_1", "schedule": "@daily", "binary": "curl", "args": []any{}},
		},
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid schedule to be rejected")
	}
}

func TestHandleCronSyncRejectsInjectionInArgs(t *testing.T) {
	requireCrontab(t)
	newTestCronLogBaseDir(t)
	user := "site_crontest2"
	ensureTestSystemUser(t, user)

	_, err := handleCronSync(context.Background(), map[string]any{
		"run_as_user": user,
		"jobs": []any{
			map[string]any{"id": "cron_1", "schedule": "* * * * *", "binary": "curl", "args": []any{"http://x; rm -rf /"}},
		},
	}, nil)
	if err == nil {
		t.Fatal("expected an argument containing shell metacharacters to be rejected")
	}
}

// TestHandleCronSyncNormalizesEmbeddedNewlineInSchedule proves, end to end
// against a real crontab, that a schedule crafted with an embedded newline
// (see TestValidateCronScheduleRejectsEmbeddedNewline) cannot inject a
// second crontab entry: the real crontab ends up with exactly one line for
// the job, not two.
func TestHandleCronSyncNormalizesEmbeddedNewlineInSchedule(t *testing.T) {
	requireCrontab(t)
	newTestCronLogBaseDir(t)
	user := "site_crontest4"
	ensureTestSystemUser(t, user)

	_, err := handleCronSync(context.Background(), map[string]any{
		"run_as_user": user,
		"jobs": []any{
			map[string]any{"id": "cron_nl", "schedule": "0\n3 * * *", "binary": "curl", "args": []any{"https://example.com"}},
		},
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleCronSync: %v", err)
	}

	out, err := exec.Command("crontab", "-u", user, "-l").CombinedOutput()
	if err != nil {
		t.Fatalf("crontab -l: %v: %s", err, out)
	}
	lines := 0
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.Contains(l, "serverpanel:") {
			lines++
		}
	}
	if lines != 1 {
		t.Fatalf("expected exactly 1 job line in the crontab, got %d:\n%s", lines, out)
	}
}

func TestHandleCronSyncRejectsTooManyJobs(t *testing.T) {
	newTestCronLogBaseDir(t)
	jobs := make([]any, maxCronJobsPerSync+1)
	for i := range jobs {
		jobs[i] = map[string]any{"id": "cron_x", "schedule": "* * * * *", "binary": "curl", "args": []any{}}
	}
	_, err := handleCronSync(context.Background(), map[string]any{
		"run_as_user": "site_whatever", "jobs": jobs,
	}, nil)
	if err == nil {
		t.Fatal("expected too many jobs to be rejected")
	}
}

func TestHandleCronSyncWritesAndClearsCrontab(t *testing.T) {
	requireCrontab(t)
	newTestCronLogBaseDir(t)
	user := "site_crontest3"
	ensureTestSystemUser(t, user)

	out, err := handleCronSync(context.Background(), map[string]any{
		"run_as_user": user,
		"jobs": []any{
			map[string]any{"id": "cron_a", "schedule": "0 3 * * *", "binary": "curl", "args": []any{"https://example.com/cron"}},
		},
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleCronSync: %v", err)
	}
	var res cronSyncResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if res.JobCount != 1 || res.RunAsUser != user {
		t.Fatalf("unexpected result: %+v", res)
	}

	crontabOut, err := exec.Command("crontab", "-u", user, "-l").CombinedOutput()
	if err != nil {
		t.Fatalf("crontab -l: %v: %s", err, crontabOut)
	}
	if !strings.Contains(string(crontabOut), "0 3 * * *") || !strings.Contains(string(crontabOut), "serverpanel:cron_a") {
		t.Fatalf("crontab contents = %q, missing expected job line", crontabOut)
	}

	logDir := filepath.Join(cronLogBaseDir, user)
	if st, err := os.Stat(logDir); err != nil || !st.IsDir() {
		t.Fatalf("expected cron log directory %s to exist", logDir)
	}

	// Syncing an empty job list clears the crontab — this is the same call
	// the control plane makes to apply a deletion or a disable.
	if _, err := handleCronSync(context.Background(), map[string]any{
		"run_as_user": user, "jobs": []any{},
	}, func(string) {}); err != nil {
		t.Fatalf("handleCronSync (empty): %v", err)
	}
	crontabOut, err = exec.Command("crontab", "-u", user, "-l").CombinedOutput()
	if err == nil && strings.Contains(string(crontabOut), "serverpanel:cron_a") {
		t.Fatalf("expected the job to be removed from the crontab, got %q", crontabOut)
	}
}
