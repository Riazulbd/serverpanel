package capabilities

import (
	"strings"
	"testing"
)

func TestValidCronScheduleAcceptsStandardFiveField(t *testing.T) {
	for _, s := range []string{"* * * * *", "0 3 * * *", "*/15 * * * *", "0,30 8-18 * * 1-5"} {
		if err := validCronSchedule(s); err != nil {
			t.Errorf("validCronSchedule(%q) = %v, want nil", s, err)
		}
	}
}

func TestValidCronScheduleAcceptsNicknames(t *testing.T) {
	for _, s := range []string{"@daily", "@hourly", "@reboot"} {
		if err := validCronSchedule(s); err != nil {
			t.Errorf("validCronSchedule(%q) = %v, want nil", s, err)
		}
	}
}

func TestValidCronScheduleRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "* * * *", "* * * * * *", "sixty * * * *", "@notaword", "* * * * *; rm -rf /"} {
		if err := validCronSchedule(s); err == nil {
			t.Errorf("validCronSchedule(%q) = nil, want an error", s)
		}
	}
}

func TestValidCronCommandRejectsEmptyAndMultiline(t *testing.T) {
	if err := validCronCommand(""); err == nil {
		t.Error("expected empty command to be rejected")
	}
	if err := validCronCommand("echo one\necho two"); err == nil {
		t.Error("expected a multi-line command to be rejected (crontab injection risk)")
	}
	if err := validCronCommand(strings.Repeat("a", 2001)); err == nil {
		t.Error("expected an over-long command to be rejected")
	}
}

func TestValidCronCommandAcceptsOrdinaryCommand(t *testing.T) {
	if err := validCronCommand("/usr/bin/php /home/sites/site_example/artisan schedule:run"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidCronSystemUserRejectsNonSiteUser(t *testing.T) {
	if err := validCronSystemUser(nil, "root"); err == nil {
		t.Error("expected root to be rejected as a cron target user")
	}
	if err := validCronSystemUser(nil, "www-data"); err == nil {
		t.Error("expected a non-site-prefixed user to be rejected")
	}
}

func TestCronRoundTripUpsertListRemove(t *testing.T) {
	content := "" // brand new crontab
	job := cronJob{ID: "cron_abc123", Label: "Laravel scheduler", Schedule: "* * * * *", Command: "/usr/bin/php /home/sites/site_example/artisan schedule:run", Enabled: true}

	content = upsertCronJob(content, job)
	jobs := listCronJobs(content)
	if len(jobs) != 1 {
		t.Fatalf("after upsert, listCronJobs returned %d jobs, want 1 (content=%q)", len(jobs), content)
	}
	if jobs[0] != job {
		t.Fatalf("round-tripped job = %+v, want %+v", jobs[0], job)
	}

	// Update in place: same ID, different schedule/label — must replace, not duplicate.
	updated := job
	updated.Schedule = "*/5 * * * *"
	updated.Label = "Laravel scheduler (every 5 min)"
	content = upsertCronJob(content, updated)
	jobs = listCronJobs(content)
	if len(jobs) != 1 {
		t.Fatalf("after update upsert, listCronJobs returned %d jobs, want 1 (content=%q)", len(jobs), content)
	}
	if jobs[0] != updated {
		t.Fatalf("updated job = %+v, want %+v", jobs[0], updated)
	}

	content = removeCronJob(content, job.ID)
	jobs = listCronJobs(content)
	if len(jobs) != 0 {
		t.Fatalf("after removeCronJob, listCronJobs returned %d jobs, want 0", len(jobs))
	}
}

func TestCronPreservesUnmanagedCrontabLines(t *testing.T) {
	foreign := "# a human wrote this directly\n0 4 * * * /usr/local/bin/some-other-script.sh\n"
	job := cronJob{ID: "cron_new", Label: "", Schedule: "@daily", Command: "echo hi", Enabled: true}

	content := upsertCronJob(foreign, job)
	if !strings.Contains(content, "some-other-script.sh") {
		t.Fatalf("upsertCronJob dropped a foreign (non-serverpanel) crontab line: %q", content)
	}

	jobs := listCronJobs(content)
	if len(jobs) != 1 || jobs[0].ID != "cron_new" {
		t.Fatalf("listCronJobs = %+v, want exactly the one managed job", jobs)
	}

	content = removeCronJob(content, "cron_new")
	if !strings.Contains(content, "some-other-script.sh") {
		t.Fatalf("removeCronJob dropped a foreign (non-serverpanel) crontab line: %q", content)
	}
	if strings.Contains(content, cronMarkerPrefix) {
		t.Fatalf("removeCronJob left a managed marker behind: %q", content)
	}
}

func TestCronDisabledJobIsCommentedOutButStillParses(t *testing.T) {
	job := cronJob{ID: "cron_off", Label: "paused job", Schedule: "@hourly", Command: "echo hi", Enabled: false}
	content := upsertCronJob("", job)

	if !strings.Contains(content, "\n# @hourly echo hi") {
		t.Fatalf("expected a disabled job's entry line to be commented out, got: %q", content)
	}
	jobs := listCronJobs(content)
	if len(jobs) != 1 || jobs[0].Enabled {
		t.Fatalf("listCronJobs = %+v, want one disabled job", jobs)
	}
}

func TestCronLabelWithSpacesRoundTrips(t *testing.T) {
	job := cronJob{ID: "cron_lbl", Label: "Nightly DB cleanup & vacuum", Schedule: "@daily", Command: "echo hi", Enabled: true}
	content := upsertCronJob("", job)
	jobs := listCronJobs(content)
	if len(jobs) != 1 || jobs[0].Label != job.Label {
		t.Fatalf("label round-trip failed: got %+v, want label %q", jobs, job.Label)
	}
}
