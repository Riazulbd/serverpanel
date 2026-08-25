package capabilities

import (
	"strings"
	"testing"
)

func TestValidateCronUser(t *testing.T) {
	valid := []string{"site_example_com", "site_a"}
	for _, u := range valid {
		if err := validateCronUser(u); err != nil {
			t.Errorf("validateCronUser(%q) = %v, want nil", u, err)
		}
	}
	invalid := []string{"root", "www-data", "", "site_UPPER", "SITE_x", "site_" + string(make([]byte, 40))}
	for _, u := range invalid {
		if err := validateCronUser(u); err == nil {
			t.Errorf("validateCronUser(%q) = nil, want error", u)
		}
	}
}

func TestValidateSchedule(t *testing.T) {
	valid := []string{"* * * * *", "0 2 * * *", "*/5 * * * *", "0,30 9-17 * * 1-5", "@daily", "@hourly", "@reboot"}
	for _, s := range valid {
		if err := validateSchedule(s); err != nil {
			t.Errorf("validateSchedule(%q) = %v, want nil", s, err)
		}
	}
	invalid := []string{"", "* * * *", "* * * * * *", "* * * * $(rm -rf /)", "0 2 * * *; rm -rf /"}
	for _, s := range invalid {
		if err := validateSchedule(s); err == nil {
			t.Errorf("validateSchedule(%q) = nil, want error", s)
		}
	}
}

func TestValidateCommand(t *testing.T) {
	if err := validateCommand("/usr/bin/php /home/sites/site_x/public/artisan schedule:run"); err != nil {
		t.Errorf("valid command rejected: %v", err)
	}
	if err := validateCommand(""); err == nil {
		t.Error("empty command should be rejected")
	}
	if err := validateCommand("echo hi\nrm -rf /"); err == nil {
		t.Error("command with newline should be rejected (crontab line injection)")
	}
}

func TestParseAndRenderRoundTrip(t *testing.T) {
	e := CronEntry{ID: "abc123", User: "site_x", Label: "Nightly backup", Schedule: "0 2 * * *", Command: "/usr/bin/php artisan backup:run", Enabled: true}
	content := renderMarkerLine(e) + "\n" + renderJobLine(e) + "\n"

	got := parseCrontab(content, "site_x")
	if len(got) != 1 {
		t.Fatalf("parseCrontab: got %d entries, want 1 (content=%q)", len(got), content)
	}
	if got[0] != e {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got[0], e)
	}
}

func TestParseDisabledEntry(t *testing.T) {
	e := CronEntry{ID: "abc123", User: "site_x", Label: "", Schedule: "0 2 * * *", Command: "/usr/bin/php artisan backup:run", Enabled: false}
	content := renderMarkerLine(e) + "\n" + renderJobLine(e) + "\n"

	got := parseCrontab(content, "site_x")
	if len(got) != 1 || got[0].Enabled {
		t.Fatalf("expected one disabled entry, got %+v", got)
	}
	if got[0] != e {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got[0], e)
	}
}

func TestParseCrontabPreservesForeignContent(t *testing.T) {
	content := "MAILTO=someone@example.com\n# a user comment\n0 3 * * * /usr/bin/some-other-job\n"
	got := parseCrontab(content, "site_x")
	if len(got) != 0 {
		t.Fatalf("expected no managed entries in foreign-only crontab, got %+v", got)
	}
}

func TestRewriteCrontabPreservesUnrelatedLines(t *testing.T) {
	foreign := "MAILTO=someone@example.com\n0 3 * * * /usr/bin/some-other-job\n"
	e := CronEntry{ID: "id1", User: "site_x", Schedule: "* * * * *", Command: "true", Enabled: true}

	updated := rewriteCrontab(foreign, e.ID, &e)
	if got := parseCrontab(updated, "site_x"); len(got) != 1 || got[0] != e {
		t.Fatalf("expected the new entry to be present, got %+v (content=%q)", got, updated)
	}
	for _, line := range []string{"MAILTO=someone@example.com", "0 3 * * * /usr/bin/some-other-job"} {
		if !strings.Contains(updated, line) {
			t.Errorf("expected unrelated line %q to survive rewriteCrontab, content=%q", line, updated)
		}
	}
}

func TestRewriteCrontabUpdateThenDelete(t *testing.T) {
	e := CronEntry{ID: "id1", User: "site_x", Label: "a", Schedule: "* * * * *", Command: "true", Enabled: true}
	content := rewriteCrontab("", e.ID, &e)

	e.Enabled = false
	content = rewriteCrontab(content, e.ID, &e)
	got := parseCrontab(content, "site_x")
	if len(got) != 1 || got[0].Enabled {
		t.Fatalf("expected exactly one disabled entry after update, got %+v", got)
	}

	content = rewriteCrontab(content, e.ID, nil)
	got = parseCrontab(content, "site_x")
	if len(got) != 0 {
		t.Fatalf("expected no entries after delete, got %+v", got)
	}
}

func TestMultipleEntriesIndependentlyManaged(t *testing.T) {
	e1 := CronEntry{ID: "id1", User: "site_x", Schedule: "* * * * *", Command: "true", Enabled: true}
	e2 := CronEntry{ID: "id2", User: "site_x", Schedule: "0 0 * * *", Command: "false", Enabled: true}

	content := rewriteCrontab("", e1.ID, &e1)
	content = rewriteCrontab(content, e2.ID, &e2)

	got := parseCrontab(content, "site_x")
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}

	content = rewriteCrontab(content, e1.ID, nil)
	got = parseCrontab(content, "site_x")
	if len(got) != 1 || got[0].ID != "id2" {
		t.Fatalf("expected only id2 to remain, got %+v", got)
	}
}
