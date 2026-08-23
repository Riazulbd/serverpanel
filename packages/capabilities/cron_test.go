package capabilities

import (
	"context"
	"strings"
	"testing"
)

func TestValidateCronSystemUserRejectsNonSiteUsers(t *testing.T) {
	valid := []string{"site_example_com", "site_a"}
	for _, u := range valid {
		if err := validateCronSystemUser(u); err != nil {
			t.Errorf("validateCronSystemUser(%q) = %v, want nil", u, err)
		}
	}
	invalid := []string{"", "root", "www-data", "site", "admin"}
	for _, u := range invalid {
		if err := validateCronSystemUser(u); err == nil {
			t.Errorf("validateCronSystemUser(%q) accepted a non-site-user (would let cron run as root/shared user)", u)
		}
	}
}

func TestValidateCronScheduleAcceptsValid(t *testing.T) {
	valid := []string{
		"* * * * *",
		"0 0 * * *",
		"*/5 * * * *",
		"0,30 9-17 * * 1-5",
		"15 2 1 * *",
	}
	for _, s := range valid {
		if err := validateCronSchedule(s); err != nil {
			t.Errorf("validateCronSchedule(%q) = %v, want nil", s, err)
		}
	}
}

func TestValidateCronScheduleRejectsMalformed(t *testing.T) {
	invalid := []string{
		"", "* * * *", "* * * * * *",
		"* * * * mon-fri",     // named weekday not supported
		"* * * * *; rm -rf /", // trailing shell injection attempt as a 6th token
		"a b c d e",           // non-numeric, non-* fields
	}
	for _, s := range invalid {
		if err := validateCronSchedule(s); err == nil {
			t.Errorf("validateCronSchedule(%q) accepted, want rejection", s)
		}
	}
}

func TestValidateCronCommandRejectsNewlinesAndOversize(t *testing.T) {
	if err := validateCronCommand(""); err == nil {
		t.Error("empty command accepted")
	}
	if err := validateCronCommand("php artisan schedule:run\n0 0 * * * rm -rf /"); err == nil {
		t.Error("command with an embedded newline accepted — this could forge an extra crontab line")
	}
	if err := validateCronCommand(strings.Repeat("a", 4001)); err == nil {
		t.Error("oversized command accepted")
	}
	if err := validateCronCommand("php /home/sites/site_example/public/artisan schedule:run >> /dev/null 2>&1"); err != nil {
		t.Errorf("valid command rejected: %v", err)
	}
}

func TestValidateCronLabelRejectsNewlinesAndOversize(t *testing.T) {
	if err := validateCronLabel("Laravel scheduler\nextra"); err == nil {
		t.Error("label with embedded newline accepted")
	}
	if err := validateCronLabel(strings.Repeat("a", 201)); err == nil {
		t.Error("oversized label accepted")
	}
	if err := validateCronLabel("Laravel scheduler"); err != nil {
		t.Errorf("valid label rejected: %v", err)
	}
}

func TestRenderParseCrontabRoundTrip(t *testing.T) {
	entries := []cronEntry{
		{ID: "abc123", Schedule: "*/5 * * * *", Command: "php artisan schedule:run", Label: "Laravel scheduler"},
		{ID: "def456", Schedule: "0 3 * * *", Command: "wp cron event run --due-now --path=/home/sites/site_ex/public", Label: ""},
	}
	rendered := renderCrontab(entries)
	got := parseCrontab(rendered)

	if len(got) != len(entries) {
		t.Fatalf("round trip produced %d entries, want %d:\n%s", len(got), len(entries), rendered)
	}
	for i, want := range entries {
		if got[i] != want {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want)
		}
	}
}

func TestParseCrontabIgnoresUnmarkedContent(t *testing.T) {
	text := "MAILTO=\"\"\n# a manually added comment\n17 4 * * * /usr/local/bin/something\n" +
		cronMarkerPrefix + "xyz789 label=" + encodeCronLabel("cleanup") + "\n0 4 * * * find /tmp -mtime +7 -delete\n"
	got := parseCrontab(text)
	if len(got) != 1 {
		t.Fatalf("parseCrontab returned %d entries, want 1 (only the marked one): %+v", len(got), got)
	}
	if got[0].ID != "xyz789" || got[0].Label != "cleanup" {
		t.Errorf("parseCrontab = %+v, want ID=xyz789 Label=cleanup", got[0])
	}
}

func TestParseCrontabSkipsMarkerWithoutFollowingScheduleLine(t *testing.T) {
	text := cronMarkerPrefix + "orphan label=\n"
	got := parseCrontab(text)
	if len(got) != 0 {
		t.Fatalf("parseCrontab = %+v, want 0 entries for a marker with no schedule line", got)
	}
}

func TestNewCronIDIsUniqueAndURLSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newCronID()
		if seen[id] {
			t.Fatalf("newCronID produced a duplicate: %q", id)
		}
		seen[id] = true
		if strings.ContainsAny(id, " \n\t/") {
			t.Fatalf("newCronID produced an unsafe id: %q", id)
		}
	}
}

func TestHandleCronCreateRejectsInvalidSystemUserBeforeAnySystemCall(t *testing.T) {
	_, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": "root", "schedule": "* * * * *", "command": "id",
	}, nil)
	if err == nil {
		t.Fatal("expected cron.create targeting the root user to be rejected before shelling out to crontab")
	}
}

func TestHandleCronCreateRejectsInvalidSchedule(t *testing.T) {
	_, err := handleCronCreate(context.Background(), map[string]any{
		"system_user": "site_example", "schedule": "not a schedule", "command": "id",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid schedule to be rejected")
	}
}

func TestHandleCronDeleteRejectsMissingID(t *testing.T) {
	_, err := handleCronDelete(context.Background(), map[string]any{
		"system_user": "site_example",
	}, nil)
	if err == nil {
		t.Fatal("expected a missing id to be rejected")
	}
}
