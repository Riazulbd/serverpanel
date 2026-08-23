package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// cronMarkerPrefix tags every crontab line ServerPanel manages with the
// control plane's own cron_jobs.id, one marker-comment line followed by the
// (possibly commented-out, for a disabled job) schedule line. This is what
// lets cron.upsert/cron.delete find and replace exactly one job's two lines
// out of a user's crontab without disturbing anything else already in it —
// crontab has no concept of named entries on its own.
const cronMarkerPrefix = "# serverpanel:cron:"

// cronJobIDRe matches the ids the control plane generates via randID("cron")
// (see apps/controlplane/store.go) — never caller-composed text, since it
// ends up embedded in a crontab as an unescaped comment.
var cronJobIDRe = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// cronFieldRe is a permissive but bounded allow-list for one of the 5
// standard cron fields: digits, "*", ranges ("1-5"), steps ("*/15"), and
// comma-separated lists of the above. It rejects anything containing shell
// metacharacters, which matters here because the field ends up written
// verbatim into a crontab line that cron itself will later pass to
// /bin/sh -c — the same reasoning as validateCronCommand below.
var cronFieldRe = regexp.MustCompile(`^(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?(,(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?)*$`)

type cronJobResult struct {
	JobID    string `json:"job_id"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Enabled  bool   `json:"enabled"`
}

func validateCronSchedule(schedule string) error {
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return fmt.Errorf("schedule must have exactly 5 space-separated fields (minute hour day month weekday), got %d", len(fields))
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return fmt.Errorf("invalid cron field %q", f)
		}
	}
	return nil
}

// validateCronCommand deliberately does NOT reject shell metacharacters:
// the command is expected to be an ordinary shell command line (that's what
// cron always runs, for any user, on any system) and it only ever executes
// as the isolated, nologin site system user validated by
// validCronSystemUser — never as root. The isolation boundary here is the
// Linux user account, the same one file.write/backup.restore already rely
// on, not command-string filtering. What IS rejected is anything that could
// let one "job" smuggle in additional crontab lines/entries.
func validateCronCommand(command string) error {
	if command == "" {
		return fmt.Errorf("command must not be empty")
	}
	if len(command) > 2000 {
		return fmt.Errorf("command must be 2000 characters or fewer")
	}
	if strings.ContainsAny(command, "\n\r") {
		return fmt.Errorf("command must not contain newlines")
	}
	return nil
}

// validCronSystemUser restricts cron management to system users ServerPanel
// itself created for a site (systemUserForDomain always prefixes with
// "site_"), so this capability can never be pointed at an arbitrary Linux
// account — including root — by a caller-supplied string.
func validCronSystemUser(ctx context.Context, sysUser string) error {
	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return fmt.Errorf("invalid system_user %q: cron jobs may only be managed for a ServerPanel-managed site user", sysUser)
	}
	if _, err := run(ctx, "id", "-u", sysUser); err != nil {
		return fmt.Errorf("system_user %q does not exist", sysUser)
	}
	return nil
}

// readCrontab returns sysUser's current crontab, or "" if they don't have
// one yet (crontab -l's own way of reporting that is a non-zero exit with
// "no crontab for <user>" on stderr, which run() folds into combined
// output — not a real error condition for our purposes).
func readCrontab(ctx context.Context, sysUser string) (string, error) {
	out, err := run(ctx, "crontab", "-u", sysUser, "-l")
	if err != nil {
		if strings.Contains(strings.ToLower(out), "no crontab for") {
			return "", nil
		}
		return "", fmt.Errorf("read crontab for %s: %w: %s", sysUser, err, out)
	}
	return out, nil
}

// writeCrontab installs content as sysUser's entire crontab, streaming it
// as the child process's stdin rather than as a command-line argument —
// the same reasoning as importSQLDump in backup.go.
func writeCrontab(ctx context.Context, sysUser, content string) error {
	cmd := exec.CommandContext(ctx, "crontab", "-u", sysUser, "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("write crontab for %s: %w: %s", sysUser, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeCronBlock strips the marker line for jobID and the single line that
// follows it (the schedule+command line, present whether or not it's
// currently commented out for a disabled job) out of content, leaving
// every other line — including entries this system never created —
// untouched.
func removeCronBlock(content, jobID string) string {
	marker := cronMarkerPrefix + jobID
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	skipNext := false
	for _, line := range lines {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.TrimSpace(line) == marker {
			skipNext = true
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// upsertCronBlock replaces (or appends, if absent) jobID's two-line block.
// A disabled job is written as a "#"-commented entry line rather than
// removed entirely, so schedule/command survive a later re-enable exactly
// as they were.
func upsertCronBlock(content, jobID, schedule, command string, enabled bool) string {
	content = strings.TrimRight(removeCronBlock(content, jobID), "\n")

	entry := schedule + " " + command
	if !enabled {
		entry = "#" + entry
	}
	block := cronMarkerPrefix + jobID + "\n" + entry

	if content == "" {
		return block + "\n"
	}
	return content + "\n" + block + "\n"
}

// handleCronUpsert creates or updates one cron job identified by job_id
// (always control-plane-generated, never end-user text) in system_user's
// crontab. It is idempotent — calling it twice with the same job_id
// replaces the prior entry rather than duplicating it — which is what lets
// the control plane use the same capability for both "create" and "edit
// schedule/command/enabled state".
func handleCronUpsert(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	jobID, _ := params["job_id"].(string)
	schedule, _ := params["schedule"].(string)
	command, _ := params["command"].(string)
	enabled, _ := params["enabled"].(bool)

	if err := validCronSystemUser(ctx, sysUser); err != nil {
		return "", err
	}
	if !cronJobIDRe.MatchString(jobID) {
		return "", fmt.Errorf("invalid job_id %q", jobID)
	}
	if err := validateCronSchedule(schedule); err != nil {
		return "", err
	}
	if err := validateCronCommand(command); err != nil {
		return "", err
	}

	progress("reading current crontab for " + sysUser)
	current, err := readCrontab(ctx, sysUser)
	if err != nil {
		return "", err
	}

	progress("writing updated crontab")
	if err := writeCrontab(ctx, sysUser, upsertCronBlock(current, jobID, schedule, command, enabled)); err != nil {
		return "", err
	}

	out, _ := json.Marshal(cronJobResult{JobID: jobID, Schedule: schedule, Command: command, Enabled: enabled})
	return string(out), nil
}

// handleCronDelete removes one cron job's block from system_user's
// crontab. If that was the user's only managed entry, the crontab is
// removed outright via `crontab -r` rather than left installed-but-empty.
func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	jobID, _ := params["job_id"].(string)

	if err := validCronSystemUser(ctx, sysUser); err != nil {
		return "", err
	}
	if !cronJobIDRe.MatchString(jobID) {
		return "", fmt.Errorf("invalid job_id %q", jobID)
	}

	progress("reading current crontab for " + sysUser)
	current, err := readCrontab(ctx, sysUser)
	if err != nil {
		return "", err
	}
	updated := removeCronBlock(current, jobID)

	progress("writing updated crontab")
	if strings.TrimSpace(updated) == "" {
		if out, err := run(ctx, "crontab", "-u", sysUser, "-r"); err != nil && !strings.Contains(strings.ToLower(out), "no crontab for") {
			return "", fmt.Errorf("remove empty crontab for %s: %w: %s", sysUser, err, out)
		}
	} else if err := writeCrontab(ctx, sysUser, updated); err != nil {
		return "", err
	}

	return "cron job deleted: " + jobID, nil
}
