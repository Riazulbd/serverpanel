package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"os/user"
	"regexp"
	"strings"
)

// Cron jobs are only ever scheduled for a managed site's own unprivileged
// system user (home directory under /home/sites/, created by
// handleSiteCreate) — never root or any other account. That is what keeps
// this a bounded hosting feature ("run an application's scheduled task as
// its own restricted user") rather than a path to arbitrary privileged
// command execution: the worst a scheduled command can do is whatever that
// site's own PHP-FPM pool could already do, since the pool runs as this
// same user.
const managedSiteUserHomePrefix = "/home/sites/"

// cronIDRe bounds the opaque tag embedded in the crontab line (see
// cronTag) to characters that cannot alter crontab's own line syntax.
var cronIDRe = regexp.MustCompile(`^[a-zA-Z0-9_]{1,64}$`)

// cronFieldRe matches one field of a standard 5-field cron schedule.
// Deliberately narrow: no step lists beyond digits/`,-*/`, no day names —
// enough for every schedule the dashboard offers, nothing that could hide
// shell metacharacters.
var cronFieldRe = regexp.MustCompile(`^[0-9,\-*/]+$`)

var cronNamedSchedules = map[string]bool{
	"@yearly": true, "@annually": true, "@monthly": true, "@weekly": true,
	"@daily": true, "@midnight": true, "@hourly": true, "@reboot": true,
}

// cronDisabledPrefix marks a suspended cron entry. Prefixing the whole
// line with "#" is enough for crontab to treat it as a pure comment (a
// no-op), while the tag substring further down the line still matches
// findCronLine — so a disabled job's entry is trivially recoverable
// (cron.set_enabled with enabled=true) rather than lost.
const cronDisabledPrefix = "#DISABLED#"

func cronTag(id string) string { return "# spcron:" + id }

type cronResult struct {
	ID       string `json:"id"`
	Schedule string `json:"schedule,omitempty"`
	Command  string `json:"command,omitempty"`
	Enabled  bool   `json:"enabled"`
}

func validateCronID(id string) error {
	if !cronIDRe.MatchString(id) {
		return fmt.Errorf("invalid cron job id")
	}
	return nil
}

func validateCronSchedule(schedule string) error {
	if cronNamedSchedules[schedule] {
		return nil
	}
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return fmt.Errorf("schedule must be a 5-field cron expression (minute hour day month weekday) or a named schedule (@daily, @hourly, @weekly, @monthly, @yearly, @reboot)")
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return fmt.Errorf("invalid cron schedule field %q", f)
		}
	}
	return nil
}

// validateCronCommand rejects characters that would let a command alter
// its own crontab line rather than merely being the thing that line runs:
// an unescaped '#' truncates the rest of the line as a comment (silently
// dropping our log-redirect and tag), and '\n'/'\r' would inject an
// entirely separate crontab line.
func validateCronCommand(command string) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return fmt.Errorf("command is required")
	}
	if len(command) > 2000 {
		return fmt.Errorf("command too long (2000 characters max)")
	}
	if strings.ContainsAny(command, "#\n\r") {
		return fmt.Errorf("command may not contain '#' or newline characters — these break crontab line parsing")
	}
	return nil
}

// validateCronUser confirms userName is a real, existing Linux account
// AND that it is one of our own managed site users, never an arbitrary
// system account (root, www-data, a human admin's login, ...). Returns
// its home directory, which is where the job's stdout/stderr log lives.
func validateCronUser(userName string) (home string, err error) {
	u, err := user.Lookup(userName)
	if err != nil {
		return "", fmt.Errorf("unknown system user %q", userName)
	}
	if !strings.HasPrefix(u.HomeDir, managedSiteUserHomePrefix) {
		return "", fmt.Errorf("cron jobs may only be scheduled for a managed site's own system user, not %q", userName)
	}
	return u.HomeDir, nil
}

// readCrontab returns userName's current crontab as individual lines. A
// user with no crontab yet is not an error (crontab -l's "no crontab for"
// exit is the normal starting state for a freshly created site user).
func readCrontab(ctx context.Context, userName string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "crontab", "-u", userName, "-l")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "no crontab for") {
			return nil, nil
		}
		return nil, fmt.Errorf("read crontab for %s: %w: %s", userName, err, strings.TrimSpace(string(out)))
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		lines = append(lines, l)
	}
	return lines, nil
}

// writeCrontab replaces userName's entire crontab with lines. crontab(1)
// has no "append one line" mode, so every mutation in this file is a
// read-modify-write of the full table — findCronLine is what keeps that
// safe for entries this agent didn't create (they're left untouched,
// never parsed as ours).
func writeCrontab(ctx context.Context, userName string, lines []string) error {
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	cmd := exec.CommandContext(ctx, "crontab", "-u", userName, "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("write crontab for %s: %w: %s", userName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// findCronLine returns the index of the line tagged with id, or -1. It
// matches on tag suffix after stripping a possible disabled-prefix, so it
// finds an entry regardless of its enabled/disabled state.
func findCronLine(lines []string, id string) int {
	tag := cronTag(id)
	for i, l := range lines {
		trimmed := strings.TrimSpace(strings.TrimPrefix(l, cronDisabledPrefix))
		if strings.HasSuffix(trimmed, tag) {
			return i
		}
	}
	return -1
}

func handleCronCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	id, _ := params["id"].(string)
	userName, _ := params["user"].(string)
	schedule, _ := params["schedule"].(string)
	command, _ := params["command"].(string)

	if err := validateCronID(id); err != nil {
		return "", err
	}
	if err := validateCronSchedule(schedule); err != nil {
		return "", err
	}
	if err := validateCronCommand(command); err != nil {
		return "", err
	}
	home, err := validateCronUser(userName)
	if err != nil {
		return "", err
	}

	lines, err := readCrontab(ctx, userName)
	if err != nil {
		return "", err
	}

	// Idempotent: a retried create for an id that already landed succeeds
	// without adding a duplicate entry, rather than erroring or doubling
	// up the schedule.
	if idx := findCronLine(lines, id); idx >= 0 {
		enabled := !strings.HasPrefix(lines[idx], cronDisabledPrefix)
		out, _ := json.Marshal(cronResult{ID: id, Schedule: schedule, Command: command, Enabled: enabled})
		return string(out), nil
	}

	progress("adding cron entry for " + userName)
	newLine := fmt.Sprintf("%s %s >> %s/cron.log 2>&1 %s", schedule, command, home, cronTag(id))
	lines = append(lines, newLine)
	if err := writeCrontab(ctx, userName, lines); err != nil {
		return "", err
	}

	out, _ := json.Marshal(cronResult{ID: id, Schedule: schedule, Command: command, Enabled: true})
	return string(out), nil
}

func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	id, _ := params["id"].(string)
	userName, _ := params["user"].(string)

	if err := validateCronID(id); err != nil {
		return "", err
	}
	if _, err := validateCronUser(userName); err != nil {
		return "", err
	}

	lines, err := readCrontab(ctx, userName)
	if err != nil {
		return "", err
	}

	idx := findCronLine(lines, id)
	if idx < 0 {
		// Already absent: deleting a job that's already gone is success,
		// not an error — a retried delete must be safe to repeat.
		out, _ := json.Marshal(cronResult{ID: id})
		return string(out), nil
	}

	progress("removing cron entry for " + userName)
	lines = append(lines[:idx], lines[idx+1:]...)
	if err := writeCrontab(ctx, userName, lines); err != nil {
		return "", err
	}

	out, _ := json.Marshal(cronResult{ID: id})
	return string(out), nil
}

func handleCronSetEnabled(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	id, _ := params["id"].(string)
	userName, _ := params["user"].(string)
	enabled, _ := params["enabled"].(bool)

	if err := validateCronID(id); err != nil {
		return "", err
	}
	if _, err := validateCronUser(userName); err != nil {
		return "", err
	}

	lines, err := readCrontab(ctx, userName)
	if err != nil {
		return "", err
	}

	idx := findCronLine(lines, id)
	if idx < 0 {
		return "", fmt.Errorf("cron job %q not found for user %q", id, userName)
	}

	line := lines[idx]
	currentlyEnabled := !strings.HasPrefix(line, cronDisabledPrefix)
	if enabled && !currentlyEnabled {
		lines[idx] = strings.TrimPrefix(line, cronDisabledPrefix)
	} else if !enabled && currentlyEnabled {
		lines[idx] = cronDisabledPrefix + line
	}

	if err := writeCrontab(ctx, userName, lines); err != nil {
		return "", err
	}

	out, _ := json.Marshal(cronResult{ID: id, Enabled: enabled})
	return string(out), nil
}
