package capabilities

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Cron jobs are stored in the target system user's own crontab (never
// root's), each line tagged with a trailing "# serverpanel-cron:<id>"
// marker comment so cron.delete/cron.set_enabled can find and mutate
// exactly one managed entry without disturbing anything else already in
// that user's crontab — a user could in principle also edit their own
// crontab by hand (e.g. via a future SSH feature) and every managed line
// stays individually identifiable and untouched unless its own id is
// targeted.
const (
	cronMarkerPrefix   = "# serverpanel-cron:"
	cronDisabledPrefix = "#DISABLED# "
)

// cronFieldRe allow-lists standard-form cron schedule fields: digits,
// "*", "/", "," and "-". Named values (JAN, MON, @daily, ...) are
// intentionally not accepted in this release — see docs/API.md.
var cronFieldRe = regexp.MustCompile(`^[0-9*/,-]+$`)

var cronIDRe = regexp.MustCompile(`^[a-zA-Z0-9_]{1,64}$`)

func validateCronUser(user string) error {
	if user == "" || !strings.HasPrefix(user, "site_") {
		return fmt.Errorf("invalid system_user: cron jobs may only run as an application's own site_ system user, never root")
	}
	return nil
}

func validateCronID(id string) error {
	if !cronIDRe.MatchString(id) {
		return fmt.Errorf("invalid cron job id")
	}
	return nil
}

func validateCronSchedule(schedule string) error {
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return fmt.Errorf("schedule must have exactly 5 space-separated fields (minute hour day month weekday), got %d", len(fields))
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return fmt.Errorf("invalid cron schedule field %q", f)
		}
	}
	return nil
}

func validateCronCommand(command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("command is required")
	}
	if len(command) > 2000 {
		return "", fmt.Errorf("command too long (2000 character max)")
	}
	// '#' is rejected rather than escaped: cron itself treats '#' as a
	// comment marker that truncates the rest of the line, which would
	// silently break our own trailing id marker (and could be abused to
	// forge/hide it). Newlines are rejected because a crontab file is
	// one job per line — an embedded newline would inject an unmanaged
	// second job.
	if strings.ContainsAny(command, "\n\r#") {
		return "", fmt.Errorf("command must not contain newlines or '#' (wrap complex commands in a script file instead)")
	}
	return command, nil
}

// cronLineID extracts the id from a managed crontab line's trailing
// marker comment, or reports ok=false for a line this package didn't
// write (e.g. something the user's crontab already had).
func cronLineID(line string) (id string, ok bool) {
	idx := strings.Index(line, cronMarkerPrefix)
	if idx < 0 {
		return "", false
	}
	id = strings.TrimSpace(line[idx+len(cronMarkerPrefix):])
	return id, id != ""
}

func readCrontabLines(ctx context.Context, user string) ([]string, error) {
	out, err := run(ctx, "crontab", "-u", user, "-l")
	if err != nil {
		if strings.Contains(out, "no crontab for") {
			return nil, nil
		}
		return nil, fmt.Errorf("reading crontab for %s: %w: %s", user, err, out)
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

func writeCrontabLines(ctx context.Context, user string, lines []string) error {
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	out, err := runWithStdin(ctx, content, "crontab", "-u", user, "-")
	if err != nil {
		return fmt.Errorf("writing crontab for %s: %w: %s", user, err, out)
	}
	return nil
}

// handleCronCreate appends one managed line to the target user's
// crontab. The caller (control plane) supplies the job id up front so the
// crontab marker and the control plane's own persisted record always
// share the same id.
func handleCronCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	schedule, _ := params["schedule"].(string)
	rawCommand, _ := params["command"].(string)
	id, _ := params["id"].(string)

	if err := validateCronUser(sysUser); err != nil {
		return "", err
	}
	if err := validateCronID(id); err != nil {
		return "", err
	}
	if err := validateCronSchedule(schedule); err != nil {
		return "", err
	}
	command, err := validateCronCommand(rawCommand)
	if err != nil {
		return "", err
	}

	lines, err := readCrontabLines(ctx, sysUser)
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		if existing, ok := cronLineID(l); ok && existing == id {
			return "", fmt.Errorf("cron job %q already exists", id)
		}
	}

	lines = append(lines, fmt.Sprintf("%s %s %s%s", schedule, command, cronMarkerPrefix, id))

	progress("updating crontab for " + sysUser)
	if err := writeCrontabLines(ctx, sysUser, lines); err != nil {
		return "", err
	}
	return "cron job created", nil
}

// handleCronDelete removes exactly the one line carrying the given id,
// leaving every other line in the user's crontab (managed or not)
// untouched.
func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	id, _ := params["id"].(string)

	if err := validateCronUser(sysUser); err != nil {
		return "", err
	}
	if err := validateCronID(id); err != nil {
		return "", err
	}

	lines, err := readCrontabLines(ctx, sysUser)
	if err != nil {
		return "", err
	}

	kept := make([]string, 0, len(lines))
	found := false
	for _, l := range lines {
		if existing, ok := cronLineID(l); ok && existing == id {
			found = true
			continue
		}
		kept = append(kept, l)
	}
	if !found {
		return "", fmt.Errorf("cron job %q not found", id)
	}

	progress("updating crontab for " + sysUser)
	if err := writeCrontabLines(ctx, sysUser, kept); err != nil {
		return "", err
	}
	return "cron job deleted", nil
}

// handleCronSetEnabled toggles a job's crontab line between active and a
// "#DISABLED# "-prefixed comment (still fully cron-syntax-valid, and
// still individually identifiable by its trailing id marker) so
// disable/re-enable never loses the job's schedule or command.
func handleCronSetEnabled(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	id, _ := params["id"].(string)
	enabled, _ := params["enabled"].(bool)

	if err := validateCronUser(sysUser); err != nil {
		return "", err
	}
	if err := validateCronID(id); err != nil {
		return "", err
	}

	lines, err := readCrontabLines(ctx, sysUser)
	if err != nil {
		return "", err
	}

	found := false
	for i, l := range lines {
		existing, ok := cronLineID(l)
		if !ok || existing != id {
			continue
		}
		found = true
		trimmed := strings.TrimPrefix(l, cronDisabledPrefix)
		if enabled {
			lines[i] = trimmed
		} else {
			lines[i] = cronDisabledPrefix + trimmed
		}
	}
	if !found {
		return "", fmt.Errorf("cron job %q not found", id)
	}

	progress("updating crontab for " + sysUser)
	if err := writeCrontabLines(ctx, sysUser, lines); err != nil {
		return "", err
	}
	state := "disabled"
	if enabled {
		state = "enabled"
	}
	return "cron job " + state, nil
}
