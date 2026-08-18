package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// cronMarker tags every crontab line this control plane manages, appended
// as a trailing shell comment (safe either way a cron implementation reads
// it: as cron's own end-of-line comment, or — if not — as a POSIX shell
// comment once the whole line is handed to `sh -c`, since it's always
// preceded by whitespace). This is what lets cron.list/cron.delete find and
// address exactly the jobs created through the dashboard without touching
// any other line a human or another tool put in the same user's crontab.
const cronMarker = "# serverpanel:cron:"

// cronIDRe matches the IDs the control plane generates (see
// apps/controlplane/store.go randID), not anything a caller could shape to
// break out of the marker comment.
var cronIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// cronFieldRe is the allow-list for each of the 5 schedule fields. It's
// intentionally not a full cron-syntax validator (no weekday/month names,
// no step-range semantics checked) — just enough charset restriction that a
// schedule value can never inject a newline or an extra crontab field.
var cronFieldRe = regexp.MustCompile(`^[0-9*/,-]+$`)

type cronJob struct {
	ID       string `json:"id"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
}

type cronListResult struct {
	Jobs []cronJob `json:"jobs"`
}

func validCronSchedule(schedule string) ([]string, error) {
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return nil, fmt.Errorf("schedule must have exactly 5 fields (minute hour day-of-month month day-of-week), got %d", len(fields))
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return nil, fmt.Errorf("invalid schedule field %q: only digits, *, /, ,, - are allowed", f)
		}
	}
	return fields, nil
}

func validCronCommand(command string) error {
	if command == "" {
		return fmt.Errorf("command is required")
	}
	if len(command) > 2000 {
		return fmt.Errorf("command must be 2000 characters or fewer")
	}
	if strings.ContainsAny(command, "\n\r") {
		return fmt.Errorf("command must not contain newlines")
	}
	return nil
}

// cronLine renders one managed crontab entry. Schedule/command have already
// been validated (no newlines, fixed charset for schedule), so this is safe
// string formatting, not injection-prone concatenation.
func cronLine(job cronJob) string {
	return fmt.Sprintf("%s %s %s%s", job.Schedule, job.Command, cronMarker, job.ID)
}

// parseCrontab extracts only serverpanel-managed jobs (lines carrying
// cronMarker) from raw `crontab -l` output. Every other line — the user's
// own entries, blank lines, comments, environment variable assignments — is
// left untouched and simply ignored here, which is what makes
// cron.create/cron.delete safe to run against a crontab that also has
// unrelated content.
func parseCrontab(raw string) []cronJob {
	var out []cronJob
	for _, line := range strings.Split(raw, "\n") {
		idx := strings.Index(line, cronMarker)
		if idx < 0 {
			continue
		}
		id := strings.TrimSpace(line[idx+len(cronMarker):])
		body := strings.TrimSpace(line[:idx])
		fields := strings.SplitN(body, " ", 6)
		if len(fields) < 6 || id == "" {
			continue
		}
		out = append(out, cronJob{
			ID:       id,
			Schedule: strings.Join(fields[:5], " "),
			Command:  fields[5],
		})
	}
	return out
}

// readCrontab returns the current managed jobs plus every raw line that
// isn't one of ours, so callers can rewrite a crontab without disturbing
// anything the user (or another tool) put there. A user with no crontab
// yet is not an error — `crontab -l` exits non-zero with "no crontab for
// <user>" in that case, which this treats as an empty crontab.
func readCrontab(ctx context.Context, sysUser string) (jobs []cronJob, otherLines []string, err error) {
	out, runErr := run(ctx, "crontab", "-u", sysUser, "-l")
	if runErr != nil {
		if strings.Contains(strings.ToLower(out), "no crontab for") {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read crontab for %s: %w: %s", sysUser, runErr, out)
	}
	jobs = parseCrontab(out)
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" || strings.Contains(line, cronMarker) {
			continue
		}
		otherLines = append(otherLines, line)
	}
	return jobs, otherLines, nil
}

// writeCrontab replaces sysUser's entire crontab with otherLines followed by
// one line per job, via `crontab -u <user> -` (content on stdin) — never a
// shell, never string-built into a command.
func writeCrontab(ctx context.Context, sysUser string, otherLines []string, jobs []cronJob) error {
	var b strings.Builder
	for _, line := range otherLines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	for _, job := range jobs {
		b.WriteString(cronLine(job))
		b.WriteByte('\n')
	}
	out, err := runStdin(ctx, b.String(), "crontab", "-u", sysUser, "-")
	if err != nil {
		return fmt.Errorf("write crontab for %s: %w: %s", sysUser, err, out)
	}
	return nil
}

func handleCronList(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	if !siteSystemUserRe.MatchString(sysUser) {
		return "", fmt.Errorf("invalid system_user %q", sysUser)
	}

	jobs, _, err := readCrontab(ctx, sysUser)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(cronListResult{Jobs: jobs})
	return string(out), nil
}

func handleCronCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	id, _ := params["id"].(string)
	schedule, _ := params["schedule"].(string)
	command, _ := params["command"].(string)

	if !siteSystemUserRe.MatchString(sysUser) {
		return "", fmt.Errorf("invalid system_user %q", sysUser)
	}
	if !cronIDRe.MatchString(id) {
		return "", fmt.Errorf("invalid cron job id")
	}
	fields, err := validCronSchedule(schedule)
	if err != nil {
		return "", err
	}
	if err := validCronCommand(command); err != nil {
		return "", err
	}

	progress("reading current crontab for " + sysUser)
	jobs, otherLines, err := readCrontab(ctx, sysUser)
	if err != nil {
		return "", err
	}
	for _, j := range jobs {
		if j.ID == id {
			return "", fmt.Errorf("a cron job with id %q already exists", id)
		}
	}
	job := cronJob{ID: id, Schedule: strings.Join(fields, " "), Command: command}
	jobs = append(jobs, job)

	progress("writing crontab for " + sysUser)
	if err := writeCrontab(ctx, sysUser, otherLines, jobs); err != nil {
		return "", err
	}

	out, _ := json.Marshal(job)
	return string(out), nil
}

func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	id, _ := params["id"].(string)

	if !siteSystemUserRe.MatchString(sysUser) {
		return "", fmt.Errorf("invalid system_user %q", sysUser)
	}
	if !cronIDRe.MatchString(id) {
		return "", fmt.Errorf("invalid cron job id")
	}

	jobs, otherLines, err := readCrontab(ctx, sysUser)
	if err != nil {
		return "", err
	}
	kept := jobs[:0]
	found := false
	for _, j := range jobs {
		if j.ID == id {
			found = true
			continue
		}
		kept = append(kept, j)
	}
	if !found {
		return "", fmt.Errorf("no cron job with id %q", id)
	}

	progress("writing crontab for " + sysUser)
	if err := writeCrontab(ctx, sysUser, otherLines, kept); err != nil {
		return "", err
	}
	return "cron job removed", nil
}
