package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
)

// Cron job management. Every managed entry lives in the target system
// user's own crontab (never root's), which is what keeps a scheduled job
// bounded by the same isolation the rest of this package already gives that
// user (own uid, no shell, php-fpm pool, open_basedir) — see site.go. cron
// jobs therefore may only be created for an existing "site_"-prefixed
// system user, the same isolation boundary db.create/site.set_status
// already enforce; this capability does not add a way to schedule anything
// as root.
//
// A managed entry is a two-line block in the user's crontab:
//
//	# serverpanel-cron id=<id> label=<url-encoded label>
//	<schedule> <command>
//
// Disabling a job comments out the second line ("# <schedule> <command>")
// rather than removing it, so re-enabling doesn't lose the schedule/command.
// The crontab file itself is the only source of truth — there is no
// database table mirroring it on the control-plane side (see
// apps/controlplane/cron.go), so a job edited directly on the box is never
// out of sync with what the dashboard shows.
const cronMarkerPrefix = "# serverpanel-cron "

type cronJob struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Enabled  bool   `json:"enabled"`
}

var cronFieldRe = regexp.MustCompile(`^(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?(,(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?)*$`)

var cronNicknames = map[string]bool{
	"@yearly": true, "@annually": true, "@monthly": true, "@weekly": true,
	"@daily": true, "@midnight": true, "@hourly": true, "@reboot": true,
}

func validCronSchedule(schedule string) error {
	fields := strings.Fields(schedule)
	if len(fields) == 1 && cronNicknames[fields[0]] {
		return nil
	}
	if len(fields) != 5 {
		return fmt.Errorf("schedule must be 5 space-separated cron fields (minute hour day month weekday), or one of %s",
			strings.Join(sortedCronNicknames(), ", "))
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return fmt.Errorf("invalid cron field %q", f)
		}
	}
	return nil
}

func sortedCronNicknames() []string {
	return []string{"@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly", "@reboot"}
}

func validCronCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("command is required")
	}
	if strings.ContainsAny(command, "\n\r") {
		return fmt.Errorf("command must be a single line")
	}
	if len(command) > 2000 {
		return fmt.Errorf("command must be 2000 characters or fewer")
	}
	return nil
}

func validCronLabel(label string) error {
	if strings.ContainsAny(label, "\n\r") {
		return fmt.Errorf("label must be a single line")
	}
	if len(label) > 200 {
		return fmt.Errorf("label must be 200 characters or fewer")
	}
	return nil
}

// validCronSystemUser enforces that cron jobs can only ever be scheduled
// for an application's own isolated system user, and that the user
// actually exists on this host (never trusting a caller-supplied name that
// merely looks right).
func validCronSystemUser(ctx context.Context, user string) error {
	if !strings.HasPrefix(user, "site_") {
		return fmt.Errorf("cron jobs may only be scheduled for an application's own isolated system user (must start with \"site_\")")
	}
	if _, err := run(ctx, "id", "-u", user); err != nil {
		return fmt.Errorf("system user %q does not exist on this server", user)
	}
	return nil
}

func marshalCronEntry(job cronJob) []string {
	marker := fmt.Sprintf("%sid=%s label=%s", cronMarkerPrefix, job.ID, url.QueryEscape(job.Label))
	line := job.Schedule + " " + job.Command
	if !job.Enabled {
		line = "# " + line
	}
	return []string{marker, line}
}

func parseCronMarker(line string) (id, label string, ok bool) {
	if !strings.HasPrefix(line, cronMarkerPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(line, cronMarkerPrefix)
	for _, f := range strings.Fields(rest) {
		if v, found := strings.CutPrefix(f, "id="); found {
			id = v
		}
		if v, found := strings.CutPrefix(f, "label="); found {
			label, _ = url.QueryUnescape(v)
		}
	}
	return id, label, id != ""
}

func parseCronEntryLine(line string) (schedule, command string, enabled, ok bool) {
	trimmed := strings.TrimSpace(line)
	enabled = true
	if strings.HasPrefix(trimmed, "#") {
		enabled = false
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "", "", false, false
	}
	if strings.HasPrefix(fields[0], "@") {
		if len(fields) < 2 {
			return "", "", false, false
		}
		return fields[0], strings.Join(fields[1:], " "), enabled, true
	}
	if len(fields) < 6 {
		return "", "", false, false
	}
	return strings.Join(fields[:5], " "), strings.Join(fields[5:], " "), enabled, true
}

// listCronJobs parses every serverpanel-managed marker+entry pair out of a
// crontab's raw content. Lines that aren't part of a managed block (an
// unrelated cron entry a human added directly, blank lines, comments) are
// simply not returned — listCronJobs never mutates or reports on entries it
// doesn't own.
func listCronJobs(content string) []cronJob {
	lines := strings.Split(content, "\n")
	var jobs []cronJob
	for i := 0; i < len(lines); i++ {
		id, label, ok := parseCronMarker(lines[i])
		if !ok {
			continue
		}
		if i+1 >= len(lines) {
			continue
		}
		schedule, command, enabled, ok := parseCronEntryLine(lines[i+1])
		if !ok {
			continue
		}
		jobs = append(jobs, cronJob{ID: id, Label: label, Schedule: schedule, Command: command, Enabled: enabled})
		i++
	}
	return jobs
}

// upsertCronJob returns crontab content with job's marker+entry block
// replaced in place if one with the same ID already exists, or appended
// otherwise. Every other line (including entries this package didn't
// create) is preserved verbatim and in order.
func upsertCronJob(content string, job cronJob) string {
	lines := strings.Split(content, "\n")
	var out []string
	replaced := false
	for i := 0; i < len(lines); i++ {
		id, _, ok := parseCronMarker(lines[i])
		if ok && id == job.ID {
			out = append(out, marshalCronEntry(job)...)
			replaced = true
			if i+1 < len(lines) {
				i++ // skip the old entry line that belongs to this marker
			}
			continue
		}
		out = append(out, lines[i])
	}
	if !replaced {
		for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
			out = out[:len(out)-1]
		}
		out = append(out, marshalCronEntry(job)...)
	}
	return strings.Join(out, "\n")
}

// removeCronJob returns crontab content with the marker+entry block for id
// removed. Every other line is preserved verbatim.
func removeCronJob(content string, id string) string {
	lines := strings.Split(content, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		mid, _, ok := parseCronMarker(lines[i])
		if ok && mid == id {
			if i+1 < len(lines) {
				i++
			}
			continue
		}
		out = append(out, lines[i])
	}
	return strings.Join(out, "\n")
}

// readUserCrontab returns the raw content of user's crontab, or "" if the
// user has none yet (crontab -l exits non-zero with "no crontab for ..." in
// that case — a normal, expected state, not an error).
func readUserCrontab(ctx context.Context, user string) (string, error) {
	out, err := run(ctx, "crontab", "-u", user, "-l")
	if err != nil {
		if strings.Contains(out, "no crontab for") {
			return "", nil
		}
		return "", fmt.Errorf("read crontab for %s: %w: %s", user, err, out)
	}
	return out, nil
}

// writeUserCrontab replaces user's entire crontab with content, via
// `crontab -u <user> -` reading the new content from stdin — never a shell
// string built from caller-supplied text.
func writeUserCrontab(ctx context.Context, user, content string) error {
	cmd := exec.CommandContext(ctx, "crontab", "-u", user, "-")
	cmd.Stdin = strings.NewReader(strings.TrimRight(content, "\n") + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("write crontab for %s: %w: %s", user, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func handleCronList(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["system_user"].(string)
	if err := validCronSystemUser(ctx, user); err != nil {
		return "", err
	}
	content, err := readUserCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	jobs := listCronJobs(content)
	if jobs == nil {
		jobs = []cronJob{}
	}
	out, _ := json.Marshal(jobs)
	return string(out), nil
}

func handleCronSet(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["system_user"].(string)
	id, _ := params["id"].(string)
	label, _ := params["label"].(string)
	schedule, _ := params["schedule"].(string)
	command, _ := params["command"].(string)
	enabled := true
	if v, ok := params["enabled"].(bool); ok {
		enabled = v
	}

	if id == "" {
		return "", fmt.Errorf("id is required")
	}
	if err := validCronSystemUser(ctx, user); err != nil {
		return "", err
	}
	if err := validCronSchedule(schedule); err != nil {
		return "", err
	}
	if err := validCronCommand(command); err != nil {
		return "", err
	}
	if err := validCronLabel(label); err != nil {
		return "", err
	}

	progress("reading existing crontab for " + user)
	content, err := readUserCrontab(ctx, user)
	if err != nil {
		return "", err
	}

	job := cronJob{ID: id, Label: label, Schedule: schedule, Command: command, Enabled: enabled}
	newContent := upsertCronJob(content, job)

	progress("writing crontab for " + user)
	if err := writeUserCrontab(ctx, user, newContent); err != nil {
		return "", err
	}

	out, _ := json.Marshal(job)
	return string(out), nil
}

func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["system_user"].(string)
	id, _ := params["id"].(string)
	if id == "" {
		return "", fmt.Errorf("id is required")
	}
	if err := validCronSystemUser(ctx, user); err != nil {
		return "", err
	}

	content, err := readUserCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	newContent := removeCronJob(content, id)

	progress("writing crontab for " + user)
	if err := writeUserCrontab(ctx, user, newContent); err != nil {
		return "", err
	}
	return fmt.Sprintf("cron job %q removed", id), nil
}
