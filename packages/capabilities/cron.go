package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// cronMarkerBegin/End delimit the block of this system user's crontab that
// ServerPanel owns. cron.sync only ever replaces the content between these
// markers, preserving any lines the user (or another tool) added outside
// them — the same "don't clobber what we don't own" principle site.go's
// writeDefaultIndex applies to an existing index file.
const (
	cronMarkerBegin = "# >>> serverpanel managed cron jobs — do not edit by hand, changes are overwritten <<<"
	cronMarkerEnd   = "# <<< end serverpanel managed cron jobs >>>"
)

var cronShortcuts = map[string]bool{
	"@yearly": true, "@annually": true, "@monthly": true, "@weekly": true,
	"@daily": true, "@midnight": true, "@hourly": true, "@reboot": true,
}

// cronNames is the set of three-letter month/day-of-week abbreviations
// standard cron accepts in place of a number.
var cronNames = map[string]bool{
	"jan": true, "feb": true, "mar": true, "apr": true, "may": true, "jun": true,
	"jul": true, "aug": true, "sep": true, "oct": true, "nov": true, "dec": true,
	"sun": true, "mon": true, "tue": true, "wed": true, "thu": true, "fri": true, "sat": true,
}

var digitsRe = regexp.MustCompile(`^[0-9]+$`)

// validCronField validates one of the five whitespace-separated schedule
// fields against real cron grammar (comma-separated lists of `*`, a
// number, a three-letter name, an `a-b` range, or any of those with a
// `/step`) — deliberately stricter than "safe character set" so that
// something like the word "sixty" in place of a minute is rejected here
// rather than silently accepted and only failing later at `crontab -u
// <user> -`.
func validCronField(f string) bool {
	if f == "" {
		return false
	}
	for _, part := range strings.Split(f, ",") {
		base := part
		if i := strings.Index(part, "/"); i >= 0 {
			base = part[:i]
			step := part[i+1:]
			if step == "" || !digitsRe.MatchString(step) {
				return false
			}
		}
		if base == "*" {
			continue
		}
		for _, endpoint := range strings.SplitN(base, "-", 2) {
			if endpoint == "" {
				return false
			}
			if digitsRe.MatchString(endpoint) || cronNames[strings.ToLower(endpoint)] {
				continue
			}
			return false
		}
	}
	return true
}

func validCronSchedule(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if cronShortcuts[s] {
		return true
	}
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return false
	}
	for _, f := range fields {
		if !validCronField(f) {
			return false
		}
	}
	return true
}

// validCronCommand rejects anything that would break the one-job-per-line
// crontab format (newlines) or is unreasonably large; it does not restrict
// shell syntax within the command itself. That's deliberate: a cron job's
// command is inherently an arbitrary shell command, same as cPanel/
// ServerAvatar/every other panel's cron feature — the isolation boundary is
// which system user runs it (cron.sync always writes into exactly one
// already-isolated site user's crontab, never root's), not what the
// command's text contains.
func validCronCommand(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" || len(cmd) > 1000 {
		return false
	}
	return !strings.ContainsAny(cmd, "\n\r")
}

// cronJobSpec is one entry cron.sync is told to ensure exists. ID is
// opaque to the agent (the control plane's cron_jobs.id) and is embedded as
// a trailing shell comment purely so an operator inspecting `crontab -l`
// by hand can map a line back to the dashboard.
type cronJobSpec struct {
	ID       string `json:"id"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
}

// escapeCronPercent guards against cron's own quirk where an unescaped "%"
// in a crontab command is treated as a newline (and everything after it as
// stdin to the command) rather than a literal percent sign — surprising
// behavior a job author almost never intends, so it's escaped automatically
// rather than left as a footgun.
func escapeCronPercent(cmd string) string {
	return strings.ReplaceAll(cmd, "%", `\%`)
}

// handleCronSync replaces the entire ServerPanel-managed block of
// system_user's crontab with exactly the jobs listed in params["jobs"] —
// idempotent by construction (a retry produces the same crontab, not a
// duplicated one) and the reason the control plane never issues an
// incremental "add one line" agent command: the persisted job list in the
// control plane's database is always the single source of truth, and
// cron.sync's only contract is "make the live crontab match it".
func handleCronSync(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return "", fmt.Errorf("invalid system_user")
	}

	rawJobs, _ := params["jobs"].([]any)
	jobs := make([]cronJobSpec, 0, len(rawJobs))
	for _, r := range rawJobs {
		b, err := json.Marshal(r)
		if err != nil {
			return "", fmt.Errorf("invalid job entry: %w", err)
		}
		var j cronJobSpec
		if err := json.Unmarshal(b, &j); err != nil {
			return "", fmt.Errorf("invalid job entry: %w", err)
		}
		if j.ID == "" {
			return "", fmt.Errorf("job missing id")
		}
		if !validCronSchedule(j.Schedule) {
			return "", fmt.Errorf("job %s: invalid schedule %q", j.ID, j.Schedule)
		}
		if !validCronCommand(j.Command) {
			return "", fmt.Errorf("job %s: invalid command", j.ID)
		}
		jobs = append(jobs, j)
	}

	if _, err := exec.LookPath("crontab"); err != nil {
		return "", fmt.Errorf("crontab is not installed on this server")
	}
	if _, err := run(ctx, "id", "-u", sysUser); err != nil {
		return "", fmt.Errorf("system user %q does not exist", sysUser)
	}

	progress(fmt.Sprintf("syncing %d cron job(s) for %s", len(jobs), sysUser))

	existing, _ := run(ctx, "crontab", "-u", sysUser, "-l")
	preserved := stripManagedBlock(existing)

	var block strings.Builder
	block.WriteString(cronMarkerBegin + "\n")
	for _, j := range jobs {
		fmt.Fprintf(&block, "%s %s # serverpanel:%s\n", j.Schedule, escapeCronPercent(j.Command), j.ID)
	}
	block.WriteString(cronMarkerEnd + "\n")

	newCrontab := preserved
	if newCrontab != "" && !strings.HasSuffix(newCrontab, "\n") {
		newCrontab += "\n"
	}
	newCrontab += block.String()

	if out, err := runWithStdin(ctx, newCrontab, "crontab", "-u", sysUser, "-"); err != nil {
		return "", fmt.Errorf("crontab -u %s -: %w: %s", sysUser, err, out)
	}

	return fmt.Sprintf("synced %d cron job(s) for %s", len(jobs), sysUser), nil
}

// stripManagedBlock removes a previous ServerPanel-managed block (if any)
// from an existing crontab listing, leaving any other lines untouched and
// in their original order/position.
func stripManagedBlock(crontab string) string {
	lines := strings.Split(crontab, "\n")
	var out []string
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == cronMarkerBegin:
			inBlock = true
			continue
		case trimmed == cronMarkerEnd:
			inBlock = false
			continue
		case inBlock:
			continue
		case strings.Contains(trimmed, "no crontab for"):
			// `crontab -l`'s "no crontab for <user>" error text, when
			// captured via CombinedOutput on an empty crontab — never a
			// real line to preserve.
			continue
		default:
			out = append(out, line)
		}
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}
