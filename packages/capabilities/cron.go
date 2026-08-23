package capabilities

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// cronFieldRe matches one cron schedule field: digits, *, /, -, , only —
// never letters or shell metacharacters, since these values end up written
// verbatim into a crontab line.
var cronFieldRe = regexp.MustCompile(`^[0-9*/,-]+$`)

// cronAliasRe matches the standard cron "nickname" schedules, accepted as a
// whole-schedule alternative to the 5-field form.
var cronAliasRe = regexp.MustCompile(`^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)$`)

// maxCronCommandLen bounds a cron command's stored/rendered length — cron
// lines are unbounded in principle, but a sane ceiling keeps a single job
// from producing an unreasonably large crontab file.
const maxCronCommandLen = 2000

// ValidateCronSchedule reports whether schedule is a valid 5-field cron
// expression or one of the standard @alias forms. Exported so the control
// plane can reject an invalid schedule with a 400 before ever dispatching to
// an agent.
func ValidateCronSchedule(schedule string) error {
	if cronAliasRe.MatchString(schedule) {
		return nil
	}
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return fmt.Errorf("schedule must have 5 space-separated fields (minute hour day month weekday) or be a @alias like @daily, got %q", schedule)
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return fmt.Errorf("invalid schedule field %q: only digits, *, /, -, and , are allowed", f)
		}
	}
	return nil
}

// ValidateCronCommand reports whether command is safe to render as a single
// crontab line. Cron jobs run as the site's own isolated, unprivileged
// system user (see site.go), so the security boundary here is the same
// per-site isolation every other site capability relies on — not a
// restriction on what that user's own command may do. What this function
// guards against is a command that would corrupt or escape the generated
// crontab file itself (an embedded newline would inject an extra,
// unvalidated line).
func ValidateCronCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("command is required")
	}
	if strings.ContainsAny(command, "\n\r") {
		return fmt.Errorf("command must not contain newlines")
	}
	if len(command) > maxCronCommandLen {
		return fmt.Errorf("command exceeds the maximum length of %d characters", maxCronCommandLen)
	}
	return nil
}

// cronJobSpec is one job in cron.apply's params.jobs list.
type cronJobSpec struct {
	Schedule string
	Command  string
	Comment  string
	Enabled  bool
}

// buildCrontabContent renders the full managed crontab body for one system
// user from its current job list. cron.apply always replaces sysUser's
// entire crontab (never appends/edits a single line), so the control
// plane's job records and the live crontab can never drift apart — the same
// "regenerate the whole managed file from the record of truth" pattern
// site.go's nginx vhost and php-fpm pool writers use.
func buildCrontabContent(sysUser string, jobs []cronJobSpec) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by ServerPanel for %s. Do not edit by hand; changes made\n", sysUser)
	b.WriteString("# through the dashboard regenerate this file.\n")
	b.WriteString("SHELL=/bin/sh\n")

	for i, j := range jobs {
		if err := ValidateCronSchedule(j.Schedule); err != nil {
			return "", fmt.Errorf("job %d: %w", i, err)
		}
		if err := ValidateCronCommand(j.Command); err != nil {
			return "", fmt.Errorf("job %d: %w", i, err)
		}
		if comment := strings.TrimSpace(oneLine(j.Comment)); comment != "" {
			b.WriteString("# " + comment + "\n")
		}
		line := j.Schedule + " " + j.Command
		if !j.Enabled {
			line = "#" + line
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String(), nil
}

// oneLine collapses any newlines in a comment down to a single crontab
// comment line, since a raw newline there would otherwise inject an
// unvalidated, unintended crontab entry.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// handleCronApply replaces the entire crontab for one isolated site system
// user with the job list the control plane supplies. There is no
// cron.create/cron.delete capability — every cron mutation goes through
// this same full regeneration, which is what keeps a partially-applied edit
// from ever being possible.
func handleCronApply(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return "", fmt.Errorf("invalid system_user")
	}

	rawJobs, _ := params["jobs"].([]any)
	jobs := make([]cronJobSpec, 0, len(rawJobs))
	for i, rj := range rawJobs {
		m, ok := rj.(map[string]any)
		if !ok {
			return "", fmt.Errorf("job %d: invalid job entry", i)
		}
		schedule, _ := m["schedule"].(string)
		command, _ := m["command"].(string)
		comment, _ := m["comment"].(string)
		enabled, _ := m["enabled"].(bool)
		jobs = append(jobs, cronJobSpec{Schedule: schedule, Command: command, Comment: comment, Enabled: enabled})
	}

	content, err := buildCrontabContent(sysUser, jobs)
	if err != nil {
		return "", err
	}

	progress(fmt.Sprintf("writing crontab for %s (%d job(s))", sysUser, len(jobs)))
	if err := installCrontab(ctx, sysUser, content); err != nil {
		return "", err
	}
	return fmt.Sprintf("crontab applied for %s: %d job(s)", sysUser, len(jobs)), nil
}

// installCrontab replaces sysUser's entire crontab via `crontab -u <user>
// -`, streaming the generated content over stdin rather than through a temp
// file path or a shell-interpolated argv. crontab(1) itself parses and
// validates the file and rejects a malformed one without touching the
// previously installed crontab, so a bad generated file can never leave the
// user with a broken or half-written one.
func installCrontab(ctx context.Context, sysUser, content string) error {
	cmd := exec.CommandContext(ctx, "crontab", "-u", sysUser, "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("crontab -u %s: %w: %s", sysUser, err, strings.TrimSpace(string(out)))
	}
	return nil
}
