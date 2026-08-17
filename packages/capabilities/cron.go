package capabilities

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// cronFieldRe allow-lists the characters a single cron schedule field may
// contain (standard 5-field cron: minute hour day-of-month month
// day-of-week) — digits plus the *, /, -, and , used for
// steps/ranges/lists/wildcards. No named shortcuts (@daily) or macros:
// nothing here needs its own parser to validate safely.
var cronFieldRe = regexp.MustCompile(`^[0-9*/,-]+$`)

// cronJobIDRe is the allow-list for a cron job's own ID, which this handler
// uses both as a crontab comment marker and as a path component of that
// job's output log file — so, like every other path-relevant value in this
// package, it is revalidated here rather than trusted just because it
// originated from the control plane.
var cronJobIDRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// cronArgRe is deliberately restrictive: no shell metacharacters, no
// whitespace, no quotes. Every character it allows means exactly itself
// when the resulting crontab line is later parsed by cron's own /bin/sh,
// so args never need (and never get) shell-quoting — there is no character
// in this set that could terminate the intended command, chain a second
// one, or trigger redirection/substitution.
var cronArgRe = regexp.MustCompile(`^[A-Za-z0-9_./=:@-]{1,200}$`)

// cronAllowedBinaries is the fixed set of programs a cron job may invoke.
// This is the same "allow-list of the thing, not free text" boundary
// site.create's app_type check and service.control's managedUnits use:
// cron jobs are not a general command-execution feature, they are "run one
// of these specific, already-vetted tools on a schedule." Each entry is
// resolved to an absolute path at sync time (never left to cron's own,
// often minimal, default PATH), so a job that worked when created doesn't
// silently start failing at 2am because cron couldn't find it on PATH.
var cronAllowedBinaries = map[string]string{
	"php":      "php8.3",
	"wp":       "/usr/local/bin/wp",
	"composer": "/usr/local/bin/composer",
	"curl":     "curl",
}

// maxCronJobsPerSync bounds how many jobs a single cron.sync call will
// write, which is what stands between "manage cron jobs for a site" and an
// unbounded crontab file for one system user.
const maxCronJobsPerSync = 100

// cronLogBaseDir is a var (not const) so tests can point it at a temp
// directory instead of the real system path, matching backupBaseDir.
var cronLogBaseDir = "/var/log/serverpanel/cron"

type cronJobSpec struct {
	ID       string
	Schedule string
	// Line is the fully resolved, already-safe command text (absolute
	// binary path + validated args + output redirection to a
	// server-constructed log path) that goes directly after the schedule
	// field in the crontab line.
	Line string
}

type cronSyncResult struct {
	RunAsUser string `json:"run_as_user"`
	JobCount  int    `json:"job_count"`
}

// validateCronSchedule checks schedule and, on success, returns it
// re-normalized as exactly 5 single-space-separated fields. Returning the
// normalized form (not the caller's original string) matters: strings.
// Fields splits on any run of whitespace, including a literal newline, so
// e.g. "0\n3 * * *" also tokenizes into 5 fields that each individually
// pass cronFieldRe — if the original string were used as-is in the
// generated crontab line, that embedded newline would terminate the line
// early and let the rest be parsed as a second, attacker-controlled
// crontab entry. Every caller of this function must use the returned,
// normalized string, never the input, for exactly that reason.
func validateCronSchedule(schedule string) (string, error) {
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return "", fmt.Errorf("schedule must have exactly 5 fields (minute hour day-of-month month day-of-week), got %d", len(fields))
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return "", fmt.Errorf("invalid schedule field %q", f)
		}
	}
	return strings.Join(fields, " "), nil
}

// resolveCronBinary maps an allow-listed logical name to the absolute path
// cron should invoke, failing clearly if that tool isn't actually
// installed on this server rather than writing a crontab entry that will
// only be discovered to be broken the first time it silently fails to run.
func resolveCronBinary(name string) (string, error) {
	target, ok := cronAllowedBinaries[name]
	if !ok {
		return "", fmt.Errorf("binary %q is not an allow-listed cron command", name)
	}
	if strings.HasPrefix(target, "/") {
		if _, err := os.Stat(target); err != nil {
			return "", fmt.Errorf("%s is not installed on this server (expected at %s); run stack.install first", name, target)
		}
		return target, nil
	}
	resolved, err := exec.LookPath(target)
	if err != nil {
		return "", fmt.Errorf("%s is not installed on this server; run stack.install first", name)
	}
	return resolved, nil
}

// handleCronSync replaces run_as_user's entire crontab with exactly the job
// set given. Create, edit, delete, enable, and disable a cron job are all,
// agent-side, just "sync the desired job list" — the same "control plane
// is the source of truth, regenerate the whole file" pattern site.create
// uses for nginx vhosts. There is deliberately no incremental
// add-one-line/remove-one-line capability: it keeps the allow-list small
// and makes every sync trivially idempotent and safe to retry.
func handleCronSync(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	runAsUser, _ := params["run_as_user"].(string)
	if !strings.HasPrefix(runAsUser, "site_") {
		return "", fmt.Errorf("run_as_user must be a managed site system user")
	}
	if _, err := run(ctx, "id", "-u", runAsUser); err != nil {
		return "", fmt.Errorf("run_as_user %q is not a known system user", runAsUser)
	}

	rawJobs, _ := params["jobs"].([]any)
	if len(rawJobs) > maxCronJobsPerSync {
		return "", fmt.Errorf("too many cron jobs (%d), maximum is %d per site", len(rawJobs), maxCronJobsPerSync)
	}

	logDir := cronLogBaseDir + "/" + runAsUser

	jobs := make([]cronJobSpec, 0, len(rawJobs))
	for _, raw := range rawJobs {
		m, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("each job must be an object")
		}
		id, _ := m["id"].(string)
		schedule, _ := m["schedule"].(string)
		binaryName, _ := m["binary"].(string)
		rawArgs, _ := m["args"].([]any)

		if !cronJobIDRe.MatchString(id) {
			return "", fmt.Errorf("invalid job id %q", id)
		}
		normalizedSchedule, err := validateCronSchedule(schedule)
		if err != nil {
			return "", fmt.Errorf("job %s: %w", id, err)
		}
		binaryPath, err := resolveCronBinary(binaryName)
		if err != nil {
			return "", fmt.Errorf("job %s: %w", id, err)
		}
		args := make([]string, 0, len(rawArgs))
		for _, a := range rawArgs {
			s, ok := a.(string)
			if !ok || !cronArgRe.MatchString(s) {
				return "", fmt.Errorf("job %s: invalid argument %q", id, a)
			}
			args = append(args, s)
		}

		line := strings.Join(append([]string{binaryPath}, args...), " ")
		line += fmt.Sprintf(" >> %s/%s.log 2>&1", logDir, id)
		jobs = append(jobs, cronJobSpec{ID: id, Schedule: normalizedSchedule, Line: line})
	}

	// Deterministic file contents regardless of the order the caller sent
	// jobs in — makes the resulting crontab (and tests asserting on it)
	// stable across retries.
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })

	if len(jobs) > 0 {
		progress("preparing cron output log directory")
		if err := os.MkdirAll(logDir, 0750); err != nil {
			return "", fmt.Errorf("create cron log directory: %w", err)
		}
		if out, err := run(ctx, "chown", "-R", runAsUser+":"+runAsUser, logDir); err != nil {
			return "", fmt.Errorf("chown cron log directory: %w: %s", err, out)
		}
	}

	progress(fmt.Sprintf("writing %d cron job(s) for %s", len(jobs), runAsUser))

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Managed by ServerPanel for %s. Do not edit by hand;\n", runAsUser)
	buf.WriteString("# changes made through the dashboard regenerate this file.\n")
	for _, j := range jobs {
		fmt.Fprintf(&buf, "%s %s # serverpanel:%s\n", j.Schedule, j.Line, j.ID)
	}

	cmd := exec.CommandContext(ctx, "crontab", "-u", runAsUser, "-")
	cmd.Stdin = bytes.NewReader(buf.Bytes())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("crontab -u %s: %w: %s", runAsUser, err, strings.TrimSpace(string(out)))
	}

	res := cronSyncResult{RunAsUser: runAsUser, JobCount: len(jobs)}
	outJSON, _ := json.Marshal(res)
	return string(outJSON), nil
}
