package capabilities

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// cronMarkerPrefix tags each entry this project's cron management ever
// writes. Site users have a nologin shell (see site.go handleSiteCreate),
// so this is the *only* way a site's crontab is ever modified — there is no
// scenario where a site owner has hand-edited it out of band that this
// format needs to tolerate, but the parser still ignores anything that
// doesn't match the marker so a manually installed crontab is never
// silently clobbered by a create/delete round trip.
const cronMarkerPrefix = "# serverpanel-cron id="

// cronFieldRe validates one of the five whitespace-separated cron schedule
// fields (minute hour day-of-month month day-of-week): digits, "*",
// ranges, steps, and comma lists. Named values (e.g. "mon-fri") are not
// accepted in this release — numeric-only keeps the validator small and
// unambiguous; a dashboard-side preset picker can still translate common
// choices ("every 5 minutes", "daily at 2am") into numeric fields.
var cronFieldRe = regexp.MustCompile(`^(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?(,(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?)*$`)

// cronEntry is one managed cron job. It is what cron.list/create return as
// TaskEvent detail (JSON) for the control plane to relay to the dashboard;
// see apps/controlplane/crons.go.
type cronEntry struct {
	ID       string `json:"id"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Label    string `json:"label"`
}

func validateCronSystemUser(sysUser string) error {
	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return fmt.Errorf("cron jobs may only be managed for an isolated application user, got %q", sysUser)
	}
	return nil
}

func validateCronSchedule(schedule string) error {
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return fmt.Errorf("schedule must have exactly 5 fields (minute hour day-of-month month day-of-week), got %d", len(fields))
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return fmt.Errorf("invalid cron schedule field %q", f)
		}
	}
	return nil
}

// validateCronCommand rejects the two things that would let a command
// string smuggle extra crontab entries or corrupt the managed file: a
// newline (which would let the "command" become its own crontab line — or
// worse, forge another marker comment) and unbounded length. It does not
// otherwise restrict what the command runs: this job executes as the
// site's own already-isolated system user (never root — validateCronSystemUser
// enforces that), the same trust boundary a deployed PHP file already
// crosses, so an arbitrary shell command here is not a new privilege.
func validateCronCommand(command string) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return fmt.Errorf("command is required")
	}
	if strings.ContainsAny(command, "\n\r") {
		return fmt.Errorf("command must be a single line")
	}
	if len(command) > 4000 {
		return fmt.Errorf("command is too long (4000 characters max)")
	}
	return nil
}

func validateCronLabel(label string) error {
	if strings.ContainsAny(label, "\n\r") {
		return fmt.Errorf("label must be a single line")
	}
	if len(label) > 200 {
		return fmt.Errorf("label is too long (200 characters max)")
	}
	return nil
}

func newCronID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func encodeCronLabel(label string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(label))
}

func decodeCronLabel(encoded string) string {
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return string(b)
}

// renderCrontab formats entries as a complete crontab body. It is always
// used to replace the whole file (via writeCrontab), never to append —
// that is what makes delete-by-id and create-by-append both safe to
// implement as "parse, mutate the in-memory list, write the whole thing
// back": there is never a partial/interleaved edit of the file on disk.
func renderCrontab(entries []cronEntry) string {
	var b strings.Builder
	b.WriteString("# Managed by ServerPanel. Do not edit by hand; changes made through\n")
	b.WriteString("# the dashboard regenerate this file in full.\n")
	for _, e := range entries {
		labelEnc := encodeCronLabel(e.Label)
		fmt.Fprintf(&b, "%s%s label=%s\n%s %s\n", cronMarkerPrefix, e.ID, labelEnc, e.Schedule, e.Command)
	}
	return b.String()
}

// parseCrontab reads back what renderCrontab wrote. A marker line not
// immediately followed by a well-formed schedule+command line is skipped
// rather than erroring — the source of truth is whatever crontab already
// installed, and a single malformed pair (e.g. from a version of this code
// that changes the format later) should not make every other entry
// unreadable.
func parseCrontab(text string) []cronEntry {
	lines := strings.Split(text, "\n")
	var out []cronEntry
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !strings.HasPrefix(line, cronMarkerPrefix) {
			continue
		}
		rest := strings.TrimPrefix(line, cronMarkerPrefix)
		id := rest
		label := ""
		if idx := strings.Index(rest, " label="); idx >= 0 {
			id = rest[:idx]
			label = decodeCronLabel(rest[idx+len(" label="):])
		}
		if id == "" || i+1 >= len(lines) {
			continue
		}
		fields := strings.Fields(lines[i+1])
		if len(fields) < 6 {
			continue
		}
		out = append(out, cronEntry{
			ID:       id,
			Schedule: strings.Join(fields[:5], " "),
			Command:  strings.Join(fields[5:], " "),
			Label:    label,
		})
		i++ // the schedule/command line was consumed as part of this pair
	}
	return out
}

// readCrontab returns the current managed entries for sysUser, treating
// "no crontab for <user>" (crontab -l's exit status for a user who has
// never had one installed) as zero entries rather than an error.
func readCrontab(ctx context.Context, sysUser string) ([]cronEntry, error) {
	out, err := run(ctx, "crontab", "-u", sysUser, "-l")
	if err != nil {
		if strings.Contains(out, "no crontab for") {
			return nil, nil
		}
		return nil, fmt.Errorf("read crontab for %s: %w: %s", sysUser, err, out)
	}
	return parseCrontab(out), nil
}

// writeCrontab replaces sysUser's entire crontab. Content is piped over
// stdin (never a shell, never an argv built from caller-supplied text) so
// arbitrarily long/odd command text never has to survive an argv or shell
// quoting boundary.
func writeCrontab(ctx context.Context, sysUser string, entries []cronEntry) error {
	content := renderCrontab(entries)
	cmd := exec.CommandContext(ctx, "crontab", "-u", sysUser, "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("write crontab for %s: %w: %s", sysUser, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func handleCronList(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	if err := validateCronSystemUser(sysUser); err != nil {
		return "", err
	}

	entries, err := readCrontab(ctx, sysUser)
	if err != nil {
		return "", err
	}
	if entries == nil {
		entries = []cronEntry{}
	}
	out, _ := json.Marshal(entries)
	return string(out), nil
}

func handleCronCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	schedule, _ := params["schedule"].(string)
	command, _ := params["command"].(string)
	label, _ := params["label"].(string)

	if err := validateCronSystemUser(sysUser); err != nil {
		return "", err
	}
	if err := validateCronSchedule(schedule); err != nil {
		return "", err
	}
	if err := validateCronCommand(command); err != nil {
		return "", err
	}
	if err := validateCronLabel(label); err != nil {
		return "", err
	}

	entries, err := readCrontab(ctx, sysUser)
	if err != nil {
		return "", err
	}
	entry := cronEntry{ID: newCronID(), Schedule: schedule, Command: command, Label: label}
	entries = append(entries, entry)

	progress("writing crontab for " + sysUser)
	if err := writeCrontab(ctx, sysUser, entries); err != nil {
		return "", err
	}

	out, _ := json.Marshal(entry)
	return string(out), nil
}

func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	id, _ := params["id"].(string)

	if err := validateCronSystemUser(sysUser); err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("id is required")
	}

	entries, err := readCrontab(ctx, sysUser)
	if err != nil {
		return "", err
	}

	kept := entries[:0]
	found := false
	for _, e := range entries {
		if e.ID == id {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return "", fmt.Errorf("cron job %q not found", id)
	}

	progress("writing crontab for " + sysUser)
	if err := writeCrontab(ctx, sysUser, kept); err != nil {
		return "", err
	}
	return "cron job removed", nil
}
