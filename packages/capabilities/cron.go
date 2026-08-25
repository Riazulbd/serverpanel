package capabilities

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
)

// Cron jobs are always scoped to one isolated site system user (never root,
// never an arbitrary username) — the same isolation boundary site.go
// already establishes. The command a job runs is opaque to us (that's the
// point of a cron job), but it only ever reaches `crontab`, which hands it
// to that user's own crontab; cron itself later executes it under that
// user's uid, exactly as if the user had run `crontab -e` over SSH. This
// package never runs the job command itself.
var cronUserRe = regexp.MustCompile(`^site_[a-z0-9_]{1,32}$`)

// cronMacros are the standard cron time-specification macros accepted in
// place of five space-separated fields.
var cronMacros = map[string]bool{
	"@yearly": true, "@annually": true, "@monthly": true, "@weekly": true,
	"@daily": true, "@midnight": true, "@hourly": true, "@reboot": true,
}

// cronFieldRe is deliberately permissive within a safe charset (digits,
// `*`, `,`, `-`, `/`) rather than trying to fully validate cron field
// semantics — invalid-but-safe expressions are rejected by cron itself at
// read time; what matters here is that no field can smuggle a newline or
// shell metacharacter into the crontab file.
var cronFieldRe = regexp.MustCompile(`^[0-9*,/-]+$`)

const cronMarkerPrefix = "# serverpanel-cron "

// CronEntry is one managed cron job, as returned by cron.list/cron.create
// and persisted (as plain crontab text, not a database row — the
// crontab is the source of truth, matching db.list's live-query pattern)
// via a marker comment line immediately followed by the job line.
type CronEntry struct {
	ID       string `json:"id"`
	User     string `json:"user"`
	Label    string `json:"label"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Enabled  bool   `json:"enabled"`
}

func validateCronUser(user string) error {
	if !cronUserRe.MatchString(user) {
		return fmt.Errorf("cron jobs may only be scheduled for an isolated site system user, got %q", user)
	}
	return nil
}

func validateSchedule(schedule string) error {
	if cronMacros[schedule] {
		return nil
	}
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return fmt.Errorf("schedule must have exactly 5 fields (minute hour day-of-month month day-of-week) or be a macro like @daily, got %q", schedule)
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return fmt.Errorf("invalid schedule field %q", f)
		}
	}
	return nil
}

func validateCommand(command string) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return fmt.Errorf("command is required")
	}
	if len(command) > 1024 {
		return fmt.Errorf("command must be at most 1024 characters")
	}
	if strings.ContainsAny(command, "\n\r\x00") {
		return fmt.Errorf("command must not contain newlines")
	}
	return nil
}

func validateLabel(label string) error {
	if len(label) > 80 {
		return fmt.Errorf("label must be at most 80 characters")
	}
	if strings.ContainsAny(label, "\n\r\x00") {
		return fmt.Errorf("label must not contain newlines")
	}
	return nil
}

func newCronID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// parseCrontab extracts every serverpanel-managed entry from raw crontab
// text. Lines that aren't part of a recognized marker+job pair (a user's
// own MAILTO=, blank lines, unrelated comments or jobs) are ignored here
// but preserved verbatim by rewriteCrontab, so this package never touches
// cron state it didn't create.
func parseCrontab(content, user string) []CronEntry {
	lines := strings.Split(content, "\n")
	var entries []CronEntry
	for i := 0; i < len(lines); i++ {
		id, label, enabled, ok := parseMarkerLine(lines[i])
		if !ok || i+1 >= len(lines) {
			continue
		}
		jobLine := lines[i+1]
		schedule, command, jobOK := parseJobLine(jobLine)
		if !jobOK {
			continue
		}
		entries = append(entries, CronEntry{
			ID: id, User: user, Label: label, Schedule: schedule, Command: command, Enabled: enabled,
		})
		i++ // consumed the job line too
	}
	return entries
}

func parseMarkerLine(line string) (id, label string, enabled, ok bool) {
	if !strings.HasPrefix(line, cronMarkerPrefix) {
		return "", "", false, false
	}
	rest := strings.TrimPrefix(line, cronMarkerPrefix)
	fields := strings.Fields(rest)
	enabled = true
	for _, f := range fields {
		if v, found := strings.CutPrefix(f, "id="); found {
			id = v
		} else if v, found := strings.CutPrefix(f, "enabled="); found {
			enabled = v == "true"
		} else if v, found := strings.CutPrefix(f, "label="); found {
			if decoded, err := url.QueryUnescape(v); err == nil {
				label = decoded
			}
		}
	}
	if id == "" {
		return "", "", false, false
	}
	return id, label, enabled, true
}

func parseJobLine(line string) (schedule, command string, ok bool) {
	active := strings.TrimPrefix(line, "#")
	active = strings.TrimSpace(active)
	fields := strings.SplitN(active, " ", 6)
	if strings.HasPrefix(active, "@") {
		if len(fields) < 2 {
			return "", "", false
		}
		return fields[0], strings.TrimSpace(strings.Join(fields[1:], " ")), true
	}
	if len(fields) < 6 {
		return "", "", false
	}
	return strings.Join(fields[:5], " "), strings.TrimSpace(fields[5]), true
}

func renderMarkerLine(e CronEntry) string {
	return fmt.Sprintf("%sid=%s enabled=%t label=%s", cronMarkerPrefix, e.ID, e.Enabled, url.QueryEscape(e.Label))
}

func renderJobLine(e CronEntry) string {
	line := e.Schedule + " " + e.Command
	if !e.Enabled {
		line = "#" + line
	}
	return line
}

// rewriteCrontab applies one change (upsert or delete, selected by
// whether entry is nil) to raw crontab content, preserving every line
// that isn't part of the managed entry's own marker+job pair. Existing
// pairs for other ids, and any content the user or another tool put in
// this crontab, are left byte-for-byte alone.
func rewriteCrontab(content, targetID string, entry *CronEntry) string {
	lines := strings.Split(content, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		id, _, _, ok := parseMarkerLine(lines[i])
		if ok && id == targetID && i+1 < len(lines) {
			i++ // drop this managed pair; replaced or deleted below
			continue
		}
		out = append(out, lines[i])
	}
	// Trim trailing blank lines left over from the drop, so repeated
	// updates don't accumulate empty lines at the end of the file.
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	if entry != nil {
		out = append(out, renderMarkerLine(*entry), renderJobLine(*entry))
	}
	return strings.Join(out, "\n") + "\n"
}

func readUserCrontab(ctx context.Context, user string) (string, error) {
	out, err := run(ctx, "crontab", "-u", user, "-l")
	if err != nil {
		// GNU/cronie crontab exits non-zero with "no crontab for <user>"
		// the first time — an empty crontab, not a failure.
		if strings.Contains(out, "no crontab for") {
			return "", nil
		}
		return "", fmt.Errorf("read crontab for %s: %w: %s", user, err, out)
	}
	return out, nil
}

func writeUserCrontab(ctx context.Context, user, content string) error {
	cmd := exec.CommandContext(ctx, "crontab", "-u", user, "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("write crontab for %s: %w: %s", user, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func handleCronList(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["user"].(string)
	if err := validateCronUser(user); err != nil {
		return "", err
	}
	content, err := readUserCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	entries := parseCrontab(content, user)
	if entries == nil {
		entries = []CronEntry{}
	}
	out, _ := json.Marshal(entries)
	return string(out), nil
}

func handleCronCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["user"].(string)
	schedule, _ := params["schedule"].(string)
	command, _ := params["command"].(string)
	label, _ := params["label"].(string)

	if err := validateCronUser(user); err != nil {
		return "", err
	}
	if err := validateSchedule(schedule); err != nil {
		return "", err
	}
	if err := validateCommand(command); err != nil {
		return "", err
	}
	if err := validateLabel(label); err != nil {
		return "", err
	}
	if _, err := run(ctx, "id", "-u", user); err != nil {
		return "", fmt.Errorf("system user %q does not exist on this server", user)
	}

	entry := CronEntry{ID: newCronID(), User: user, Label: label, Schedule: schedule, Command: strings.TrimSpace(command), Enabled: true}

	progress("reading current crontab for " + user)
	content, err := readUserCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	progress("writing cron job " + entry.ID)
	if err := writeUserCrontab(ctx, user, rewriteCrontab(content, entry.ID, &entry)); err != nil {
		return "", err
	}

	out, _ := json.Marshal(entry)
	return string(out), nil
}

func handleCronSetEnabled(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["user"].(string)
	id, _ := params["id"].(string)
	enabled, _ := params["enabled"].(bool)

	if err := validateCronUser(user); err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("id is required")
	}

	content, err := readUserCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	entries := parseCrontab(content, user)
	var found *CronEntry
	for i := range entries {
		if entries[i].ID == id {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		return "", fmt.Errorf("cron job %q not found for user %q", id, user)
	}
	found.Enabled = enabled

	if err := writeUserCrontab(ctx, user, rewriteCrontab(content, id, found)); err != nil {
		return "", err
	}
	out, _ := json.Marshal(*found)
	return string(out), nil
}

func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["user"].(string)
	id, _ := params["id"].(string)

	if err := validateCronUser(user); err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("id is required")
	}

	content, err := readUserCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	if err := writeUserCrontab(ctx, user, rewriteCrontab(content, id, nil)); err != nil {
		return "", err
	}
	return fmt.Sprintf("cron job %q deleted for user %q", id, user), nil
}
