package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// cronDir is where per-site-user managed cron files live — one file per
// system user under /etc/cron.d, containing only entries this control
// plane created. This is a var (not const) so tests can point it at a temp
// directory instead of the real system path.
var cronDir = "/etc/cron.d"

// cronIDRe constrains cron job IDs (assigned by the control plane — see
// apps/controlplane/store.go randID — and passed down as an opaque
// string) to a charset safe to embed in a cron.d comment marker.
var cronIDRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// cronFieldRe allow-lists each of the five schedule fields to digits and
// the standard */,- operators. Day/month names (MON, JAN, ...) are
// deliberately not supported — this keeps the validator simple and, more
// importantly, keeps every accepted character safe to write directly into
// a single cron.d line with no risk of it being (or containing) a second
// line, a comment terminator, or shell-meaningful syntax.
var cronFieldRe = regexp.MustCompile(`^[0-9*/,-]+$`)

// cronEntry is both the agent's internal representation of one managed
// cron.d entry and the JSON shape returned to the control plane by
// cron.create/cron.list.
type cronEntry struct {
	ID       string `json:"id"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Enabled  bool   `json:"enabled"`
}

// validateCronSchedule requires exactly five fields (minute hour
// day-of-month month day-of-week), each restricted to cronFieldRe.
func validateCronSchedule(schedule string) error {
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return fmt.Errorf("schedule must have exactly 5 fields (minute hour day-of-month month day-of-week), got %d", len(fields))
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return fmt.Errorf("invalid schedule field %q: only digits and * / , - are allowed (day/month names are not supported)", f)
		}
	}
	return nil
}

func validateCronCommand(command string) error {
	if command == "" {
		return fmt.Errorf("command is required")
	}
	if strings.ContainsAny(command, "\n\r") {
		return fmt.Errorf("command must not contain newlines")
	}
	if len(command) > 2000 {
		return fmt.Errorf("command is too long (max 2000 characters)")
	}
	return nil
}

func cronFilePath(sysUser string) string {
	return filepath.Join(cronDir, "serverpanel-"+sysUser)
}

// readCronEntries parses a managed cron.d file back into entries. Every
// line this package ever writes comes as a fixed
// "# sp-cron:<id> enabled|disabled" header line followed by exactly one
// body line ("<schedule> <user> <command>", optionally "#"-commented when
// disabled) — so parsing only ever has to understand this package's own
// output, never arbitrary hand-edited cron.d syntax. A missing file (no
// managed crons yet) is not an error.
func readCronEntries(sysUser string) ([]cronEntry, error) {
	data, err := os.ReadFile(cronFilePath(sysUser))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var entries []cronEntry
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		header, ok := strings.CutPrefix(lines[i], "# sp-cron:")
		if !ok {
			continue
		}
		parts := strings.Fields(header)
		if len(parts) != 2 || i+1 >= len(lines) {
			continue
		}
		id, state := parts[0], parts[1]

		body := strings.TrimPrefix(lines[i+1], "#")
		fields := strings.Fields(body)
		if len(fields) < 7 {
			continue
		}
		schedule := strings.Join(fields[0:5], " ")
		// fields[5] is always sysUser (the run-as column cron.d requires);
		// the command is everything in the body after that token.
		cmdStart := strings.Index(body, fields[5]) + len(fields[5])
		command := strings.TrimSpace(body[cmdStart:])

		entries = append(entries, cronEntry{ID: id, Schedule: schedule, Command: command, Enabled: state == "enabled"})
		i++ // skip the body line we just consumed
	}
	return entries, nil
}

// writeCronEntries atomically rewrites a system user's entire managed
// cron.d file from entries. Because cronFilePath's file is the only place
// this package ever writes under cronDir, and only this function ever
// writes it, a full rewrite on every change is safe — there is never
// unmanaged content in the file that a partial edit would need to
// preserve. An empty entries list removes the file entirely rather than
// leaving an empty one behind.
func writeCronEntries(sysUser string, entries []cronEntry) error {
	path := cronFilePath(sysUser)
	if len(entries) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	var b strings.Builder
	b.WriteString("# Managed by ServerPanel for system user " + sysUser + ". Do not edit by hand;\n")
	b.WriteString("# changes made through the dashboard regenerate this file.\n")
	for _, e := range entries {
		state, prefix := "enabled", ""
		if !e.Enabled {
			state, prefix = "disabled", "#"
		}
		fmt.Fprintf(&b, "# sp-cron:%s %s\n", e.ID, state)
		fmt.Fprintf(&b, "%s%s %s %s\n", prefix, e.Schedule, sysUser, e.Command)
	}

	if err := os.MkdirAll(cronDir, 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func handleCronCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	id, _ := params["id"].(string)
	schedule, _ := params["schedule"].(string)
	command, _ := params["command"].(string)

	if err := validateSiteSystemUser(sysUser); err != nil {
		return "", err
	}
	if !cronIDRe.MatchString(id) {
		return "", fmt.Errorf("invalid cron id %q", id)
	}
	if err := validateCronSchedule(schedule); err != nil {
		return "", err
	}
	if err := validateCronCommand(command); err != nil {
		return "", err
	}
	if _, err := run(ctx, "id", "-u", sysUser); err != nil {
		return "", fmt.Errorf("system_user %q does not exist on this server", sysUser)
	}

	entries, err := readCronEntries(sysUser)
	if err != nil {
		return "", fmt.Errorf("read existing cron entries: %w", err)
	}
	for _, e := range entries {
		if e.ID == id {
			return "", fmt.Errorf("cron id %q already exists", id)
		}
	}
	entry := cronEntry{ID: id, Schedule: schedule, Command: command, Enabled: true}
	entries = append(entries, entry)

	progress("writing cron entry for " + sysUser)
	if err := writeCronEntries(sysUser, entries); err != nil {
		return "", fmt.Errorf("write cron file: %w", err)
	}

	out, _ := json.Marshal(entry)
	return string(out), nil
}

func handleCronList(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	if err := validateSiteSystemUser(sysUser); err != nil {
		return "", err
	}
	entries, err := readCronEntries(sysUser)
	if err != nil {
		return "", fmt.Errorf("read cron entries: %w", err)
	}
	out, _ := json.Marshal(entries)
	return string(out), nil
}

func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	id, _ := params["id"].(string)
	if err := validateSiteSystemUser(sysUser); err != nil {
		return "", err
	}
	if !cronIDRe.MatchString(id) {
		return "", fmt.Errorf("invalid cron id %q", id)
	}

	entries, err := readCronEntries(sysUser)
	if err != nil {
		return "", fmt.Errorf("read cron entries: %w", err)
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
		return "", fmt.Errorf("cron id %q not found", id)
	}
	if err := writeCronEntries(sysUser, kept); err != nil {
		return "", fmt.Errorf("write cron file: %w", err)
	}
	return fmt.Sprintf("cron %q deleted", id), nil
}

func handleCronSetEnabled(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	id, _ := params["id"].(string)
	enabled, _ := params["enabled"].(bool)
	if err := validateSiteSystemUser(sysUser); err != nil {
		return "", err
	}
	if !cronIDRe.MatchString(id) {
		return "", fmt.Errorf("invalid cron id %q", id)
	}

	entries, err := readCronEntries(sysUser)
	if err != nil {
		return "", fmt.Errorf("read cron entries: %w", err)
	}
	found := false
	for i := range entries {
		if entries[i].ID == id {
			entries[i].Enabled = enabled
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("cron id %q not found", id)
	}
	if err := writeCronEntries(sysUser, entries); err != nil {
		return "", fmt.Errorf("write cron file: %w", err)
	}

	state := "disabled"
	if enabled {
		state = "enabled"
	}
	return fmt.Sprintf("cron %q %s", id, state), nil
}
