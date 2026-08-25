package capabilities

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Cron jobs are managed by editing the target system user's real crontab
// through the standard `crontab -u <user> -l` / `crontab -u <user> -`
// commands — there is no separate scheduler daemon and no direct write to
// /var/spool/cron. Every entry this package creates is tagged with a machine-
// readable marker comment on the line immediately above it:
//
//	# serverpanel-cron id=cron_ab12cd34 enabled=true label=Nightly backup
//	*/15 * * * * /usr/bin/php /home/sites/site_x/artisan schedule:run
//
// A disabled entry keeps the exact same two lines except the schedule/command
// line is prefixed with "#" (a plain crontab comment, so cron never runs it)
// — history and the exact command are preserved rather than deleted, which is
// what makes re-enabling lossless. Any other line already present in a user's
// crontab (something added by hand, or by anything other than this control
// plane) is round-tripped byte-for-byte and never touched.
//
// system_user is always the site's own isolated system user (see site.go) —
// callers never get to name an arbitrary username here; see cron.go's use in
// apps/controlplane/cron.go, which derives it from the stored site record
// rather than accepting it from client input. validateManagedSystemUser below
// is defense in depth (format + existence check), not the ownership boundary
// itself.

// cronEntry is one managed crontab entry, as exposed to the control plane
// (and, from there, the dashboard) in cron.list/create/update/set_enabled's
// JSON result.
type cronEntry struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Enabled  bool   `json:"enabled"`
}

// cronSegment is one line-group of a parsed crontab document: either a
// managed entry (marker + schedule/command line, collapsed into one
// cronEntry) or a single verbatim line this package doesn't understand and
// must preserve exactly as-is on the next write.
type cronSegment struct {
	raw   string
	entry *cronEntry
}

// CronPresets maps a friendly preset name to its standard 5-field cron
// expression. The dashboard offers these as one-click schedule choices in
// addition to a free-form custom expression; either way, the resulting
// expression is validated identically by validateCronSchedule before it's
// ever written to a crontab.
var CronPresets = map[string]string{
	"every_minute": "* * * * *",
	"hourly":       "0 * * * *",
	"daily":        "0 0 * * *",
	"weekly":       "0 0 * * 0",
	"monthly":      "0 0 1 * *",
}

var cronMarkerRe = regexp.MustCompile(`^# serverpanel-cron id=([A-Za-z0-9_]+) enabled=(true|false) label=(.*)$`)

// cronFieldSpec is the valid value range for one of the five standard cron
// fields, used to bound-check literal values and range/step endpoints.
type cronFieldSpec struct {
	name     string
	min, max int
}

var cronFields = [5]cronFieldSpec{
	{"minute", 0, 59},
	{"hour", 0, 23},
	{"day of month", 1, 31},
	{"month", 1, 12},
	{"day of week", 0, 7}, // both 0 and 7 mean Sunday
}

// cronSegmentValueRe matches one comma-separated segment of a single cron
// field: a bare "*", a number, or a range "N-N", any of those optionally
// followed by a "/step". Anything else (names, extra punctuation, embedded
// whitespace) is rejected outright rather than guessed at.
var cronSegmentValueRe = regexp.MustCompile(`^(\*|[0-9]+(?:-[0-9]+)?)(/[0-9]+)?$`)

// validateCronSchedule rejects anything that isn't a well-formed standard
// 5-field cron expression with every literal value in range for its field.
func validateCronSchedule(expr string) error {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("cron schedule must have exactly 5 space-separated fields (minute hour day-of-month month day-of-week), got %d in %q", len(fields), expr)
	}
	for i, field := range fields {
		spec := cronFields[i]
		for _, segment := range strings.Split(field, ",") {
			if segment == "" {
				return fmt.Errorf("%s field: empty list segment in %q", spec.name, field)
			}
			m := cronSegmentValueRe.FindStringSubmatch(segment)
			if m == nil {
				return fmt.Errorf("%s field: invalid value %q", spec.name, segment)
			}
			base := m[1]
			if base != "*" {
				parts := strings.SplitN(base, "-", 2)
				var lo, hi int
				for i, p := range parts {
					n, err := strconv.Atoi(p)
					if err != nil || n < spec.min || n > spec.max {
						return fmt.Errorf("%s field: value %q out of range %d-%d", spec.name, p, spec.min, spec.max)
					}
					if i == 0 {
						lo = n
					} else {
						hi = n
					}
				}
				if len(parts) == 2 && lo > hi {
					return fmt.Errorf("%s field: range %q has a start greater than its end", spec.name, base)
				}
			}
			if step := m[2]; step != "" {
				n, err := strconv.Atoi(strings.TrimPrefix(step, "/"))
				if err != nil || n <= 0 {
					return fmt.Errorf("%s field: invalid step %q", spec.name, step)
				}
			}
		}
	}
	return nil
}

// cronLineBreakingRe matches the characters that would let a caller-supplied
// command or label field break out of its single crontab line and smuggle in
// an entirely new, arbitrarily-scheduled crontab entry: a real newline or
// carriage return ends the current line early, and a NUL byte can truncate
// how downstream tools (including crontab itself) interpret the rest of the
// buffer. This is deliberately not a shell-metacharacter blocklist — a cron
// "command" is always handed to the user's shell by cron itself (via
// `SHELL -c "command"`), so ';', '|', '&&', backticks, etc. are normal,
// expected cron usage, not an injection vector; the injection surface unique
// to a *cron* field is the crontab file's own line-based syntax, not the
// shell that eventually runs the command.
var cronLineBreakingRe = regexp.MustCompile(`[\x00\r\n]`)

const maxCronCommandLen = 1000
const maxCronLabelLen = 200

// validateCronCommand guards the one field that both must remain a valid
// shell command (untouched) and must not be able to inject additional
// crontab structure.
func validateCronCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("command is required")
	}
	if len(command) > maxCronCommandLen {
		return fmt.Errorf("command must be %d characters or fewer", maxCronCommandLen)
	}
	if cronLineBreakingRe.MatchString(command) {
		return fmt.Errorf("command must not contain newlines, carriage returns, or NUL bytes")
	}
	// cron itself treats an unescaped '%' in a crontab command as a literal
	// newline (everything after it becomes the job's stdin) — a second,
	// cron-specific way a caller-supplied string could inject content the
	// crontab format wasn't meant to receive from this field. Rejected
	// outright rather than silently reinterpreted; a caller who genuinely
	// needs a literal '%' can pre-escape it as '\%', which cron itself
	// already treats as a literal percent sign.
	for i := 0; i < len(command); i++ {
		if command[i] == '%' && (i == 0 || command[i-1] != '\\') {
			return fmt.Errorf(`command must not contain an unescaped '%%' (cron treats it as a literal newline) — escape it as '\%%' for a literal percent sign`)
		}
	}
	return nil
}

func validateCronLabel(label string) error {
	if len(label) > maxCronLabelLen {
		return fmt.Errorf("label must be %d characters or fewer", maxCronLabelLen)
	}
	if cronLineBreakingRe.MatchString(label) {
		return fmt.Errorf("label must not contain newlines, carriage returns, or NUL bytes")
	}
	return nil
}

// validateManagedSystemUser checks that system_user is present, shaped like
// a system user this control plane itself would have created (the same
// "site_" prefix convention site.go's other handlers already require), and
// actually exists on this host. This is defense in depth only: the real
// ownership boundary — that the caller is allowed to touch *this particular*
// user's crontab at all — is enforced one layer up, by the control plane
// deriving system_user from the stored site record for the server+site the
// caller's session actually has a request in flight for, never from
// unauthenticated client input (see apps/controlplane/cron.go).
func validateManagedSystemUser(ctx context.Context, params map[string]any) (string, error) {
	user, _ := params["system_user"].(string)
	if user == "" || !strings.HasPrefix(user, "site_") {
		return "", fmt.Errorf("invalid system_user")
	}
	if _, err := run(ctx, "id", "-u", user); err != nil {
		return "", fmt.Errorf("system user %q does not exist on this server", user)
	}
	return user, nil
}

// splitScheduleAndCommand splits one crontab body line (with any leading
// "#" already stripped) into its 5-field schedule prefix and the remaining
// command text, preserving the command's original internal whitespace
// exactly (only the single separator between the 5th field and the command
// is consumed) — collapsing runs of whitespace the way strings.Fields would
// could otherwise silently corrupt a command containing, say, a quoted
// argument with deliberate multiple spaces.
func splitScheduleAndCommand(line string) (schedule, command string, ok bool) {
	i, n := 0, len(line)
	fieldsFound := 0
	end := 0
	for fieldsFound < 5 {
		for i < n && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		start := i
		for i < n && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		if start == i {
			return "", "", false
		}
		fieldsFound++
		end = i
	}
	schedule = strings.Join(strings.Fields(line[:end]), " ")
	command = strings.TrimLeft(line[end:], " \t")
	if command == "" {
		return "", "", false
	}
	return schedule, command, true
}

// parseCrontab turns raw crontab -l output into an ordered list of segments.
// Every line that isn't part of a recognizable serverpanel-managed marker +
// schedule/command pair is preserved verbatim as a raw segment, so a
// create/update/delete/enable/disable round trip never loses content this
// control plane didn't itself write.
func parseCrontab(content string) []cronSegment {
	content = strings.TrimRight(content, "\n")
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	segs := make([]cronSegment, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if m := cronMarkerRe.FindStringSubmatch(line); m != nil && i+1 < len(lines) {
			body := strings.TrimPrefix(lines[i+1], "#")
			if schedule, command, ok := splitScheduleAndCommand(body); ok {
				segs = append(segs, cronSegment{entry: &cronEntry{
					ID: m[1], Enabled: m[2] == "true", Label: m[3],
					Schedule: schedule, Command: command,
				}})
				i++ // the schedule/command line was consumed as part of this entry
				continue
			}
		}
		segs = append(segs, cronSegment{raw: line})
	}
	return segs
}

// renderCrontab is parseCrontab's inverse: it serializes segments back into
// crontab text, re-generating the marker + schedule/command lines for every
// managed entry (with a "#" schedule/command prefix exactly when the entry
// is disabled) and writing every raw segment back byte-for-byte.
func renderCrontab(segs []cronSegment) string {
	var b strings.Builder
	for _, s := range segs {
		if s.entry != nil {
			e := s.entry
			fmt.Fprintf(&b, "# serverpanel-cron id=%s enabled=%t label=%s\n", e.ID, e.Enabled, e.Label)
			if e.Enabled {
				fmt.Fprintf(&b, "%s %s\n", e.Schedule, e.Command)
			} else {
				fmt.Fprintf(&b, "#%s %s\n", e.Schedule, e.Command)
			}
			continue
		}
		b.WriteString(s.raw)
		b.WriteString("\n")
	}
	return b.String()
}

func cronEntriesOf(segs []cronSegment) []cronEntry {
	entries := []cronEntry{}
	for _, s := range segs {
		if s.entry != nil {
			entries = append(entries, *s.entry)
		}
	}
	return entries
}

func cronFindEntry(segs []cronSegment, id string) *cronEntry {
	for _, s := range segs {
		if s.entry != nil && s.entry.ID == id {
			return s.entry
		}
	}
	return nil
}

func cronFindIndex(segs []cronSegment, id string) int {
	for i, s := range segs {
		if s.entry != nil && s.entry.ID == id {
			return i
		}
	}
	return -1
}

// cronUpdateEntry replaces an existing entry's editable fields (schedule,
// command, label) in place, leaving its position and enabled state
// untouched — toggling enabled is a separate operation (cronSetEnabled),
// matching the dashboard's edit-fields vs. flip-a-switch split.
func cronUpdateEntry(segs []cronSegment, id, schedule, command, label string) ([]cronSegment, error) {
	i := cronFindIndex(segs, id)
	if i < 0 {
		return nil, fmt.Errorf("cron entry %q not found", id)
	}
	out := append([]cronSegment(nil), segs...)
	updated := *out[i].entry
	updated.Schedule, updated.Command, updated.Label = schedule, command, label
	out[i] = cronSegment{entry: &updated}
	return out, nil
}

func cronDeleteEntry(segs []cronSegment, id string) ([]cronSegment, error) {
	i := cronFindIndex(segs, id)
	if i < 0 {
		return nil, fmt.Errorf("cron entry %q not found", id)
	}
	out := append([]cronSegment(nil), segs[:i]...)
	return append(out, segs[i+1:]...), nil
}

func cronSetEnabled(segs []cronSegment, id string, enabled bool) ([]cronSegment, error) {
	i := cronFindIndex(segs, id)
	if i < 0 {
		return nil, fmt.Errorf("cron entry %q not found", id)
	}
	out := append([]cronSegment(nil), segs...)
	updated := *out[i].entry
	updated.Enabled = enabled
	out[i] = cronSegment{entry: &updated}
	return out, nil
}

func newCronID() (string, error) {
	buf := make([]byte, 8)
	if _, err := crand.Read(buf); err != nil {
		return "", err
	}
	return "cron_" + hex.EncodeToString(buf), nil
}

func readCrontab(ctx context.Context, user string) (string, error) {
	out, err := run(ctx, "crontab", "-u", user, "-l")
	if err != nil {
		if strings.Contains(strings.ToLower(out), "no crontab for") {
			return "", nil
		}
		return "", fmt.Errorf("crontab -u %s -l: %w: %s", user, err, out)
	}
	return out, nil
}

func writeCrontab(ctx context.Context, user, content string) error {
	out, err := runWithStdin(ctx, content, "crontab", "-u", user, "-")
	if err != nil {
		return fmt.Errorf("crontab -u %s -: %w: %s", user, err, out)
	}
	return nil
}

func handleCronList(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, err := validateManagedSystemUser(ctx, params)
	if err != nil {
		return "", err
	}
	content, err := readCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(cronEntriesOf(parseCrontab(content)))
	return string(out), nil
}

func handleCronCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, err := validateManagedSystemUser(ctx, params)
	if err != nil {
		return "", err
	}
	schedule, _ := params["schedule"].(string)
	command, _ := params["command"].(string)
	label, _ := params["label"].(string)

	enabled := true
	if v, present := params["enabled"]; present {
		b, ok := v.(bool)
		if !ok {
			return "", fmt.Errorf("enabled must be a boolean")
		}
		enabled = b
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

	id, err := newCronID()
	if err != nil {
		return "", fmt.Errorf("generate cron entry id: %w", err)
	}

	progress("reading current crontab for " + user)
	content, err := readCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	entry := cronEntry{ID: id, Label: label, Schedule: schedule, Command: command, Enabled: enabled}
	segs := append(parseCrontab(content), cronSegment{entry: &entry})

	progress("writing crontab for " + user)
	if err := writeCrontab(ctx, user, renderCrontab(segs)); err != nil {
		return "", err
	}

	out, _ := json.Marshal(entry)
	return string(out), nil
}

func handleCronUpdate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, err := validateManagedSystemUser(ctx, params)
	if err != nil {
		return "", err
	}
	id, _ := params["id"].(string)
	schedule, _ := params["schedule"].(string)
	command, _ := params["command"].(string)
	label, _ := params["label"].(string)
	if id == "" {
		return "", fmt.Errorf("id is required")
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

	content, err := readCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	segs, err := cronUpdateEntry(parseCrontab(content), id, schedule, command, label)
	if err != nil {
		return "", err
	}

	progress("writing crontab for " + user)
	if err := writeCrontab(ctx, user, renderCrontab(segs)); err != nil {
		return "", err
	}

	out, _ := json.Marshal(cronFindEntry(segs, id))
	return string(out), nil
}

func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, err := validateManagedSystemUser(ctx, params)
	if err != nil {
		return "", err
	}
	id, _ := params["id"].(string)
	if id == "" {
		return "", fmt.Errorf("id is required")
	}

	content, err := readCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	segs, err := cronDeleteEntry(parseCrontab(content), id)
	if err != nil {
		return "", err
	}

	progress("writing crontab for " + user)
	if err := writeCrontab(ctx, user, renderCrontab(segs)); err != nil {
		return "", err
	}
	return "cron entry deleted", nil
}

func handleCronSetEnabled(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, err := validateManagedSystemUser(ctx, params)
	if err != nil {
		return "", err
	}
	id, _ := params["id"].(string)
	enabled, ok := params["enabled"].(bool)
	if id == "" || !ok {
		return "", fmt.Errorf("id and a boolean enabled are required")
	}

	content, err := readCrontab(ctx, user)
	if err != nil {
		return "", err
	}
	segs, err := cronSetEnabled(parseCrontab(content), id, enabled)
	if err != nil {
		return "", err
	}

	progress("writing crontab for " + user)
	if err := writeCrontab(ctx, user, renderCrontab(segs)); err != nil {
		return "", err
	}

	out, _ := json.Marshal(cronFindEntry(segs, id))
	return string(out), nil
}
