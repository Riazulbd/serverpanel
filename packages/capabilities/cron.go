package capabilities

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// cronDDir is where the agent writes one managed drop-in file per system
// user (/etc/cron.d/serverpanel-<user>) — vars, not consts, so tests can
// redirect both into a temp directory instead of touching the real system
// cron.
var cronDDir = "/etc/cron.d"
var cronMetaDir = "/etc/serverpanel/cron"

// cronUserRe matches the same POSIX-username shape systemUserForDomain
// produces (and any other unix account this agent might be asked to
// schedule for). It exists independently of identifierRe/domainRe because
// it allows a leading underscore and hyphens, which those don't.
var cronUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// cronFieldRe is the allow-list charset for one field of a 5-field cron
// expression. It deliberately excludes anything that could change the
// meaning of the line it's placed on (spaces, quotes, '#', '%', shell
// metacharacters) — a malformed field is rejected outright rather than
// sanitized, since silently rewriting a schedule the caller didn't type
// would be worse than refusing it.
var cronFieldRe = regexp.MustCompile(`^[0-9A-Za-z*,/-]+$`)

var cronNicknameRe = regexp.MustCompile(`^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)$`)

// cronJob is both the JSON shape persisted to cronMetaDir/<user>.json (the
// durable source of truth for what this user's managed schedule contains)
// and what cron.create/cron.list return as their TaskEvent detail.
type cronJob struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Schedule  string    `json:"schedule"`
	Command   string    `json:"command"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// validateCronUser rejects anything that isn't both a syntactically valid
// unix username and (when `id` is available) an account that actually
// exists on this host — the same "don't trust the caller's string, verify
// it locally" posture handleBackupRestore takes with archive paths. The
// control plane is expected to only ever pass a site's own system_user
// (see apps/controlplane/cron.go), but the agent never assumes that.
func validateCronUser(user string) error {
	if !cronUserRe.MatchString(user) {
		return fmt.Errorf("invalid system_user %q", user)
	}
	if _, err := exec.LookPath("id"); err == nil {
		if err := exec.Command("id", "-u", user).Run(); err != nil {
			return fmt.Errorf("system user %q does not exist on this server", user)
		}
	}
	return nil
}

func validateCronSchedule(schedule string) error {
	schedule = strings.TrimSpace(schedule)
	if schedule == "" {
		return fmt.Errorf("schedule is required")
	}
	if cronNicknameRe.MatchString(schedule) {
		return nil
	}
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return fmt.Errorf("schedule must have exactly 5 fields (minute hour day-of-month month day-of-week), or be a nickname like @daily")
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return fmt.Errorf("invalid schedule field %q", f)
		}
	}
	return nil
}

// validateCronCommand rejects a command that could corrupt the cron.d file
// it's about to be written into (a raw newline would silently become a
// second, uncontrolled cron line) and escapes '%', which cron treats as a
// literal newline inside the command field unless escaped — a well-known
// footgun that would otherwise truncate any command containing one (e.g. a
// date format string or URL-encoded value) without any error surfaced
// anywhere.
func validateCronCommand(cmd string) (string, error) {
	if strings.TrimSpace(cmd) == "" {
		return "", fmt.Errorf("command is required")
	}
	if strings.ContainsAny(cmd, "\n\r\x00") {
		return "", fmt.Errorf("command must not contain newlines or null bytes")
	}
	if len(cmd) > 4096 {
		return "", fmt.Errorf("command too long (max 4096 bytes)")
	}
	return strings.ReplaceAll(cmd, "%", `\%`), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is effectively unrecoverable for this host;
		// fall back to a timestamp so callers still get a non-empty,
		// collision-unlikely-enough id rather than a panic.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func cronMetaPath(user string) string { return filepath.Join(cronMetaDir, user+".json") }
func cronDPath(user string) string    { return filepath.Join(cronDDir, "serverpanel-"+user) }

func loadCronJobs(user string) ([]cronJob, error) {
	data, err := os.ReadFile(cronMetaPath(user))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var jobs []cronJob
	if err := json.Unmarshal(data, &jobs); err != nil {
		return nil, fmt.Errorf("corrupt cron metadata for %q: %w", user, err)
	}
	return jobs, nil
}

// saveCronJobs and writeCronDFile both write-to-temp-then-rename, so a
// crash or concurrent read mid-write can never observe a half-written
// metadata file or, worse, a half-written /etc/cron.d entry that cron
// itself might try to parse.
func saveCronJobs(user string, jobs []cronJob) error {
	if err := os.MkdirAll(cronMetaDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(jobs, "", "  ")
	if err != nil {
		return err
	}
	tmp := cronMetaPath(user) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, cronMetaPath(user))
}

// writeCronDFile regenerates /etc/cron.d/serverpanel-<user> from jobs in
// full, every time. Only enabled jobs are written — "disabled" has to mean
// "cron will not run this," not just a flag nothing enforces, so a disabled
// entry is simply absent from the file cron actually reads while remaining
// visible (and re-enable-able) in the metadata JSON.
func writeCronDFile(user string, jobs []cronJob) error {
	if err := os.MkdirAll(cronDDir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Managed by ServerPanel — do not edit by hand, changes will be overwritten.\n")
	b.WriteString("SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
	for _, j := range jobs {
		if !j.Enabled {
			continue
		}
		fmt.Fprintf(&b, "%s %s %s\n", j.Schedule, user, j.Command)
	}
	path := cronDPath(user)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func handleCronList(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["system_user"].(string)
	if err := validateCronUser(user); err != nil {
		return "", err
	}
	jobs, err := loadCronJobs(user)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(jobs)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func handleCronCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["system_user"].(string)
	schedule, _ := params["schedule"].(string)
	rawCmd, _ := params["command"].(string)
	label, _ := params["label"].(string)

	if err := validateCronUser(user); err != nil {
		return "", err
	}
	if err := validateCronSchedule(schedule); err != nil {
		return "", err
	}
	cmd, err := validateCronCommand(rawCmd)
	if err != nil {
		return "", err
	}
	if len(label) > 200 {
		return "", fmt.Errorf("label too long (max 200 characters)")
	}

	jobs, err := loadCronJobs(user)
	if err != nil {
		return "", err
	}
	// A bounded per-user limit, not because 100 is a magic product number,
	// but so a compromised or scripted caller can't grow an unbounded
	// metadata file / cron.d file on this host.
	if len(jobs) >= 100 {
		return "", fmt.Errorf("cron job limit reached for user %q (max 100)", user)
	}

	job := cronJob{
		ID:        randHex(12),
		Label:     label,
		Schedule:  strings.TrimSpace(schedule),
		Command:   cmd,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	jobs = append(jobs, job)

	if err := saveCronJobs(user, jobs); err != nil {
		return "", err
	}
	if err := writeCronDFile(user, jobs); err != nil {
		return "", err
	}
	progress(fmt.Sprintf("cron job %s scheduled for user %s", job.ID, user))

	out, err := json.Marshal(job)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func handleCronDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["system_user"].(string)
	id, _ := params["cron_id"].(string)
	if err := validateCronUser(user); err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("cron_id is required")
	}

	jobs, err := loadCronJobs(user)
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
		return "", fmt.Errorf("cron job %q not found for user %q", id, user)
	}

	if err := saveCronJobs(user, kept); err != nil {
		return "", err
	}
	if err := writeCronDFile(user, kept); err != nil {
		return "", err
	}
	return fmt.Sprintf("cron job %q deleted", id), nil
}

func handleCronSetEnabled(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	user, _ := params["system_user"].(string)
	id, _ := params["cron_id"].(string)
	enabled, _ := params["enabled"].(bool)
	if err := validateCronUser(user); err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("cron_id is required")
	}

	jobs, err := loadCronJobs(user)
	if err != nil {
		return "", err
	}
	found := false
	for i := range jobs {
		if jobs[i].ID == id {
			jobs[i].Enabled = enabled
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("cron job %q not found for user %q", id, user)
	}

	if err := saveCronJobs(user, jobs); err != nil {
		return "", err
	}
	if err := writeCronDFile(user, jobs); err != nil {
		return "", err
	}
	state := "disabled"
	if enabled {
		state = "enabled"
	}
	return fmt.Sprintf("cron job %q %s", id, state), nil
}
