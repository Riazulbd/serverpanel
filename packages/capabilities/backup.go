package capabilities

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const backupBaseDir = "/var/backups/serverpanel"

type backupResult struct {
	Scope     string    `json:"scope"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

type restoreResult struct {
	Scope          string    `json:"scope"`
	RestoredFrom   string    `json:"restored_from"`
	CheckpointPath string    `json:"checkpoint_path,omitempty"`
	RestoredAt     time.Time `json:"restored_at"`
}

// createBackupArchive is the core of backup.run, factored out on its own so
// backup.restore can also call it — to take a pre-restore checkpoint of
// whatever currently exists before mutating anything. A "restore" capability
// that can itself leave the system unrecoverable on a bad or wrong archive
// would fail the product's "pre-restore checkpoint" requirement, so restore
// never proceeds without first trying to snapshot current state the same
// way an on-demand backup would.
func createBackupArchive(ctx context.Context, scope, siteRoot, dbName string, progress Progress) (backupResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if scope != "db" && scope != "files" && scope != "full" {
		return backupResult{}, fmt.Errorf("scope must be one of db, files, full")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return backupResult{}, fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return backupResult{}, fmt.Errorf("invalid db_name %q", dbName)
	}

	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return backupResult{}, fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	label := dbName
	if label == "" {
		label = filepath.Base(siteRoot)
	}
	// A second-granularity timestamp alone is not a unique filename: two
	// backups of the same site/scope within the same second — which
	// handleBackupRestore's own pre-restore checkpoint can easily trigger,
	// running seconds (or less) after the backup it's about to restore —
	// would collide and silently overwrite the very archive being restored
	// from with a fresh checkpoint of already-corrupted state. Caught by
	// TestBackupRunAndRestoreFilesRoundTrip; the random suffix makes every
	// archive path unique regardless of timing.
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return backupResult{}, fmt.Errorf("generate archive suffix: %w", err)
	}
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s-%s.tar.gz", label, scope, stamp, hex.EncodeToString(suffix)))

	workDir, err := os.MkdirTemp("", "sp-backup-*")
	if err != nil {
		return backupResult{}, err
	}
	defer os.RemoveAll(workDir)

	var tarInputs []string

	if scope == "db" || scope == "full" {
		progress("dumping database " + dbName)
		dumpPath := filepath.Join(workDir, dbName+".sql")
		out, err := run(ctx, "mysqldump", "--single-transaction", "--routines", "--events", dbName)
		if err != nil {
			return backupResult{}, fmt.Errorf("mysqldump: %w: %s", err, out)
		}
		if err := os.WriteFile(dumpPath, []byte(out), 0600); err != nil {
			return backupResult{}, fmt.Errorf("write dump: %w", err)
		}
		tarInputs = append(tarInputs, dumpPath)
	}

	if scope == "files" || scope == "full" {
		progress("archiving files from " + siteRoot)
		tarInputs = append(tarInputs, siteRoot)
	}

	progress("compressing archive")
	// tar is run with an explicit -C for the db-dump input (staged under
	// workDir, so it lands in the archive as "<db>.sql" with no path
	// prefix) but siteRoot is passed as-is, which is what lets
	// backup.restore later extract it straight back to its original
	// absolute location.
	args := []string{"-czf", outPath}
	for _, in := range tarInputs {
		if strings.HasPrefix(in, workDir) {
			args = append(args, "-C", workDir, filepath.Base(in))
		} else {
			args = append(args, in)
		}
	}
	if out, err := run(ctx, "tar", args...); err != nil {
		return backupResult{}, fmt.Errorf("tar: %w: %s", err, out)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return backupResult{}, fmt.Errorf("stat backup archive: %w", err)
	}
	sum, err := sha256File(outPath)
	if err != nil {
		return backupResult{}, fmt.Errorf("checksum backup archive: %w", err)
	}

	return backupResult{Scope: scope, Path: outPath, SizeBytes: info.Size(), SHA256: sum, CreatedAt: time.Now().UTC()}, nil
}

// handleBackupRun creates a local, checksummed backup archive. It never
// shells out to a recursive-delete anything — this capability only ever
// creates files under backupBaseDir; cleanup of old backups is a separate,
// explicitly-scoped capability (not implemented in this skeleton) rather
// than folded in here, matching "never implement disk cleanup as an
// unrestricted recursive deletion command" from docs/product-plan.md.
func handleBackupRun(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)

	res, err := createBackupArchive(ctx, scope, siteRoot, dbName, progress)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// resolveBackupArchivePath maps a caller-supplied backup path onto a real
// filesystem path guaranteed to stay inside backupBaseDir, the same
// symlink-safe defense used by resolveScopedPath for the file manager —
// restore must never be tricked into reading (and then trusting the
// checksum of) a file outside the managed backup directory.
func resolveBackupArchivePath(archivePath string) (string, error) {
	if archivePath == "" {
		return "", fmt.Errorf("archive_path is required")
	}
	realRoot, err := filepath.EvalSymlinks(backupBaseDir)
	if err != nil {
		return "", fmt.Errorf("resolve backup directory: %w", err)
	}

	cleaned := archivePath
	if !filepath.IsAbs(cleaned) {
		cleaned = filepath.Join(backupBaseDir, cleaned)
	}
	cleaned = filepath.Clean(cleaned)
	if cleaned != realRoot && !strings.HasPrefix(cleaned, realRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("archive_path must be inside the managed backup directory")
	}

	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("archive not found: %w", err)
	}
	if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("archive_path (via symlink) escapes the managed backup directory")
	}
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("archive_path does not refer to a regular file")
	}
	return resolved, nil
}

// validateBackupArchiveMembers lists (never extracts blind) an archive's
// contents and rejects anything outside exactly what this restore is scoped
// to. The archive's checksum is verified against the caller-supplied
// expected_sha256 before this runs, but that alone only proves the bytes
// match what was recorded at backup time — this is a second, independent
// check that even a backup created by this same code never contained a
// surprise path, so a restore can never be tricked into writing outside its
// declared scope (e.g. "/etc/passwd") via `tar -xzf ... -C /`.
func validateBackupArchiveMembers(ctx context.Context, archivePath, scope, siteRoot, dbName string) error {
	out, err := run(ctx, "tar", "-tzf", archivePath)
	if err != nil {
		return fmt.Errorf("list archive contents: %w: %s", err, out)
	}
	trimmedRoot := strings.TrimPrefix(filepath.Clean(siteRoot), "/")

	for _, line := range strings.Split(out, "\n") {
		entry := strings.TrimSpace(strings.TrimSuffix(line, "/"))
		if entry == "" {
			continue
		}
		switch {
		case (scope == "db" || scope == "full") && entry == dbName+".sql":
			continue
		case (scope == "files" || scope == "full") && trimmedRoot != "" &&
			(entry == trimmedRoot || strings.HasPrefix(entry, trimmedRoot+"/")):
			continue
		default:
			return fmt.Errorf("backup archive contains unexpected entry %q outside what this restore is scoped to — refusing to restore a possibly corrupted or tampered archive", line)
		}
	}
	return nil
}

// siteSystemUserFromPath recovers the isolated system user that owns a site
// from its path (e.g. "/home/sites/site_example_com/public" ->
// "site_example_com") rather than trusting a separate caller-supplied
// parameter, mirroring the same "derive it, don't trust it" approach
// file.go's handleFileWrite uses for the chown after a write.
func siteSystemUserFromPath(siteRoot string) (string, error) {
	for _, part := range strings.Split(filepath.Clean(siteRoot), string(filepath.Separator)) {
		if strings.HasPrefix(part, "site_") {
			return part, nil
		}
	}
	return "", fmt.Errorf("could not determine the isolated system user that owns %q", siteRoot)
}

// handleBackupRestore restores a previously created backup.run archive.
// Safety properties, in order:
//  1. the archive must resolve inside backupBaseDir (resolveBackupArchivePath)
//  2. its SHA-256 must match the caller-supplied expected_sha256 (the value
//     the control plane recorded when the backup was created) — restoring an
//     archive that fails this check is refused outright, never attempted
//  3. every member path inside the archive is validated against the
//     declared scope before anything is extracted
//  4. a best-effort pre-restore checkpoint of current state is taken before
//     any mutation, so a bad restore is itself recoverable
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	if progress == nil {
		progress = func(string) {}
	}
	scope, _ := params["scope"].(string)
	archivePath, _ := params["archive_path"].(string)
	expectedSHA, _ := params["expected_sha256"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	if expectedSHA == "" {
		return "", fmt.Errorf("expected_sha256 is required — restoring without checksum verification is not allowed")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}

	realArchive, err := resolveBackupArchivePath(archivePath)
	if err != nil {
		return "", err
	}

	progress("verifying backup archive checksum")
	sum, err := sha256File(realArchive)
	if err != nil {
		return "", fmt.Errorf("checksum archive: %w", err)
	}
	if sum != expectedSHA {
		return "", fmt.Errorf("checksum mismatch: this archive does not match the checksum recorded when it was created — it may be corrupted or modified, refusing to restore")
	}

	progress("validating archive contents before making any changes")
	if err := validateBackupArchiveMembers(ctx, realArchive, scope, siteRoot, dbName); err != nil {
		return "", err
	}

	var checkpoint backupResult
	progress("creating pre-restore checkpoint of current state")
	if cp, cpErr := createBackupArchive(ctx, scope, siteRoot, dbName, progress); cpErr != nil {
		progress(fmt.Sprintf("no pre-restore checkpoint could be taken (%v) — usually means nothing exists yet at the restore target", cpErr))
	} else {
		checkpoint = cp
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	if scope == "db" || scope == "full" {
		progress("extracting database dump")
		if out, err := run(ctx, "tar", "-xzf", realArchive, "-C", workDir, dbName+".sql"); err != nil {
			return "", fmt.Errorf("extract db dump: %w: %s", err, out)
		}
		sqlPath := filepath.Join(workDir, dbName+".sql")
		f, err := os.Open(sqlPath)
		if err != nil {
			return "", fmt.Errorf("open extracted dump: %w", err)
		}
		defer f.Close()

		progress("importing database " + dbName)
		cmd := exec.CommandContext(ctx, "mysql", dbName)
		cmd.Stdin = f
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("mysql import: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}

	if scope == "files" || scope == "full" {
		sysUser, err := siteSystemUserFromPath(siteRoot)
		if err != nil {
			return "", err
		}
		trimmedRoot := strings.TrimPrefix(filepath.Clean(siteRoot), "/")

		progress("extracting files into " + siteRoot)
		if out, err := run(ctx, "tar", "-xzf", realArchive, "-C", "/", trimmedRoot); err != nil {
			return "", fmt.Errorf("extract files: %w: %s", err, out)
		}
		if out, err := run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot); err != nil {
			return "", fmt.Errorf("restore ownership: %w: %s", err, out)
		}
	}

	res := restoreResult{Scope: scope, RestoredFrom: realArchive, RestoredAt: time.Now().UTC()}
	if checkpoint.Path != "" {
		res.CheckpointPath = checkpoint.Path
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
