package capabilities

import (
	"context"
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

// backupManifest is written alongside the dump/files inside every archive
// this package creates, so a later restore never has to guess an archive's
// internal layout (earlier versions of this file tarred the database dump
// from a randomly-named temp path and the site root by its absolute path,
// which made restore unable to reliably locate either without replaying
// backup-time state). Every archive built by runBackup has this fixed,
// scope-independent layout instead:
//
//	manifest.json   (this struct)
//	db.sql          (present iff scope is "db" or "full")
//	files/          (present iff scope is "files" or "full"; mirrors site_root)
type backupManifest struct {
	Scope     string    `json:"scope"`
	DBName    string    `json:"db_name,omitempty"`
	SiteRoot  string    `json:"site_root,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type backupResult struct {
	Scope     string    `json:"scope"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

type restoreResult struct {
	Scope               string    `json:"scope"`
	CheckpointPath      string    `json:"checkpoint_path"`
	CheckpointSHA       string    `json:"checkpoint_sha256"`
	CheckpointSizeBytes int64     `json:"checkpoint_size_bytes"`
	RestoredAt          time.Time `json:"restored_at"`
}

func validateBackupScope(scope, siteRoot, dbName string) error {
	if scope != "db" && scope != "files" && scope != "full" {
		return fmt.Errorf("scope must be one of db, files, full")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return fmt.Errorf("invalid db_name %q", dbName)
	}
	return nil
}

// runBackup builds a checksummed archive under backupBaseDir for the given
// scope. It is the shared implementation behind the backup.run capability
// and behind the pre-restore checkpoint that handleBackupRestore always
// takes before touching the restore target, so both paths build the exact
// same archive format.
func runBackup(ctx context.Context, scope, siteRoot, dbName string, progress Progress) (backupResult, error) {
	if err := validateBackupScope(scope, siteRoot, dbName); err != nil {
		return backupResult{}, err
	}

	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return backupResult{}, fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	label := dbName
	if label == "" {
		label = filepath.Base(siteRoot)
	}
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s.tar.gz", label, scope, stamp))

	workDir, err := os.MkdirTemp("", "sp-backup-*")
	if err != nil {
		return backupResult{}, err
	}
	defer os.RemoveAll(workDir)

	if scope == "db" || scope == "full" {
		progress("dumping database " + dbName)
		out, err := run(ctx, "mysqldump", "--single-transaction", "--routines", "--events", dbName)
		if err != nil {
			return backupResult{}, fmt.Errorf("mysqldump: %w: %s", err, out)
		}
		if err := os.WriteFile(filepath.Join(workDir, "db.sql"), []byte(out), 0600); err != nil {
			return backupResult{}, fmt.Errorf("write dump: %w", err)
		}
	}

	if scope == "files" || scope == "full" {
		progress("archiving files from " + siteRoot)
		filesDir := filepath.Join(workDir, "files")
		if err := os.MkdirAll(filesDir, 0700); err != nil {
			return backupResult{}, fmt.Errorf("create staging dir: %w", err)
		}
		// cp -a preserves permissions/ownership/symlinks; siteRoot has
		// already been validated to be a managed site home directory above.
		if out, err := run(ctx, "cp", "-a", siteRoot+"/.", filesDir); err != nil {
			return backupResult{}, fmt.Errorf("stage files: %w: %s", err, out)
		}
	}

	manifest := backupManifest{Scope: scope, DBName: dbName, SiteRoot: siteRoot, CreatedAt: time.Now().UTC()}
	manifestJSON, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(workDir, "manifest.json"), manifestJSON, 0600); err != nil {
		return backupResult{}, fmt.Errorf("write manifest: %w", err)
	}

	progress("compressing archive")
	if out, err := run(ctx, "tar", "-czf", outPath, "-C", workDir, "."); err != nil {
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

	res, err := runBackup(ctx, scope, siteRoot, dbName, progress)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// resolveBackupArchivePath maps a caller-supplied archive path onto a real
// filesystem path guaranteed to stay inside backupBaseDir, the same
// defense-in-depth pattern resolveScopedPath uses for the file manager: a
// restore request must never be able to point at an arbitrary file on the
// host (e.g. /etc/shadow) by way of a crafted archive_path.
func resolveBackupArchivePath(archivePath string) (string, error) {
	realRoot, err := filepath.EvalSymlinks(backupBaseDir)
	if err != nil {
		return "", fmt.Errorf("resolve backup directory: %w", err)
	}
	cleaned := filepath.Clean(archivePath)
	if cleaned != realRoot && !strings.HasPrefix(cleaned, realRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("archive_path must be inside the managed backup directory")
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("backup archive not found: %w", err)
	}
	if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("archive_path (via symlink) escapes the managed backup directory")
	}
	return resolved, nil
}

// handleBackupRestore restores a previously created archive. Before it
// touches anything at the restore destination, it always takes a fresh
// checkpoint backup of that destination's *current* state via runBackup —
// so a bad restore (wrong archive, corrupted dump, whatever) is itself
// recoverable, matching "before destructive restore: create pre-restore
// checkpoint" from docs/product-plan.md. The checkpoint is taken even if
// the restore below then fails, specifically so a failed restore never
// leaves the operator with less safety than before they tried.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	if progress == nil {
		progress = func(string) {}
	}
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	sysUser, _ := params["system_user"].(string)
	archivePath, _ := params["archive_path"].(string)
	expectedSHA, _ := params["expected_sha256"].(string)

	if err := validateBackupScope(scope, siteRoot, dbName); err != nil {
		return "", err
	}
	if archivePath == "" {
		return "", fmt.Errorf("archive_path is required")
	}
	if (scope == "files" || scope == "full") && (sysUser == "" || !strings.HasPrefix(sysUser, "site_")) {
		return "", fmt.Errorf("invalid system_user")
	}

	resolvedArchive, err := resolveBackupArchivePath(archivePath)
	if err != nil {
		return "", err
	}

	progress("verifying backup archive integrity")
	actualSHA, err := sha256File(resolvedArchive)
	if err != nil {
		return "", fmt.Errorf("checksum backup archive: %w", err)
	}
	if expectedSHA != "" && actualSHA != expectedSHA {
		return "", fmt.Errorf("backup archive checksum mismatch (expected %s, got %s) — refusing to restore a possibly corrupted or tampered archive", expectedSHA, actualSHA)
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-xzf", resolvedArchive, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract archive: %w: %s", err, out)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(workDir, "manifest.json"))
	if err != nil {
		return "", fmt.Errorf("archive is missing manifest.json (not a ServerPanel backup, or corrupted): %w", err)
	}
	var manifest backupManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", fmt.Errorf("archive manifest is unreadable: %w", err)
	}
	if (scope == "db" || scope == "full") && manifest.DBName == "" {
		return "", fmt.Errorf("requested scope %q needs a database dump, but the archive's manifest has none", scope)
	}
	if (scope == "files" || scope == "full") && manifest.SiteRoot == "" {
		return "", fmt.Errorf("requested scope %q needs a files archive, but the archive's manifest has none", scope)
	}

	progress("taking a pre-restore checkpoint of the current state")
	checkpoint, err := runBackup(ctx, scope, siteRoot, dbName, progress)
	if err != nil {
		return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore before touching anything: %w", err)
	}

	if scope == "db" || scope == "full" {
		progress("restoring database " + dbName)
		dumpPath := filepath.Join(workDir, "db.sql")
		if _, err := os.Stat(dumpPath); err != nil {
			return "", fmt.Errorf("restore aborted (checkpoint saved at %s): archive has no db.sql: %w", checkpoint.Path, err)
		}
		if out, err := runWithStdinFile(ctx, dumpPath, "mysql", dbName); err != nil {
			return "", fmt.Errorf("restore aborted after checkpoint %s: mysql import failed: %w: %s", checkpoint.Path, err, out)
		}
	}

	if scope == "files" || scope == "full" {
		progress("restoring files to " + siteRoot)
		filesDir := filepath.Join(workDir, "files")
		if _, err := os.Stat(filesDir); err != nil {
			return "", fmt.Errorf("restore aborted (checkpoint saved at %s): archive has no files/: %w", checkpoint.Path, err)
		}
		if !strings.HasPrefix(siteRoot, "/home/sites/") {
			return "", fmt.Errorf("site_root must be a managed site home directory")
		}
		entries, err := os.ReadDir(siteRoot)
		if err != nil {
			return "", fmt.Errorf("restore aborted (checkpoint saved at %s): cannot read site_root: %w", checkpoint.Path, err)
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(siteRoot, e.Name())); err != nil {
				return "", fmt.Errorf("restore aborted mid-way (checkpoint saved at %s): could not clear existing content: %w", checkpoint.Path, err)
			}
		}
		if out, err := run(ctx, "cp", "-a", filesDir+"/.", siteRoot); err != nil {
			return "", fmt.Errorf("restore aborted mid-way (checkpoint saved at %s): could not copy restored files: %w: %s", checkpoint.Path, err, out)
		}
		if out, err := run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot); err != nil {
			progress(fmt.Sprintf("warning: could not chown restored files to %s (%v): %s", sysUser, err, out))
		}
	}

	res := restoreResult{
		Scope: scope, CheckpointPath: checkpoint.Path, CheckpointSHA: checkpoint.SHA256,
		CheckpointSizeBytes: checkpoint.SizeBytes, RestoredAt: time.Now().UTC(),
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// runWithStdinFile runs a fixed argv (never a shell) with the given file's
// contents piped in as stdin — needed for `mysql dbname < dump.sql`-style
// restores, which the shared run() helper (no stdin support) can't express.
func runWithStdinFile(ctx context.Context, stdinPath, name string, args ...string) (string, error) {
	f, err := os.Open(stdinPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = f
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
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
