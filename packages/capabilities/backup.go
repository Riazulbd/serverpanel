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

type backupResult struct {
	Scope     string    `json:"scope"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// restoreResult is what backup.restore returns as its TaskEvent detail. The
// checkpoint fields let a caller find and, if needed, separately restore
// the automatic pre-restore snapshot this handler always takes before
// touching anything — see handleBackupRestore.
type restoreResult struct {
	Scope          string    `json:"scope"`
	RestoredFrom   string    `json:"restored_from"`
	CheckpointPath string    `json:"checkpoint_path"`
	RestoredAt     time.Time `json:"restored_at"`
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

	if err := validateBackupScopeParams(scope, siteRoot, dbName); err != nil {
		return "", err
	}

	res, err := runBackup(ctx, scope, siteRoot, dbName, "", progress)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// validateBackupScopeParams is shared by backup.run and backup.restore (the
// latter validates its own restore-target params with it before it ever
// takes the pre-restore checkpoint via the same run path).
func validateBackupScopeParams(scope, siteRoot, dbName string) error {
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

// runBackup is the core "produce a checksummed tar.gz under backupBaseDir"
// routine, factored out of handleBackupRun so handleBackupRestore can call
// it unchanged to take a pre-restore checkpoint — a restore must never run
// without first proving it can still take a fresh, restorable snapshot of
// what it's about to overwrite.
//
// labelSuffix distinguishes a checkpoint's filename from a normal backup's
// (e.g. "prerestore") purely for operator readability; it has no effect on
// validation or behavior.
func runBackup(ctx context.Context, scope, siteRoot, dbName, labelSuffix string, progress Progress) (backupResult, error) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return backupResult{}, fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	label := dbName
	if label == "" {
		label = filepath.Base(siteRoot)
	}
	if labelSuffix != "" {
		label = label + "-" + labelSuffix
	}
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s.tar.gz", label, scope, stamp))

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
	args := append([]string{"-czf", outPath}, tarInputs...)
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

// resolveBackupPath validates that a caller-supplied backup archive path is
// a real, non-symlink regular file that resolves to somewhere inside
// backupBaseDir — the same "no path traversal, no symlink escape" posture
// resolveScopedPath applies to the file manager (file.go), applied here so
// backup.restore can never be pointed at an arbitrary file on the host and
// asked to extract or mysql-import it.
func resolveBackupPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	cleanBase, err := filepath.Abs(filepath.Clean(backupBaseDir))
	if err != nil {
		return "", fmt.Errorf("resolve backup base directory: %w", err)
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	if abs != cleanBase && !strings.HasPrefix(abs, cleanBase+string(os.PathSeparator)) {
		return "", fmt.Errorf("path must be a backup archive under %s", backupBaseDir)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("backup archive not found: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("backup path must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("backup path must be a regular file")
	}
	return abs, nil
}

// handleBackupRestore restores a previously created backup.run archive.
// Safety posture:
//  1. It always takes a fresh checkpoint backup of the current live state
//     (same scope/target) before touching anything, and aborts without
//     changing anything if that checkpoint fails.
//  2. For a files/full restore it moves the current site directory aside
//     (a same-filesystem rename, effectively instant) rather than deleting
//     it, and only removes that aside copy after the restored copy is
//     successfully in place — a failed restore rolls back to the
//     pre-restore state automatically.
//  3. It only ever reads an archive from inside backupBaseDir (see
//     resolveBackupPath) and only ever writes into a /home/sites/* site
//     root or imports into a single already-validated database name —
//     never an arbitrary caller-supplied path.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	path, _ := params["path"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)

	if err := validateBackupScopeParams(scope, siteRoot, dbName); err != nil {
		return "", err
	}
	backupPath, err := resolveBackupPath(path)
	if err != nil {
		return "", err
	}

	progress("taking a pre-restore checkpoint of the current state")
	checkpoint, err := runBackup(ctx, scope, siteRoot, dbName, "prerestore", progress)
	if err != nil {
		return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore without changing anything: %w", err)
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-xzf", backupPath, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract archive: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		if err := restoreDatabase(ctx, workDir, dbName, progress); err != nil {
			return "", fmt.Errorf("restore failed after a checkpoint was safely taken at %s: %w", checkpoint.Path, err)
		}
	}

	if scope == "files" || scope == "full" {
		if err := restoreFiles(ctx, workDir, siteRoot, progress); err != nil {
			return "", fmt.Errorf("restore failed after a checkpoint was safely taken at %s: %w", checkpoint.Path, err)
		}
	}

	res := restoreResult{Scope: scope, RestoredFrom: backupPath, CheckpointPath: checkpoint.Path, RestoredAt: time.Now().UTC()}
	out, _ := json.Marshal(res)
	return string(out), nil
}

func restoreDatabase(ctx context.Context, workDir, dbName string, progress Progress) error {
	dumpPath := filepath.Join(workDir, dbName+".sql")
	f, err := os.Open(dumpPath)
	if err != nil {
		return fmt.Errorf("backup archive does not contain the expected dump %s.sql: %w", dbName, err)
	}
	defer f.Close()

	progress("restoring database " + dbName)
	cmd := exec.CommandContext(ctx, "mysql", dbName)
	cmd.Stdin = f
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql restore: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// restoreFiles replaces siteRoot's contents with what was extracted into
// workDir, keeping a same-filesystem rename of the old contents as a
// rollback point until the new contents are confirmed in place.
func restoreFiles(ctx context.Context, workDir, siteRoot string, progress Progress) error {
	extractedRoot := filepath.Join(workDir, strings.TrimPrefix(filepath.Clean(siteRoot), "/"))
	info, err := os.Stat(extractedRoot)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("backup archive does not contain the expected path %s", siteRoot)
	}

	asideDir := siteRoot + ".pre-restore-" + time.Now().UTC().Format("20060102T150405Z")
	hadExisting := false
	if _, err := os.Stat(siteRoot); err == nil {
		hadExisting = true
		progress("moving current site files aside as a rollback point")
		if err := os.Rename(siteRoot, asideDir); err != nil {
			return fmt.Errorf("move current site files aside: %w", err)
		}
	}

	progress("copying restored files into place")
	if out, err := run(ctx, "cp", "-a", extractedRoot, siteRoot); err != nil {
		os.RemoveAll(siteRoot)
		if hadExisting {
			os.Rename(asideDir, siteRoot)
		}
		return fmt.Errorf("restore files: %w: %s", err, out)
	}

	sysUser := filepath.Base(siteRoot)
	if _, err := run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot); err != nil {
		progress(fmt.Sprintf("warning: chown after restore failed: %v", err))
	}
	if hadExisting {
		os.RemoveAll(asideDir)
	}
	return nil
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
