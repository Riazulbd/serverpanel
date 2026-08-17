package capabilities

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}

	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	label := dbName
	if label == "" {
		label = filepath.Base(siteRoot)
	}
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s.tar.gz", label, scope, stamp))

	workDir, err := os.MkdirTemp("", "sp-backup-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	var tarInputs []string

	if scope == "db" || scope == "full" {
		progress("dumping database " + dbName)
		dumpPath := filepath.Join(workDir, dbName+".sql")
		out, err := run(ctx, "mysqldump", "--single-transaction", "--routines", "--events", dbName)
		if err != nil {
			return "", fmt.Errorf("mysqldump: %w: %s", err, out)
		}
		if err := os.WriteFile(dumpPath, []byte(out), 0600); err != nil {
			return "", fmt.Errorf("write dump: %w", err)
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
		return "", fmt.Errorf("tar: %w: %s", err, out)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return "", fmt.Errorf("stat backup archive: %w", err)
	}
	sum, err := sha256File(outPath)
	if err != nil {
		return "", fmt.Errorf("checksum backup archive: %w", err)
	}

	res := backupResult{Scope: scope, Path: outPath, SizeBytes: info.Size(), SHA256: sum, CreatedAt: time.Now().UTC()}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// restoreResult is what backup.restore returns as its TaskEvent detail
// (JSON). The control plane registers PreRestoreArchive (when present) as
// its own backup record — same shape as backup.run's result — so the
// safety checkpoint a restore takes before overwriting files is itself
// restorable later, not just a file sitting on disk with no control-plane
// record of it.
type restoreResult struct {
	Scope                 string `json:"scope"`
	SourcePath            string `json:"source_path"`
	DatabaseRestored      bool   `json:"database_restored"`
	FilesRestored         bool   `json:"files_restored"`
	PreRestoreArchive     string `json:"pre_restore_archive,omitempty"`
	PreRestoreArchiveSize int64  `json:"pre_restore_archive_size_bytes,omitempty"`
	PreRestoreArchiveSHA  string `json:"pre_restore_archive_sha256,omitempty"`
	RestoredAt            string `json:"restored_at"`
}

// handleBackupRestore restores a backup.run archive. It never trusts the
// checksum it's handed without re-verifying: params must include the
// sha256 the control plane recorded when the backup was created, and a
// mismatch aborts before anything is touched. Before overwriting any
// existing site files it first snapshots the current state into its own
// checksummed archive under backupBaseDir — a bad restore is itself
// recoverable, matching the "backup before restore" principle already
// documented as a gap (docs/SYSTEM.md §28) when backup.run shipped without
// this capability.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	rawPath, _ := params["path"].(string)
	expectedSHA, _ := params["sha256"].(string)
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}
	if expectedSHA == "" {
		return "", fmt.Errorf("sha256 is required to verify archive integrity before restore")
	}

	archivePath, err := resolveBackupArchivePath(rawPath)
	if err != nil {
		return "", err
	}

	progress("verifying archive integrity")
	actualSHA, err := sha256File(archivePath)
	if err != nil {
		return "", fmt.Errorf("read backup archive: %w", err)
	}
	if !strings.EqualFold(actualSHA, expectedSHA) {
		return "", fmt.Errorf("checksum mismatch: archive may be corrupted or tampered with (expected %s, got %s)", expectedSHA, actualSHA)
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting archive")
	if out, err := run(ctx, "tar", "-xzf", archivePath, "-C", workDir); err != nil {
		return "", fmt.Errorf("tar extract: %w: %s", err, out)
	}

	res := restoreResult{Scope: scope, SourcePath: archivePath}

	if scope == "db" || scope == "full" {
		dumpPath, err := findFileByName(workDir, dbName+".sql")
		if err != nil {
			return "", err
		}
		progress("restoring database " + dbName)
		f, err := os.Open(dumpPath)
		if err != nil {
			return "", fmt.Errorf("open database dump: %w", err)
		}
		cmd := exec.CommandContext(ctx, "mysql", dbName)
		cmd.Stdin = f
		out, err := cmd.CombinedOutput()
		f.Close()
		if err != nil {
			return "", fmt.Errorf("restore database %q: %w: %s", dbName, err, strings.TrimSpace(string(out)))
		}
		res.DatabaseRestored = true
	}

	if scope == "files" || scope == "full" {
		archivedRoot := filepath.Join(workDir, strings.TrimPrefix(siteRoot, "/"))
		if info, err := os.Stat(archivedRoot); err != nil || !info.IsDir() {
			return "", fmt.Errorf("archive does not contain files for %s", siteRoot)
		}

		if info, err := os.Stat(siteRoot); err == nil && info.IsDir() {
			progress("checkpointing current files before overwrite")
			checkpoint := filepath.Join(backupBaseDir, fmt.Sprintf("%s-prerestore-%s.tar.gz",
				filepath.Base(siteRoot), time.Now().UTC().Format("20060102T150405Z")))
			if out, err := run(ctx, "tar", "-czf", checkpoint, siteRoot); err != nil {
				return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore before touching existing files: %w: %s", err, out)
			}
			if info, err := os.Stat(checkpoint); err == nil {
				res.PreRestoreArchiveSize = info.Size()
			}
			if sum, err := sha256File(checkpoint); err == nil {
				res.PreRestoreArchiveSHA = sum
			}
			res.PreRestoreArchive = checkpoint
		}

		progress("restoring files to " + siteRoot)
		if err := os.RemoveAll(siteRoot); err != nil {
			return "", fmt.Errorf("clear existing site directory: %w", err)
		}
		if err := os.MkdirAll(siteRoot, 0750); err != nil {
			return "", fmt.Errorf("recreate site directory: %w", err)
		}
		if out, err := run(ctx, "cp", "-a", archivedRoot+"/.", siteRoot+"/"); err != nil {
			return "", fmt.Errorf("restore files: %w: %s", err, out)
		}

		if sysUser, _ := params["system_user"].(string); sysUser != "" {
			run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot)
		}
		res.FilesRestored = true
	}

	res.RestoredAt = time.Now().UTC().Format(time.RFC3339)
	out, _ := json.Marshal(res)
	return string(out), nil
}

// resolveBackupArchivePath maps a caller-supplied backup path onto a real
// filesystem path guaranteed to stay inside backupBaseDir, the same
// symlink-safe containment approach file.go's resolveScopedPath uses for
// the file manager — a restore request naming an arbitrary filesystem path
// must never be able to read (and feed into mysql/tar) something outside
// the managed backup directory.
func resolveBackupArchivePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	realBase, err := filepath.EvalSymlinks(backupBaseDir)
	if err != nil {
		return "", fmt.Errorf("resolve backup directory: %w", err)
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		cleaned = filepath.Join(backupBaseDir, cleaned)
	}
	if cleaned != realBase && !strings.HasPrefix(cleaned, realBase+string(filepath.Separator)) {
		return "", fmt.Errorf("path must be a backup archive under %s", backupBaseDir)
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("backup archive not found: %w", err)
	}
	if resolved != realBase && !strings.HasPrefix(resolved, realBase+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the managed backup directory")
	}
	if info, err := os.Stat(resolved); err != nil || info.IsDir() {
		return "", fmt.Errorf("backup archive not found at %s", cleaned)
	}
	return resolved, nil
}

// findFileByName walks root for the first regular file named exactly name.
// backup.run archives a database dump under a random per-run temp
// directory, so restore locates it by name (already validated against
// identifierRe + ".sql") rather than assuming a fixed archive layout.
func findFileByName(root, name string) (string, error) {
	var found string
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == name {
			found = p
			return fs.SkipAll
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return "", fmt.Errorf("search archive contents: %w", walkErr)
	}
	if found == "" {
		return "", fmt.Errorf("archive does not contain a %s database dump", name)
	}
	return found, nil
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
