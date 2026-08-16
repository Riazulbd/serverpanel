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

type backupRestoreResult struct {
	Scope            string    `json:"scope"`
	RestoredFrom     string    `json:"restored_from"`
	PreRestoreBackup string    `json:"pre_restore_backup"`
	RestoredAt       time.Time `json:"restored_at"`
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

	res, err := runBackup(ctx, progress, scope, siteRoot, dbName, "")
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// runBackup is the shared implementation behind backup.run and the
// automatic pre-restore checkpoint backup.restore takes before mutating
// anything. It always writes a stable, self-describing archive layout —
// "db.sql" for a database dump and/or a "files" directory mirroring the
// site root's contents, both at the archive root — rather than tar-ing the
// caller-supplied absolute paths directly. That's what lets backup.restore
// find its inputs deterministically: the original approach recorded the
// dump under a random per-run temp directory name inside the archive,
// which a later restore has no way to rediscover.
//
// labelPrefix distinguishes checkpoint archives ("prerestore-...") from
// ordinary ones when listing backupBaseDir.
func runBackup(ctx context.Context, progress Progress, scope, siteRoot, dbName, labelPrefix string) (backupResult, error) {
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
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s%s-%s-%s.tar.gz", labelPrefix, label, scope, stamp))

	workDir, err := os.MkdirTemp("", "sp-backup-*")
	if err != nil {
		return backupResult{}, err
	}
	defer os.RemoveAll(workDir)

	var members []string

	if scope == "db" || scope == "full" {
		progress("dumping database " + dbName)
		dumpPath := filepath.Join(workDir, "db.sql")
		out, err := run(ctx, "mysqldump", "--single-transaction", "--routines", "--events", dbName)
		if err != nil {
			return backupResult{}, fmt.Errorf("mysqldump: %w: %s", err, out)
		}
		if err := os.WriteFile(dumpPath, []byte(out), 0600); err != nil {
			return backupResult{}, fmt.Errorf("write dump: %w", err)
		}
		members = append(members, "db.sql")
	}

	if scope == "files" || scope == "full" {
		progress("archiving files from " + siteRoot)
		filesDir := filepath.Join(workDir, "files")
		if err := os.MkdirAll(filesDir, 0755); err != nil {
			return backupResult{}, fmt.Errorf("prepare files staging dir: %w", err)
		}
		// "src/." (not "src") copies siteRoot's *contents* into filesDir,
		// so the archive's files/ member mirrors siteRoot directly and a
		// restore can copy it straight back without an extra path segment.
		if out, err := run(ctx, "cp", "-a", siteRoot+"/.", filesDir+"/"); err != nil {
			return backupResult{}, fmt.Errorf("stage files for backup: %w: %s", err, out)
		}
		members = append(members, "files")
	}

	progress("compressing archive")
	args := append([]string{"-C", workDir, "-czf", outPath}, members...)
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

// handleBackupRestore restores a previously created backup.run archive.
// Safety properties, in order:
//  1. archive_path is confined to backupBaseDir (no path traversal to an
//     arbitrary file on the host).
//  2. if expected_sha256 is supplied, the archive is verified before
//     anything is touched — refuses to restore a corrupt or tampered file.
//  3. a pre-restore checkpoint (same scope/target) is taken via runBackup
//     before any destructive step; if the checkpoint itself fails, restore
//     aborts having changed nothing. Every later error message references
//     the checkpoint path so a failed restore is always recoverable.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	archivePath, _ := params["archive_path"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	expectedSHA256, _ := params["expected_sha256"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}

	absArchive, absBase, err := resolveArchivePath(archivePath)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absArchive, absBase+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive_path must be a file under %s", backupBaseDir)
	}
	if fi, err := os.Stat(absArchive); err != nil || fi.IsDir() {
		return "", fmt.Errorf("backup archive not found: %s", absArchive)
	}

	if expectedSHA256 != "" {
		progress("verifying archive checksum")
		sum, err := sha256File(absArchive)
		if err != nil {
			return "", fmt.Errorf("checksum archive: %w", err)
		}
		if !strings.EqualFold(sum, expectedSHA256) {
			return "", fmt.Errorf("archive checksum mismatch: expected %s, got %s — refusing to restore a possibly corrupt or tampered backup", expectedSHA256, sum)
		}
	}

	progress("creating pre-restore checkpoint")
	checkpoint, err := runBackup(ctx, progress, scope, siteRoot, dbName, "prerestore-")
	if err != nil {
		return "", fmt.Errorf("pre-restore checkpoint failed, restore aborted before changing anything: %w", err)
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-C", workDir, "-xzf", absArchive); err != nil {
		return "", fmt.Errorf("extract archive (pre-restore checkpoint %s was taken; nothing was changed): %w: %s", checkpoint.Path, err, out)
	}

	if scope == "db" || scope == "full" {
		dumpPath := filepath.Join(workDir, "db.sql")
		if _, err := os.Stat(dumpPath); err != nil {
			return "", fmt.Errorf("archive has no database dump for scope %q (pre-restore checkpoint %s was taken; nothing was changed): %w", scope, checkpoint.Path, err)
		}
		progress("restoring database " + dbName)
		if err := restoreDatabase(ctx, dbName, dumpPath); err != nil {
			return "", fmt.Errorf("restore database %s failed (pre-restore checkpoint %s is available to recover the prior state): %w", dbName, checkpoint.Path, err)
		}
	}

	if scope == "files" || scope == "full" {
		filesDir := filepath.Join(workDir, "files")
		if fi, err := os.Stat(filesDir); err != nil || !fi.IsDir() {
			return "", fmt.Errorf("archive has no files backup for scope %q (pre-restore checkpoint %s was taken; nothing was changed)", scope, checkpoint.Path)
		}
		progress("replacing files at " + siteRoot)
		if err := clearDirContents(siteRoot); err != nil {
			return "", fmt.Errorf("clear existing site contents at %s failed (pre-restore checkpoint %s is available to recover the prior state): %w", siteRoot, checkpoint.Path, err)
		}
		if out, err := run(ctx, "cp", "-a", filesDir+"/.", siteRoot+"/"); err != nil {
			return "", fmt.Errorf("restore files into %s failed (pre-restore checkpoint %s is available to recover the prior state): %w: %s", siteRoot, checkpoint.Path, err, out)
		}
	}

	res := backupRestoreResult{
		Scope:            scope,
		RestoredFrom:     absArchive,
		PreRestoreBackup: checkpoint.Path,
		RestoredAt:       time.Now().UTC(),
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// resolveArchivePath returns the absolute, symlink-resolved form of both
// archivePath and backupBaseDir so the caller's containment check (a
// simple string-prefix comparison) can't be defeated by ".." segments or a
// symlink that points outside backupBaseDir.
func resolveArchivePath(archivePath string) (absArchive, absBase string, err error) {
	if archivePath == "" {
		return "", "", fmt.Errorf("archive_path is required")
	}
	absBase, err = filepath.Abs(backupBaseDir)
	if err != nil {
		return "", "", err
	}
	candidate := archivePath
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(backupBaseDir, candidate)
	}
	absArchive, err = filepath.Abs(candidate)
	if err != nil {
		return "", "", err
	}
	if resolved, err := filepath.EvalSymlinks(absArchive); err == nil {
		absArchive = resolved
	}
	return absArchive, absBase, nil
}

// restoreDatabase pipes a plain-SQL dump into the mysql client via a fixed
// argv with the dump file as stdin — never through a shell, and dbName has
// already been validated against identifierRe by the caller — matching
// this package's "no arbitrary shell exec" boundary.
func restoreDatabase(ctx context.Context, dbName, dumpPath string) error {
	f, err := os.Open(dumpPath)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, "mysql", dbName)
	cmd.Stdin = f
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// clearDirContents removes every entry inside dir without removing dir
// itself, so the managed site directory's own ownership/permissions
// (set by site.create for the site's system user) survive a restore.
func clearDirContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
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
