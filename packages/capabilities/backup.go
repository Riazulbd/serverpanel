package capabilities

import (
	"bytes"
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
	ArchivePath    string    `json:"archive_path"`
	CheckpointPath string    `json:"checkpoint_path"`
	RestoredAt     time.Time `json:"restored_at"`
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

	if err := validateBackupScope(scope, siteRoot, dbName); err != nil {
		return "", err
	}

	res, err := runBackup(ctx, scope, siteRoot, dbName, progress)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// runBackup holds the actual archive-creation logic shared by
// handleBackupRun and handleBackupRestore's pre-restore checkpoint step —
// a restore must never overwrite live data without first taking a fresh
// backup of exactly what it's about to replace.
func runBackup(ctx context.Context, scope, siteRoot, dbName string, progress Progress) (backupResult, error) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return backupResult{}, fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	label := dbName
	if label == "" {
		label = filepath.Base(siteRoot)
	}
	// A bare second-precision timestamp collides when two backups of the
	// same label+scope are taken within the same second — which a
	// pre-restore checkpoint does routinely, since it backs up the exact
	// same site/scope the restore itself just read the archive path for.
	// A colliding filename would silently overwrite the archive currently
	// being restored from with a fresh backup of the (about-to-be-
	// overwritten) current state, corrupting the restore. The random
	// suffix makes every archive filename unique regardless of timing.
	suffix := make([]byte, 4)
	rand.Read(suffix)
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

// handleBackupRestore restores a previously-created backup.run archive.
// Safety properties, in order:
//  1. archive_path is constrained to backupBaseDir (no restoring from an
//     arbitrary, caller-supplied filesystem path).
//  2. an optional caller-supplied sha256 is verified before anything is
//     touched, so a corrupted or tampered archive is rejected up front.
//  3. a pre-restore checkpoint (a fresh runBackup of exactly what's about
//     to be overwritten) is taken before any destructive step, so a bad
//     restore can itself be undone.
//  4. file restore only ever overlays extracted files onto site_root via
//     `cp -a` — it never deletes anything, matching this package's "no
//     unrestricted recursive delete" rule.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	archivePath, _ := params["archive_path"].(string)
	expectedSHA256, _ := params["sha256"].(string)
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)

	if err := validateBackupScope(scope, siteRoot, dbName); err != nil {
		return "", err
	}

	cleanArchivePath := filepath.Clean(archivePath)
	if !strings.HasPrefix(cleanArchivePath, backupBaseDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive_path must be a backup archive under %s", backupBaseDir)
	}
	info, err := os.Stat(cleanArchivePath)
	if err != nil {
		return "", fmt.Errorf("backup archive not found: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("archive_path %q is a directory, not a backup archive", cleanArchivePath)
	}

	if expectedSHA256 != "" {
		progress("verifying archive checksum")
		sum, err := sha256File(cleanArchivePath)
		if err != nil {
			return "", fmt.Errorf("checksum archive: %w", err)
		}
		if !strings.EqualFold(sum, expectedSHA256) {
			return "", fmt.Errorf("archive checksum mismatch: expected %s, got %s — refusing to restore a possibly corrupted or tampered archive", expectedSHA256, sum)
		}
	}

	progress("creating pre-restore checkpoint of current state")
	checkpoint, err := runBackup(ctx, scope, siteRoot, dbName, progress)
	if err != nil {
		return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore before touching live data: %w", err)
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting archive")
	if out, err := run(ctx, "tar", "-xzf", cleanArchivePath, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract archive: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		dumpPath := filepath.Join(workDir, dbName+".sql")
		dump, err := os.ReadFile(dumpPath)
		if err != nil {
			return "", fmt.Errorf("archive does not contain expected database dump %s.sql: %w (a pre-restore checkpoint was taken at %s; nothing was modified)", dbName, err, checkpoint.Path)
		}
		progress("restoring database " + dbName)
		cmd := exec.CommandContext(ctx, "mysql", dbName)
		cmd.Stdin = bytes.NewReader(dump)
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("mysql restore: %w: %s (a pre-restore checkpoint was taken at %s before this step ran — restore from it if data is now inconsistent)", err, strings.TrimSpace(string(out)), checkpoint.Path)
		}
	}

	if scope == "files" || scope == "full" {
		// tar strips the leading "/" from absolute member paths, so the
		// files backup.run archived from an absolute site_root land back
		// under workDir at that same path, minus the leading slash.
		extractedRoot := filepath.Join(workDir, strings.TrimPrefix(siteRoot, "/"))
		if _, err := os.Stat(extractedRoot); err != nil {
			return "", fmt.Errorf("archive does not contain expected files under %s: %w (a pre-restore checkpoint was taken at %s; nothing was modified)", siteRoot, err, checkpoint.Path)
		}
		progress("restoring files to " + siteRoot)
		// Overlay only — never `--delete` or `rm`, matching this
		// package's stance that recursive deletion is a separate,
		// explicitly-scoped capability, not something folded into restore.
		if out, err := run(ctx, "cp", "-a", extractedRoot+"/.", siteRoot+"/"); err != nil {
			return "", fmt.Errorf("restore files: %w: %s (a pre-restore checkpoint was taken at %s before this step ran)", err, out, checkpoint.Path)
		}
	}

	res := restoreResult{
		Scope: scope, ArchivePath: cleanArchivePath, CheckpointPath: checkpoint.Path,
		RestoredAt: time.Now().UTC(),
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
