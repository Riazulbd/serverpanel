package capabilities

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
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

// validateBackupScope is shared by backup.run and backup.restore: both need
// the same "scope determines which of site_root/db_name are required and
// how they're validated" rule, and keeping it in one place is what makes it
// impossible for the two capabilities to silently drift apart.
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

// resolveBackupPath maps a caller-supplied backup archive path onto a real
// filesystem path guaranteed to stay inside backupBaseDir, mirroring
// resolveScopedPath's symlink-safe containment check in file.go. This is
// what stops backup.restore from being handed an arbitrary path (e.g.
// /etc/shadow) dressed up as a "backup to restore."
func resolveBackupPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
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
		return "", fmt.Errorf("backup path must be inside the managed backup directory")
	}

	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve backup path: %w", err)
	}
	if resolved != realBase && !strings.HasPrefix(resolved, realBase+string(filepath.Separator)) {
		return "", fmt.Errorf("backup path (via symlink) escapes the managed backup directory")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat backup file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("backup path must be a file, not a directory")
	}
	return resolved, nil
}

// handleBackupRun creates a local, checksummed backup archive. It never
// shells out to a recursive-delete anything — this capability only ever
// creates files under backupBaseDir; cleanup of old backups is a separate,
// explicitly-scoped capability (not implemented in this skeleton) rather
// than folded in here, matching "never implement disk cleanup as an
// unrestricted recursive deletion command" from docs/product-plan.md.
//
// The archive always uses fixed, predictable top-level entry names ("db",
// "files") rather than the caller's actual paths, which is what lets
// handleBackupRestore extract a backup created on one server/site and
// apply it to a different one (site_root and db_name at restore time need
// not match the values used at backup time) — required for the product
// plan's cross-server restore requirement.
func handleBackupRun(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	if progress == nil {
		progress = func(string) {}
	}
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	label, _ := params["label"].(string)

	if err := validateBackupScope(scope, siteRoot, dbName); err != nil {
		return "", err
	}

	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if label == "" {
		label = dbName
		if label == "" {
			label = filepath.Base(siteRoot)
		}
	}
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s.tar.gz", label, scope, stamp))

	workDir, err := os.MkdirTemp("", "sp-backup-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	var tarEntries []string

	if scope == "db" || scope == "full" {
		progress("dumping database " + dbName)
		if err := os.MkdirAll(filepath.Join(workDir, "db"), 0700); err != nil {
			return "", fmt.Errorf("create db staging dir: %w", err)
		}
		dumpPath := filepath.Join(workDir, "db", dbName+".sql")
		out, err := run(ctx, "mysqldump", "--single-transaction", "--routines", "--events", dbName)
		if err != nil {
			return "", fmt.Errorf("mysqldump: %w: %s", err, out)
		}
		if err := os.WriteFile(dumpPath, []byte(out), 0600); err != nil {
			return "", fmt.Errorf("write dump: %w", err)
		}
		tarEntries = append(tarEntries, "db")
	}

	if scope == "files" || scope == "full" {
		progress("archiving files from " + siteRoot)
		// A symlink (dereferenced by tar's -h flag below) rather than a
		// copy: siteRoot can be arbitrarily large, and this way the
		// archive always contains a "files/" entry regardless of the
		// site's actual directory name, decoupling the backup's contents
		// from the path it was taken from.
		if err := os.Symlink(siteRoot, filepath.Join(workDir, "files")); err != nil {
			return "", fmt.Errorf("stage files for archiving: %w", err)
		}
		tarEntries = append(tarEntries, "files")
	}

	progress("compressing archive")
	args := append([]string{"-czf", outPath, "-h", "-C", workDir}, tarEntries...)
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

// handleBackupRestore restores a previously created backup.run archive.
// Unless params["checkpoint"] is explicitly false, it first takes a fresh
// backup of whatever is about to be overwritten (same scope/site_root/
// db_name as the restore itself) — a pre-restore checkpoint, so a bad
// restore is itself recoverable rather than a one-way door. If the
// checkpoint step fails, the restore is aborted before anything is
// touched: a failed safety net is a reason to stop, not to proceed anyway.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	if progress == nil {
		progress = func(string) {}
	}
	path, _ := params["path"].(string)
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	checkpoint := true
	if v, ok := params["checkpoint"].(bool); ok {
		checkpoint = v
	}

	if err := validateBackupScope(scope, siteRoot, dbName); err != nil {
		return "", err
	}
	realPath, err := resolveBackupPath(path)
	if err != nil {
		return "", err
	}

	var checkpointPath string
	if checkpoint {
		progress("creating pre-restore checkpoint")
		out, err := handleBackupRun(ctx, map[string]any{
			"scope": scope, "site_root": siteRoot, "db_name": dbName, "label": "checkpoint",
		}, progress)
		if err != nil {
			return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore to avoid unrecoverable data loss: %w", err)
		}
		var cp backupResult
		if json.Unmarshal([]byte(out), &cp) == nil {
			checkpointPath = cp.Path
		}
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-xzf", realPath, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract archive: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		dumpPath := filepath.Join(workDir, "db", dbName+".sql")
		if _, err := os.Stat(dumpPath); err != nil {
			return "", fmt.Errorf("backup archive does not contain a database dump for %q", dbName)
		}
		progress("restoring database " + dbName)
		if out, err := runWithStdinFile(ctx, dumpPath, "mysql", dbName); err != nil {
			return "", fmt.Errorf("mysql restore: %w: %s", err, out)
		}
	}

	if scope == "files" || scope == "full" {
		extracted := filepath.Join(workDir, "files")
		if _, err := os.Stat(extracted); err != nil {
			return "", fmt.Errorf("backup archive does not contain a files payload")
		}
		progress("restoring files to " + siteRoot)
		entries, err := os.ReadDir(siteRoot)
		if err != nil {
			return "", fmt.Errorf("read site root: %w", err)
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(siteRoot, e.Name())); err != nil {
				return "", fmt.Errorf("clear existing site contents: %w", err)
			}
		}
		if out, err := run(ctx, "cp", "-a", extracted+"/.", siteRoot); err != nil {
			return "", fmt.Errorf("copy restored files into place: %w: %s", err, out)
		}
		// Best-effort, matching handleFileWrite's convention (file.go): a
		// restore that recovered the data but left ownership to be fixed
		// manually is far better than one that reports total failure and
		// leaves the site in whatever half-restored state cp -a got to.
		sysUser := filepath.Base(siteRoot)
		if out, err := run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot); err != nil {
			progress(fmt.Sprintf("warning: could not restore ownership to %s (%v): %s", sysUser, err, out))
		}
	}

	res := restoreResult{Scope: scope, RestoredFrom: realPath, CheckpointPath: checkpointPath, RestoredAt: time.Now().UTC()}
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
