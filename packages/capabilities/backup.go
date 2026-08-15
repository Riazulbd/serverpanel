package capabilities

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
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
	// A random suffix (not just the second-resolution timestamp) guarantees
	// two backups of the same target never collide on filename even when
	// triggered back-to-back within the same second — as handleBackupRestore
	// does for its pre-restore checkpoint, which runs immediately before a
	// restore that may itself be restoring from a backup taken seconds ago.
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s-%s.tar.gz", label, scope, stamp, randHex(4)))

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

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing is effectively unrecoverable (no entropy
		// source), and this suffix is only a collision-avoidance measure, not
		// a security boundary — fall back to a timestamp-derived value rather
		// than aborting the backup.
		return fmt.Sprintf("%x", time.Now().UnixNano())[:n*2]
	}
	return hex.EncodeToString(b)
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

type restoreResult struct {
	Scope           string `json:"scope"`
	RestoredFrom    string `json:"restored_from"`
	CheckpointPath  string `json:"checkpoint_path,omitempty"`
	CheckpointSHA   string `json:"checkpoint_sha256,omitempty"`
	CheckpointSizeB int64  `json:"checkpoint_size_bytes,omitempty"`
	DBRestored      bool   `json:"db_restored"`
	FilesRestored   bool   `json:"files_restored"`
}

// resolveBackupPath validates that a caller-supplied backup archive path is
// a real file that actually lives under backupBaseDir, following symlinks —
// the same "never trust a caller-supplied path outside a fixed, managed
// prefix" rule the file manager enforces (see file.go resolveScopedPath).
func resolveBackupPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("backup_path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve backup_path: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("backup archive not found: %w", err)
	}
	baseReal, err := filepath.EvalSymlinks(backupBaseDir)
	if err != nil {
		baseReal = backupBaseDir
	}
	if real != baseReal && !strings.HasPrefix(real, baseReal+string(filepath.Separator)) {
		return "", fmt.Errorf("backup_path must be an archive under the managed backup directory")
	}
	info, err := os.Stat(real)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("backup_path is not a regular file")
	}
	return real, nil
}

// findByExt walks a directory tree and returns the first file whose name
// ends in ext. Backup archives created by handleBackupRun embed the SQL
// dump under a randomly-named temp directory (os.MkdirTemp), so its exact
// in-archive path can't be predicted — only its extension is stable.
func findByExt(root string, ext string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ext) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no %s file found inside the extracted archive", ext)
	}
	return found, nil
}

// handleBackupRestore restores a database and/or a site's files from an
// archive previously created by handleBackupRun. It never accepts an
// arbitrary filesystem path: the archive must resolve under backupBaseDir,
// and (for a files/full restore) the target must resolve under the managed
// /home/sites/ prefix, matching the same boundary handleFileWrite and
// handleSiteCreate already enforce.
//
// Safety: before touching anything, it takes a fresh backup of whatever is
// live right now (a "pre-restore checkpoint") using the same scope/target
// being restored. If that checkpoint backup fails, the restore is aborted
// before any destructive step runs — a corrupt or unwritable backup target
// is exactly the situation where you most need the checkpoint, so silently
// skipping it defeats the point.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	dbName, _ := params["db_name"].(string)
	siteRoot, _ := params["site_root"].(string)
	sysUser, _ := params["system_user"].(string)
	expectedSHA, _ := params["expected_sha256"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(sysUser, "site_") {
		return "", fmt.Errorf("system_user must be a managed site system user")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}

	archivePath, err := resolveBackupPath(fmt.Sprint(params["backup_path"]))
	if err != nil {
		return "", err
	}

	if expectedSHA != "" {
		progress("verifying archive checksum")
		sum, err := sha256File(archivePath)
		if err != nil {
			return "", fmt.Errorf("checksum archive: %w", err)
		}
		if sum != expectedSHA {
			return "", fmt.Errorf("archive checksum mismatch: got %s, want %s — refusing to restore from a possibly-corrupt archive", sum, expectedSHA)
		}
	}

	progress("taking pre-restore checkpoint")
	checkpointParams := map[string]any{"scope": scope, "site_root": siteRoot, "db_name": dbName}
	checkpointOut, err := handleBackupRun(ctx, checkpointParams, func(string) {})
	if err != nil {
		return "", fmt.Errorf("pre-restore checkpoint backup failed, aborting restore before any change was made: %w", err)
	}
	var checkpoint backupResult
	json.Unmarshal([]byte(checkpointOut), &checkpoint)

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting archive")
	if out, err := run(ctx, "tar", "-xzf", archivePath, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract archive: %w: %s", err, out)
	}

	res := restoreResult{
		Scope: scope, RestoredFrom: archivePath,
		CheckpointPath: checkpoint.Path, CheckpointSHA: checkpoint.SHA256, CheckpointSizeB: checkpoint.SizeBytes,
	}

	if scope == "db" || scope == "full" {
		progress("locating database dump in archive")
		dumpPath, err := findByExt(workDir, ".sql")
		if err != nil {
			return "", fmt.Errorf("db restore: %w", err)
		}
		progress("restoring database " + dbName)
		if out, err := runWithStdinFile(ctx, dumpPath, "mysql", dbName); err != nil {
			return "", fmt.Errorf("mysql restore: %w: %s", err, out)
		}
		res.DBRestored = true
	}

	if scope == "files" || scope == "full" {
		extractedRoot := filepath.Join(workDir, strings.TrimPrefix(siteRoot, "/"))
		if info, err := os.Stat(extractedRoot); err != nil || !info.IsDir() {
			return "", fmt.Errorf("files restore: extracted archive did not contain %q (was it backed up from a different site_root?)", siteRoot)
		}
		progress("restoring files to " + siteRoot)
		if err := os.MkdirAll(siteRoot, 0750); err != nil {
			return "", fmt.Errorf("prepare site root: %w", err)
		}
		if out, err := run(ctx, "cp", "-a", extractedRoot+"/.", siteRoot+"/"); err != nil {
			return "", fmt.Errorf("copy restored files: %w: %s", err, out)
		}
		if out, err := run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot); err != nil {
			return "", fmt.Errorf("chown restored files: %w: %s", err, out)
		}
		res.FilesRestored = true
	}

	out, _ := json.Marshal(res)
	return string(out), nil
}
