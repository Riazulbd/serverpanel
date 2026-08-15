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
//
// handleBackupRestore (below) is the counterpart that reads an archive this
// function produced back onto disk.
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
	// A second-resolution timestamp alone is not a unique filename: two
	// backup.run calls for the same site/db within the same second (e.g. a
	// backup.restore's own pre-restore checkpoint, which runs moments after
	// the archive it's about to restore was itself created) would otherwise
	// collide and silently overwrite one archive with another's contents —
	// a real bug caught by TestHandleBackupRestoreFilesScopeRoundTrip. The
	// random suffix guarantees distinct filenames regardless of timing.
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

// randHex returns n random bytes hex-encoded, for building collision-safe
// filenames. It never errors in practice (crypto/rand.Read against the OS
// CSPRNG); an error here would mean the system's entropy source is broken,
// in which case falling back to an all-zero suffix is preferable to a
// panic — the timestamp component still narrows collisions considerably.
func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
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
	Scope               string    `json:"scope"`
	RestoredDatabase    bool      `json:"restored_database"`
	RestoredFiles       bool      `json:"restored_files"`
	CheckpointPath      string    `json:"checkpoint_path,omitempty"`
	CheckpointSizeBytes int64     `json:"checkpoint_size_bytes,omitempty"`
	CheckpointSHA256    string    `json:"checkpoint_sha256,omitempty"`
	CheckpointError     string    `json:"checkpoint_error,omitempty"`
	RestoredAt          time.Time `json:"restored_at"`
}

// handleBackupRestore restores a previously-created backup.run archive back
// onto disk: a `mysql` import for the database dump (if any) and a file-tree
// copy for the site files (if any). It only ever reads archives that
// already live under backupBaseDir — never an arbitrary caller-supplied
// path — and, when a sha256 is supplied, refuses to restore from an archive
// whose current contents don't match it.
//
// Before touching anything, it takes a best-effort "pre-restore checkpoint"
// — a fresh backup.run of the current state, using the same scope/site_root/
// db_name as the restore — so a bad restore can itself be rolled back. A
// checkpoint failure (e.g. the database or site is already gone, which is
// exactly the disaster-recovery case a restore is often used for) is
// reported in the result rather than aborting the restore, since blocking a
// recovery on the ability to snapshot what's already broken would defeat
// the point.
//
// It deliberately does not delete anything already on disk before
// restoring (files are merged/overwritten, not preceded by a wipe) — see
// handleBackupRun's doc comment on why this codebase never implements
// unrestricted recursive deletion as a capability. This means files present
// on disk but absent from the archive survive a restore; that tradeoff is
// documented in docs/OPERATIONS.md rather than left implicit.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	archivePath, _ := params["path"].(string)
	expectedSHA, _ := params["sha256"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	cleanPath := filepath.Clean(archivePath)
	if cleanPath != backupBaseDir && !strings.HasPrefix(cleanPath, backupBaseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("path must be a backup archive under %s", backupBaseDir)
	}
	if info, err := os.Stat(cleanPath); err != nil || info.IsDir() {
		return "", fmt.Errorf("backup archive not found: %s", cleanPath)
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}

	progress("verifying archive checksum")
	sum, err := sha256File(cleanPath)
	if err != nil {
		return "", fmt.Errorf("checksum archive: %w", err)
	}
	if expectedSHA != "" && !strings.EqualFold(sum, expectedSHA) {
		return "", fmt.Errorf("checksum mismatch: archive may be corrupted or tampered with (expected %s, got %s)", expectedSHA, sum)
	}

	res := restoreResult{Scope: scope, RestoredAt: time.Now().UTC()}

	progress("creating pre-restore checkpoint")
	if checkpointJSON, err := handleBackupRun(ctx, params, progress); err != nil {
		res.CheckpointError = err.Error()
		progress("warning: pre-restore checkpoint failed, continuing restore anyway: " + err.Error())
	} else {
		var checkpoint backupResult
		if json.Unmarshal([]byte(checkpointJSON), &checkpoint) == nil {
			res.CheckpointPath = checkpoint.Path
			res.CheckpointSizeBytes = checkpoint.SizeBytes
			res.CheckpointSHA256 = checkpoint.SHA256
		}
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting archive")
	if out, err := run(ctx, "tar", "-xzf", cleanPath, "-C", workDir); err != nil {
		return "", fmt.Errorf("tar extract: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		sqlPath, err := findFileWithSuffix(workDir, ".sql")
		if err != nil {
			return "", fmt.Errorf("locate database dump in archive: %w", err)
		}
		progress("restoring database " + dbName)
		f, err := os.Open(sqlPath)
		if err != nil {
			return "", fmt.Errorf("open database dump: %w", err)
		}
		defer f.Close()
		cmd := exec.CommandContext(ctx, "mysql", dbName)
		cmd.Stdin = f
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("mysql import: %w: %s", err, strings.TrimSpace(string(out)))
		}
		res.RestoredDatabase = true
	}

	if scope == "files" || scope == "full" {
		srcDir, err := findSiteFilesDir(workDir)
		if err != nil {
			return "", fmt.Errorf("locate site files in archive: %w", err)
		}
		progress("restoring files to " + siteRoot)
		if err := os.MkdirAll(siteRoot, 0750); err != nil {
			return "", fmt.Errorf("prepare site root: %w", err)
		}
		// "cp -a SRC/. DEST/" merges the archived tree into the existing
		// site root (overwriting files also present in the archive) rather
		// than replacing the directory outright — see the doc comment above.
		if out, err := run(ctx, "cp", "-a", srcDir+"/.", siteRoot+"/"); err != nil {
			return "", fmt.Errorf("copy restored files: %w: %s", err, out)
		}
		sysUser := filepath.Base(siteRoot)
		run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot)
		res.RestoredFiles = true
	}

	out, _ := json.Marshal(res)
	return string(out), nil
}

// findFileWithSuffix returns the first file under root (walked in a
// deterministic, lexical order) whose name has the given suffix — used to
// locate the single .sql dump handleBackupRun placed in its temp working
// directory before archiving.
func findFileWithSuffix(root, suffix string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if found != "" {
			return fs.SkipAll
		}
		if !d.IsDir() && strings.HasSuffix(path, suffix) {
			found = path
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no %s file found in archive", suffix)
	}
	return found, nil
}

// findSiteFilesDir locates the single site directory handleBackupRun
// archived under its original absolute path (tar strips the leading "/",
// so "/home/sites/<user>" becomes "home/sites/<user>" inside the archive).
// It intentionally does not require the archived site's name to match the
// restore target's — a restore may target a renamed site or a different
// server, which is the whole point of "restore to the same or another
// server" in the product plan.
func findSiteFilesDir(root string) (string, error) {
	base := filepath.Join(root, "home", "sites")
	entries, err := os.ReadDir(base)
	if err != nil {
		return "", fmt.Errorf("no site files found in archive (expected under home/sites/): %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			return filepath.Join(base, e.Name()), nil
		}
	}
	return "", fmt.Errorf("no site directory found in archive")
}
