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
	// A random suffix (not just the second-granularity stamp) keeps two
	// backups of the same site/scope started within the same second from
	// colliding on one output path — which would otherwise let a later
	// backup silently overwrite an earlier one still referenced elsewhere
	// (e.g. handleBackupRestore's own pre-restore checkpoint, taken
	// moments after the backup it's about to restore).
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s-%s.tar.gz", label, scope, stamp, randSuffix()))

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
// (JSON) — the control plane logs this to the audit trail; see
// apps/controlplane/backups.go handleRestoreBackup.
type restoreResult struct {
	Scope          string    `json:"scope"`
	RestoredFrom   string    `json:"restored_from"`
	CheckpointPath string    `json:"checkpoint_path,omitempty"`
	RestoredAt     time.Time `json:"restored_at"`
}

// validateBackupPath confirms path resolves to somewhere inside
// backupBaseDir — the fixed, agent-controlled directory backup.run ever
// writes to — rejecting both a literal ../ escape and a symlink planted
// inside backupBaseDir that points outside it. backup_path always comes
// from the control plane (which only ever echoes back a path it recorded
// from a prior backup.run result), but this capability treats it as
// untrusted input regardless, matching every other path-accepting handler
// in this package.
func validateBackupPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("backup_path is required")
	}
	cleaned := filepath.Clean(path)
	if cleaned != backupBaseDir && !strings.HasPrefix(cleaned, backupBaseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("backup_path must be inside %s", backupBaseDir)
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve backup_path: %w", err)
	}
	if resolved != backupBaseDir && !strings.HasPrefix(resolved, backupBaseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("backup_path (via symlink) escapes the backup directory")
	}
	return resolved, nil
}

// handleBackupRestore reverses handleBackupRun: it extracts a previously
// created archive and restores its database dump and/or files. Before
// touching anything on disk for a files/full restore, it takes a fresh
// "pre-restore checkpoint" backup of the current state (product
// requirement: "Pre-restore checkpoints") — if that checkpoint fails, the
// restore is aborted rather than risking an unrecoverable overwrite.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	backupPathParam, _ := params["backup_path"].(string)
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	expectedSHA, _ := params["sha256"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}

	backupPath, err := validateBackupPath(backupPathParam)
	if err != nil {
		return "", err
	}

	if expectedSHA != "" {
		progress("verifying backup checksum")
		sum, err := sha256File(backupPath)
		if err != nil {
			return "", fmt.Errorf("checksum backup archive: %w", err)
		}
		if !strings.EqualFold(sum, expectedSHA) {
			return "", fmt.Errorf("backup archive checksum mismatch: refusing to restore a possibly corrupted or tampered backup")
		}
	}

	var checkpointPath string
	if scope == "files" || scope == "full" {
		progress("creating pre-restore checkpoint of current files")
		ckOut, err := handleBackupRun(ctx, map[string]any{"scope": "files", "site_root": siteRoot}, func(string) {})
		if err != nil {
			return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore: %w", err)
		}
		var ck backupResult
		if err := json.Unmarshal([]byte(ckOut), &ck); err == nil {
			checkpointPath = ck.Path
		}
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-xzf", backupPath, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract backup: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		progress("restoring database " + dbName)
		dumpFile, err := findExtractedFileWithSuffix(workDir, ".sql")
		if err != nil {
			return "", err
		}
		f, err := os.Open(dumpFile)
		if err != nil {
			return "", fmt.Errorf("open extracted dump: %w", err)
		}
		defer f.Close()

		cmd := exec.CommandContext(ctx, "mysql", dbName)
		cmd.Stdin = f
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("mysql restore: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}

	if scope == "files" || scope == "full" {
		progress("restoring files to " + siteRoot)
		srcDir, err := findExtractedSiteDir(workDir)
		if err != nil {
			return "", err
		}
		if err := replaceDirContents(ctx, srcDir, siteRoot); err != nil {
			return "", err
		}
		sysUser := filepath.Base(siteRoot)
		run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot)
	}

	res := restoreResult{Scope: scope, RestoredFrom: backupPath, CheckpointPath: checkpointPath, RestoredAt: time.Now().UTC()}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// findExtractedFileWithSuffix walks an extracted backup archive looking for
// the one file backup.run's db/full scope produces (a *.sql dump); its
// exact path inside the archive depends on the temp directory backup.run
// happened to use at creation time, so this searches rather than assuming
// a fixed layout.
func findExtractedFileWithSuffix(root, suffix string) (string, error) {
	var found string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(p, suffix) {
			found = p
		}
		return nil
	})
	if found == "" {
		return "", fmt.Errorf("backup archive does not contain a %s file", suffix)
	}
	return found, nil
}

// findExtractedSiteDir locates the single site directory backup.run
// archived (originally an absolute /home/sites/<system_user> path, so tar
// re-creates it under <extracted-root>/home/sites/<system_user>).
func findExtractedSiteDir(extractedRoot string) (string, error) {
	sitesDir := filepath.Join(extractedRoot, "home", "sites")
	entries, err := os.ReadDir(sitesDir)
	if err != nil {
		return "", fmt.Errorf("backup archive does not contain a site files snapshot: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			return filepath.Join(sitesDir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("backup archive does not contain a site files snapshot")
}

// replaceDirContents clears every entry directly inside dest and copies in
// everything from src, i.e. "make dest's contents match src's" without
// removing dest itself (its ownership/permissions/mount point are left
// alone) — used to restore a site's files without needing to detach and
// recreate the site's home directory.
func replaceDirContents(ctx context.Context, src, dest string) error {
	existing, err := os.ReadDir(dest)
	if err != nil {
		return fmt.Errorf("read restore target %s: %w", dest, err)
	}
	for _, e := range existing {
		if err := os.RemoveAll(filepath.Join(dest, e.Name())); err != nil {
			return fmt.Errorf("clear restore target: %w", err)
		}
	}
	if out, err := run(ctx, "cp", "-a", src+"/.", dest+"/"); err != nil {
		return fmt.Errorf("copy restored files: %w: %s", err, out)
	}
	return nil
}

func randSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing is effectively impossible on any
		// supported platform; falling back to the current time keeps
		// this a filename-uniqueness aid rather than a hard dependency.
		return fmt.Sprintf("%x", time.Now().UnixNano())
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
