package capabilities

import (
	"context"
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

// restoreResult is what backup.restore returns as its TaskEvent detail
// (JSON). CheckpointPath/CheckpointSHA256 are populated whenever a
// pre-restore checkpoint of the current file state was taken (the default),
// so the caller always has a durable, checksummed way back if the restored
// content turns out to be wrong.
type restoreResult struct {
	Scope            string    `json:"scope"`
	RestoredPath     string    `json:"restored_path,omitempty"`
	RestoredDB       string    `json:"restored_db,omitempty"`
	CheckpointPath   string    `json:"checkpoint_path,omitempty"`
	CheckpointSHA256 string    `json:"checkpoint_sha256,omitempty"`
	CompletedAt      time.Time `json:"completed_at"`
}

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

	res, err := createBackupArchive(ctx, progress, scope, siteRoot, dbName, "")
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// createBackupArchive does the actual dump/tar/checksum work shared by
// handleBackupRun and the pre-restore checkpoint handleBackupRestore takes
// of the current state before it overwrites anything. labelSuffix
// distinguishes a checkpoint's filename from a regular backup's (e.g.
// "...-prerestore-...") so the two are never confused when listing
// backupBaseDir.
func createBackupArchive(ctx context.Context, progress Progress, scope, siteRoot, dbName, labelSuffix string) (backupResult, error) {
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

// handleBackupRestore restores a previously created backup.run archive.
// Safety properties, in order:
//  1. backup_path is confined to backupBaseDir (never a caller-chosen
//     filesystem path) — this agent only ever restores from an archive it
//     itself could have created.
//  2. if expected_sha256 is given (the control plane always supplies the
//     checksum it recorded when the backup was made), the archive's
//     current on-disk checksum must match before anything is touched.
//  3. unless skip_checkpoint is set, a fresh checkpoint backup of the
//     current file state is taken first, so a bad restore is itself
//     recoverable.
//  4. files are staged into a sibling temp directory and only swapped into
//     place with the previous directory moved aside (not deleted) until the
//     swap succeeds — a failure partway through never leaves the site
//     missing.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	backupPath, _ := params["backup_path"].(string)
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	expectedSHA256, _ := params["expected_sha256"].(string)
	skipCheckpoint, _ := params["skip_checkpoint"].(bool)

	if err := validateBackupScopeParams(scope, siteRoot, dbName); err != nil {
		return "", err
	}

	cleanPath := filepath.Clean(backupPath)
	if !strings.HasPrefix(cleanPath, backupBaseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("backup_path must be under %s", backupBaseDir)
	}
	info, err := os.Stat(cleanPath)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("backup archive not found: %s", cleanPath)
	}

	if expectedSHA256 != "" {
		progress("verifying backup checksum")
		sum, err := sha256File(cleanPath)
		if err != nil {
			return "", fmt.Errorf("checksum backup archive: %w", err)
		}
		if !strings.EqualFold(sum, expectedSHA256) {
			return "", fmt.Errorf("backup checksum mismatch: expected %s, got %s — refusing to restore a possibly corrupted or tampered archive", expectedSHA256, sum)
		}
	}

	res := restoreResult{Scope: scope}

	if (scope == "files" || scope == "full") && !skipCheckpoint {
		progress("creating pre-restore checkpoint of current state")
		cp, err := createBackupArchive(ctx, progress, scope, siteRoot, dbName, "prerestore")
		if err != nil {
			return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore: %w", err)
		}
		res.CheckpointPath = cp.Path
		res.CheckpointSHA256 = cp.SHA256
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-xzf", cleanPath, "-C", workDir); err != nil {
		return "", fmt.Errorf("tar extract: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		dumpPath, err := findFileByName(workDir, dbName+".sql")
		if err != nil {
			return "", fmt.Errorf("locate database dump in archive: %w", err)
		}
		progress("restoring database " + dbName)
		if err := restoreDatabaseDump(ctx, dbName, dumpPath); err != nil {
			return "", err
		}
		res.RestoredDB = dbName
	}

	if scope == "files" || scope == "full" {
		extractedRoot := filepath.Join(workDir, strings.TrimPrefix(siteRoot, "/"))
		if _, err := os.Stat(extractedRoot); err != nil {
			return "", fmt.Errorf("archive does not contain expected path %s: %w", siteRoot, err)
		}
		progress("swapping in restored files for " + siteRoot)
		if err := atomicSwapDir(ctx, extractedRoot, siteRoot); err != nil {
			return "", fmt.Errorf("restore files: %w", err)
		}
		res.RestoredPath = siteRoot
	}

	res.CompletedAt = time.Now().UTC()
	out, _ := json.Marshal(res)
	return string(out), nil
}

// restoreDatabaseDump pipes a .sql dump into mysql on stdin. This is kept
// separate from the run() helper (packages/capabilities/exec_helpers.go)
// because run() only ever returns CombinedOutput and has no stdin support;
// dbName has already been validated against identifierRe by the caller, and
// nothing else caller-supplied reaches this argv.
func restoreDatabaseDump(ctx context.Context, dbName, dumpPath string) error {
	f, err := os.Open(dumpPath)
	if err != nil {
		return fmt.Errorf("open database dump: %w", err)
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, "mysql", dbName)
	cmd.Stdin = f
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql restore: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// findFileByName walks root looking for the first regular file named name.
// Used to locate a database dump inside an extracted backup archive without
// depending on the workDir path the original backup happened to use (it's a
// fresh os.MkdirTemp path every time, on both the backup and restore side).
func findFileByName(root, name string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if found != "" {
			return filepath.SkipAll
		}
		if !d.IsDir() && d.Name() == name {
			found = path
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no file named %q found in archive", name)
	}
	return found, nil
}

// atomicSwapDir stages newDir's contents next to target (via `cp -a`, so it
// works even when newDir and target are on different filesystems — e.g.
// newDir under the OS temp dir, target under /home/sites), then uses two
// same-directory os.Rename calls to swap it into place. The previous target
// is moved aside rather than deleted outright, and if the final rename
// fails, the original is moved back — a failed restore should never leave a
// site's directory missing.
func atomicSwapDir(ctx context.Context, newDir, target string) error {
	ts := time.Now().UTC().Format("20060102T150405Z")
	staging := target + ".restoring-" + ts

	if out, err := run(ctx, "cp", "-a", newDir, staging); err != nil {
		return fmt.Errorf("stage restored files: %w: %s", err, out)
	}

	var movedAside string
	if _, err := os.Stat(target); err == nil {
		movedAside = target + ".pre-restore-" + ts
		if err := os.Rename(target, movedAside); err != nil {
			os.RemoveAll(staging)
			return fmt.Errorf("move aside existing directory: %w", err)
		}
	} else if !os.IsNotExist(err) {
		os.RemoveAll(staging)
		return err
	}

	if err := os.Rename(staging, target); err != nil {
		if movedAside != "" {
			os.Rename(movedAside, target) // best-effort rollback so the site is never left missing
		}
		return fmt.Errorf("move restored directory into place (rolled back if possible): %w", err)
	}

	if movedAside != "" {
		// The pre-restore checkpoint archive already captured this state
		// durably; don't also leave a second on-disk copy behind.
		os.RemoveAll(movedAside)
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
