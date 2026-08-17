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

// randHex returns n random bytes hex-encoded, used only to make generated
// filenames collision-proof — never used for anything security-sensitive
// (tokens/keys use their own dedicated random generation elsewhere).
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing is effectively unrecoverable on any real
		// system; fall back to the timestamp alone rather than panicking.
		return ""
	}
	return hex.EncodeToString(b)
}

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
	// A random suffix (not just the second-precision timestamp) keeps two
	// backups of the same site+scope from ever colliding on the same
	// filename — this matters in particular for backup.restore's
	// pre-restore checkpoint, which runs a backup.run of the same
	// label+scope that's about to be restored, easily within the same
	// second as a prior backup.
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

type restoreResult struct {
	Scope            string    `json:"scope"`
	RestoredFrom     string    `json:"restored_from"`
	CheckpointDetail string    `json:"checkpoint_detail"`
	RestoredAt       time.Time `json:"restored_at"`
}

// handleBackupRestore restores a backup archive previously created by
// backup.run. It never trusts backup_path as an arbitrary filesystem
// location (it must live under backupBaseDir, same as backup.run only ever
// writes there), and it never overwrites live data before first taking a
// fresh "pre-restore checkpoint" backup of the current state — so a bad
// restore (wrong archive, corrupted dump) is itself always recoverable
// rather than a one-way door. This mirrors backup.run's own validation
// approach, per docs/OPERATIONS.md §3.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	backupPath, _ := params["backup_path"].(string)
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	expectedSHA, _ := params["sha256"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	realBackupBase, err := filepath.EvalSymlinks(backupBaseDir)
	if err != nil {
		return "", fmt.Errorf("resolve backup directory: %w", err)
	}
	cleanedPath := filepath.Clean(backupPath)
	if !strings.HasPrefix(cleanedPath, realBackupBase+string(filepath.Separator)) {
		return "", fmt.Errorf("backup_path must be a managed backup archive under %s", backupBaseDir)
	}
	info, err := os.Stat(cleanedPath)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("backup archive not found: %s", backupPath)
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}

	if expectedSHA != "" {
		progress("verifying backup archive checksum")
		sum, err := sha256File(cleanedPath)
		if err != nil {
			return "", fmt.Errorf("checksum backup archive: %w", err)
		}
		if !strings.EqualFold(sum, expectedSHA) {
			return "", fmt.Errorf("backup archive checksum mismatch: refusing to restore a corrupted or tampered archive")
		}
	}

	// Pre-restore checkpoint: take a fresh backup of whatever is live right
	// now, before touching it. If this step fails, abort — restoring on top
	// of data we couldn't first save a copy of is exactly the unrecoverable
	// scenario this exists to prevent.
	progress("creating pre-restore checkpoint of current state")
	checkpointDetail, err := handleBackupRun(ctx, map[string]any{
		"scope": scope, "site_root": siteRoot, "db_name": dbName,
	}, func(string) {})
	if err != nil {
		return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore to avoid unrecoverable data loss: %w", err)
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-xzf", cleanedPath, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract backup archive: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		dumpPath, err := findFileWithSuffix(workDir, dbName+".sql")
		if err != nil {
			return "", fmt.Errorf("database dump for %q not found inside the backup archive: %w", dbName, err)
		}
		progress("restoring database " + dbName)
		f, err := os.Open(dumpPath)
		if err != nil {
			return "", fmt.Errorf("open extracted dump: %w", err)
		}
		out, err := runWithStdin(ctx, f, "mysql", dbName)
		f.Close()
		if err != nil {
			return "", fmt.Errorf("restore database: %w: %s", err, out)
		}
	}

	if scope == "files" || scope == "full" {
		extractedRoot := filepath.Join(workDir, strings.TrimPrefix(siteRoot, "/"))
		if info, err := os.Stat(extractedRoot); err != nil || !info.IsDir() {
			return "", fmt.Errorf("site files for %q not found inside the backup archive", siteRoot)
		}
		progress("replacing live files at " + siteRoot)
		// Clear the live directory's contents (not the directory itself, so
		// its ownership/mode survive) before copying the restored tree back
		// in — the pre-restore checkpoint above is what makes this safe.
		entries, err := os.ReadDir(siteRoot)
		if err != nil {
			return "", fmt.Errorf("read live site root: %w", err)
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(siteRoot, e.Name())); err != nil {
				return "", fmt.Errorf("clear live site root: %w", err)
			}
		}
		if out, err := run(ctx, "cp", "-a", extractedRoot+"/.", siteRoot+"/"); err != nil {
			return "", fmt.Errorf("copy restored files into place: %w: %s", err, out)
		}
	}

	res := restoreResult{Scope: scope, RestoredFrom: cleanedPath, CheckpointDetail: checkpointDetail, RestoredAt: time.Now().UTC()}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// findFileWithSuffix walks root looking for a file whose name ends in
// suffix, used to locate a restored SQL dump without depending on the exact
// (randomly-named) temp directory backup.run happened to use when the
// archive was created.
func findFileWithSuffix(root, suffix string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), suffix) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no file matching %q found in archive", suffix)
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
