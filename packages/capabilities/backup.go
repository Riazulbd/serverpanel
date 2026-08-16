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

var backupBaseDir = "/var/backups/serverpanel"

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
	Scope            string    `json:"scope"`
	ArchivePath      string    `json:"archive_path"`
	ChecksumVerified bool      `json:"checksum_verified"`
	CheckpointPath   string    `json:"checkpoint_path,omitempty"`
	RestoredDBName   string    `json:"restored_db_name,omitempty"`
	RestoredSiteRoot string    `json:"restored_site_root,omitempty"`
	RestoredAt       time.Time `json:"restored_at"`
}

// handleBackupRestore is the counterpart to handleBackupRun: it restores a
// previously created archive (db dump, files, or both) into a target that
// is always named explicitly by the caller (restore_db_name /
// restore_site_root / restore_system_user) rather than inferred from the
// archive's original location — this is what makes "restore to a different
// server, or to a freshly re-provisioned site with a different system
// user" the same code path as "restore in place," per docs/OPERATIONS.md
// §Backup and restore.
//
// Unless skip_checkpoint is set, it takes a best-effort snapshot of
// whatever currently occupies the restore target (scoped the same way
// backup.run is) before making any destructive change, so a bad restore is
// itself recoverable.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	archivePath, _ := params["archive_path"].(string)
	expectedSHA, _ := params["expected_sha256"].(string)
	scope, _ := params["scope"].(string)
	restoreSiteRoot, _ := params["restore_site_root"].(string)
	restoreSystemUser, _ := params["restore_system_user"].(string)
	restoreDBName, _ := params["restore_db_name"].(string)
	skipCheckpoint, _ := params["skip_checkpoint"].(bool)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}

	cleanArchive := filepath.Clean(archivePath)
	if cleanArchive != backupBaseDir && !strings.HasPrefix(cleanArchive, backupBaseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("archive_path must be a file under %s", backupBaseDir)
	}
	if info, err := os.Stat(cleanArchive); err != nil || info.IsDir() {
		return "", fmt.Errorf("backup archive not found: %s", cleanArchive)
	}

	if scope == "files" || scope == "full" {
		if !strings.HasPrefix(restoreSiteRoot, "/home/sites/") {
			return "", fmt.Errorf("restore_site_root must be a managed site home directory")
		}
		if !strings.HasPrefix(restoreSystemUser, "site_") {
			return "", fmt.Errorf("restore_system_user must be a managed site's system user")
		}
	}
	if scope == "db" || scope == "full" {
		if !identifierRe.MatchString(restoreDBName) {
			return "", fmt.Errorf("invalid restore_db_name %q", restoreDBName)
		}
	}

	checksumVerified := false
	if expectedSHA != "" {
		progress("verifying archive checksum")
		sum, err := sha256File(cleanArchive)
		if err != nil {
			return "", fmt.Errorf("checksum archive: %w", err)
		}
		if !strings.EqualFold(sum, expectedSHA) {
			return "", fmt.Errorf("archive checksum mismatch: got %s, want %s — refusing to restore a possibly corrupt or tampered backup", sum, expectedSHA)
		}
		checksumVerified = true
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-xzf", cleanArchive, "-C", workDir); err != nil {
		return "", fmt.Errorf("tar extract: %w: %s", err, out)
	}

	var checkpointPath string
	if !skipCheckpoint {
		ckpt, err := createPreRestoreCheckpoint(ctx, scope, restoreSiteRoot, restoreDBName, progress)
		if err != nil {
			return "", fmt.Errorf("pre-restore checkpoint: %w", err)
		}
		if ckpt != nil {
			checkpointPath = ckpt.Path
		}
	}

	if scope == "db" || scope == "full" {
		sqlPath, err := findSQLDump(workDir)
		if err != nil {
			return "", err
		}
		progress("restoring database into " + restoreDBName)
		if out, err := runWithStdinFile(ctx, sqlPath, "mysql", restoreDBName); err != nil {
			return "", fmt.Errorf("mysql restore: %w: %s", err, out)
		}
	}

	if scope == "files" || scope == "full" {
		srcDir, err := findFilesRoot(workDir)
		if err != nil {
			return "", err
		}
		progress("restoring files to " + restoreSiteRoot)
		if err := os.MkdirAll(restoreSiteRoot, 0750); err != nil {
			return "", fmt.Errorf("create restore target: %w", err)
		}
		// "srcDir/." (not "srcDir") copies the *contents* of srcDir into an
		// already-existing restoreSiteRoot rather than nesting srcDir's own
		// basename inside it; cp interprets the trailing "/." itself, so
		// this is still a fixed, literal argv element, not shell globbing.
		if out, err := run(ctx, "cp", "-a", srcDir+"/.", restoreSiteRoot); err != nil {
			return "", fmt.Errorf("copy restored files: %w: %s", err, out)
		}
		if out, err := run(ctx, "chown", "-R", restoreSystemUser+":"+restoreSystemUser, restoreSiteRoot); err != nil {
			return "", fmt.Errorf("chown restored files: %w: %s", err, out)
		}
	}

	res := restoreResult{
		Scope:            scope,
		ArchivePath:      cleanArchive,
		ChecksumVerified: checksumVerified,
		CheckpointPath:   checkpointPath,
		RestoredAt:       time.Now().UTC(),
	}
	if scope == "db" || scope == "full" {
		res.RestoredDBName = restoreDBName
	}
	if scope == "files" || scope == "full" {
		res.RestoredSiteRoot = restoreSiteRoot
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// createPreRestoreCheckpoint snapshots whatever currently exists at the
// restore target before a destructive restore overwrites it — best-effort:
// a fresh restore target (new site, new database) legitimately has nothing
// to snapshot yet, which is not an error, just a no-op checkpoint.
func createPreRestoreCheckpoint(ctx context.Context, scope, siteRoot, dbName string, progress Progress) (*backupResult, error) {
	dbExists := false
	if scope == "db" || scope == "full" {
		if out, err := run(ctx, "mysql", "-N", "-e",
			fmt.Sprintf("SHOW DATABASES LIKE '%s'", dbName)); err == nil && strings.TrimSpace(out) == dbName {
			dbExists = true
		}
	}
	siteRootExists := false
	if scope == "files" || scope == "full" {
		if info, err := os.Stat(siteRoot); err == nil && info.IsDir() {
			entries, _ := os.ReadDir(siteRoot)
			siteRootExists = len(entries) > 0
		}
	}

	checkpointScope := ""
	switch {
	case (scope == "full" && dbExists && siteRootExists):
		checkpointScope = "full"
	case (scope == "db" || scope == "full") && dbExists:
		checkpointScope = "db"
	case (scope == "files" || scope == "full") && siteRootExists:
		checkpointScope = "files"
	default:
		progress("pre-restore checkpoint skipped: nothing exists yet at the restore target")
		return nil, nil
	}

	progress("creating pre-restore checkpoint (" + checkpointScope + ")")
	out, err := handleBackupRun(ctx, map[string]any{
		"scope":     checkpointScope,
		"site_root": siteRoot,
		"db_name":   dbName,
	}, func(string) {})
	if err != nil {
		return nil, err
	}
	var res backupResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		return nil, fmt.Errorf("parse checkpoint result: %w", err)
	}
	return &res, nil
}

// findSQLDump locates the single .sql file produced by handleBackupRun
// inside an extracted archive. More than one match is treated as an error
// rather than guessed at, since silently picking one could restore the
// wrong database.
func findSQLDump(workDir string) (string, error) {
	var matches []string
	err := filepath.WalkDir(workDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".sql") {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("scan extracted archive: %w", err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("archive does not contain a database dump (no .sql file) — check scope matches how the backup was created")
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("archive contains %d .sql files, expected exactly one", len(matches))
	}
	return matches[0], nil
}

// findFilesRoot locates the single site directory produced by
// handleBackupRun's "files"/"full" scope: tar stores an absolute path
// (e.g. /home/sites/site_example) with its leading "/" stripped, so it
// extracts under workDir/home/sites/<name>.
func findFilesRoot(workDir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(workDir, "home", "sites", "*"))
	if err != nil {
		return "", fmt.Errorf("scan extracted archive: %w", err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("archive does not contain a files backup (no home/sites/* entry) — check scope matches how the backup was created")
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("archive contains %d site directories, expected exactly one", len(matches))
	}
	return matches[0], nil
}
