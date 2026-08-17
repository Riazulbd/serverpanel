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

// backupManifest is written into every backup archive (as manifest.json)
// alongside its payload, so backup.restore never has to guess an archive's
// internal layout from the scope alone — it reads back exactly which
// member holds the DB dump and which holds the files payload. This is also
// what lets restore reject an archive that isn't actually one of ours (or
// predates manifest support) with a clear error instead of a confusing
// tar/mysql failure.
type backupManifest struct {
	Scope          string `json:"scope"`
	DBFile         string `json:"db_file,omitempty"`
	DBName         string `json:"db_name,omitempty"`
	FilesMember    string `json:"files_member,omitempty"`
	SiteRootOrigin string `json:"site_root_origin,omitempty"`
	CreatedAt      string `json:"created_at"`
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

	manifest := backupManifest{Scope: scope, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	// tarArgs accumulates alternating "-C dir member" groups so a single
	// tar invocation can pull members from more than one source directory:
	// the DB dump lives in workDir, but the files member is tarred
	// directly out of the site's own parent directory rather than copied
	// there first (cheaper, and avoids doubling disk usage for large
	// sites).
	var tarArgs []string

	if scope == "db" || scope == "full" {
		progress("dumping database " + dbName)
		manifest.DBFile = "database.sql"
		manifest.DBName = dbName
		dumpPath := filepath.Join(workDir, manifest.DBFile)
		out, err := run(ctx, "mysqldump", "--single-transaction", "--routines", "--events", dbName)
		if err != nil {
			return "", fmt.Errorf("mysqldump: %w: %s", err, out)
		}
		if err := os.WriteFile(dumpPath, []byte(out), 0600); err != nil {
			return "", fmt.Errorf("write dump: %w", err)
		}
		tarArgs = append(tarArgs, "-C", workDir, manifest.DBFile)
	}

	if scope == "files" || scope == "full" {
		progress("archiving files from " + siteRoot)
		manifest.FilesMember = filepath.Base(siteRoot)
		manifest.SiteRootOrigin = siteRoot
		tarArgs = append(tarArgs, "-C", filepath.Dir(siteRoot), manifest.FilesMember)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("build manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "manifest.json"), manifestBytes, 0600); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}
	tarArgs = append([]string{"-C", workDir, "manifest.json"}, tarArgs...)

	progress("compressing archive")
	args := append([]string{"-czf", outPath}, tarArgs...)
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
	Scope             string    `json:"scope"`
	RestoredDBName    string    `json:"restored_db_name,omitempty"`
	DBCheckpointPath  string    `json:"db_checkpoint_path,omitempty"`
	RestoredSiteRoot  string    `json:"restored_site_root,omitempty"`
	PreRestoreSiteDir string    `json:"pre_restore_site_dir,omitempty"`
	RestoredAt        time.Time `json:"restored_at"`
}

// handleBackupRestore restores a previously-created backup.run archive.
// Safety properties, in order:
//
//  1. The archive path is resolved to a real file strictly inside
//     backupBaseDir (resolveBackupPath) — never an arbitrary path a task's
//     params could otherwise point at.
//  2. A caller-supplied sha256 is mandatory and must match the archive's
//     actual checksum before anything is touched — this is what stops a
//     restore from ever running against a corrupted or tampered archive
//     (see docs/SECURITY.md "backup integrity").
//  3. Before overwriting a live database or site directory, the current
//     contents are checkpointed (DB: a fresh mysqldump; files: the
//     existing site directory is moved aside, never deleted) so a bad
//     restore is itself recoverable. Nothing this handler does is a
//     destructive delete of pre-existing customer data.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	archivePath, _ := params["path"].(string)
	expectedSHA, _ := params["sha256"].(string)
	targetDBName, _ := params["db_name"].(string)
	targetSiteRoot, _ := params["site_root"].(string)
	ownerUser, _ := params["owner_user"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	if expectedSHA == "" {
		return "", fmt.Errorf("sha256 is required: a restore must never proceed against an unverified archive")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(targetDBName) {
		return "", fmt.Errorf("invalid db_name %q", targetDBName)
	}
	if scope == "files" || scope == "full" {
		if !strings.HasPrefix(targetSiteRoot, "/home/sites/") {
			return "", fmt.Errorf("site_root must be a managed site home directory")
		}
		if !strings.HasPrefix(ownerUser, "site_") {
			return "", fmt.Errorf("invalid owner_user")
		}
	}

	realArchive, err := resolveBackupPath(backupBaseDir, archivePath)
	if err != nil {
		return "", err
	}

	progress("verifying backup archive integrity")
	actualSHA, err := sha256File(realArchive)
	if err != nil {
		return "", fmt.Errorf("checksum backup archive: %w", err)
	}
	if !strings.EqualFold(actualSHA, expectedSHA) {
		return "", fmt.Errorf("backup archive checksum mismatch: refusing to restore from a corrupted or tampered archive (expected %s, got %s)", expectedSHA, actualSHA)
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-xzf", realArchive, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract archive: %w: %s", err, out)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(workDir, "manifest.json"))
	if err != nil {
		return "", fmt.Errorf("archive has no manifest.json (not a ServerPanel backup): %w", err)
	}
	var manifest backupManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", fmt.Errorf("parse manifest: %w", err)
	}

	res := restoreResult{Scope: scope}

	if scope == "db" || scope == "full" {
		if manifest.DBFile == "" {
			return "", fmt.Errorf("archive does not contain a database dump (it was created with scope=%s)", manifest.Scope)
		}
		dumpPath := filepath.Join(workDir, manifest.DBFile)
		if _, err := os.Stat(dumpPath); err != nil {
			return "", fmt.Errorf("dump file missing from archive: %w", err)
		}

		checkpointPath, err := checkpointDatabaseIfExists(ctx, progress, targetDBName)
		if err != nil {
			return "", err
		}
		res.DBCheckpointPath = checkpointPath

		progress("restoring database " + targetDBName)
		if err := restoreDatabaseDump(ctx, targetDBName, dumpPath); err != nil {
			return "", fmt.Errorf("restore database: %w", err)
		}
		res.RestoredDBName = targetDBName
	}

	if scope == "files" || scope == "full" {
		if manifest.FilesMember == "" {
			return "", fmt.Errorf("archive does not contain a files payload (it was created with scope=%s)", manifest.Scope)
		}
		extractedDir := filepath.Join(workDir, manifest.FilesMember)
		info, err := os.Stat(extractedDir)
		if err != nil || !info.IsDir() {
			return "", fmt.Errorf("files payload missing from archive")
		}

		if _, err := os.Stat(targetSiteRoot); err == nil {
			progress("preserving current site contents before overwrite")
			stamp := time.Now().UTC().Format("20060102T150405Z")
			preRestoreDir := targetSiteRoot + ".pre-restore." + stamp
			if err := os.Rename(targetSiteRoot, preRestoreDir); err != nil {
				return "", fmt.Errorf("preserve existing site contents: %w", err)
			}
			res.PreRestoreSiteDir = preRestoreDir
		}

		progress("restoring files to " + targetSiteRoot)
		if err := os.MkdirAll(targetSiteRoot, 0750); err != nil {
			return "", fmt.Errorf("recreate site root: %w", err)
		}
		// "extractedDir/." (a literal path, not a shell glob — no shell is
		// involved in this exec.Command call) copies the directory's
		// contents into targetSiteRoot rather than nesting extractedDir's
		// own basename inside it.
		if out, err := run(ctx, "cp", "-a", extractedDir+"/.", targetSiteRoot+"/"); err != nil {
			return "", fmt.Errorf("copy restored files: %w: %s", err, out)
		}
		if out, err := run(ctx, "chown", "-R", ownerUser+":"+ownerUser, targetSiteRoot); err != nil {
			return "", fmt.Errorf("chown restored files: %w: %s", err, out)
		}
		res.RestoredSiteRoot = targetSiteRoot
	}

	res.RestoredAt = time.Now().UTC()
	out, _ := json.Marshal(res)
	return string(out), nil
}

// resolveBackupPath maps a caller-supplied archive path onto a real
// filesystem path guaranteed to stay inside baseDir, mirroring
// resolveScopedPath's approach in file.go: both the requested path and
// baseDir are resolved through EvalSymlinks so a symlink planted under
// baseDir that points elsewhere can't be used to restore from (or leak the
// contents of) a file outside the managed backup directory.
func resolveBackupPath(baseDir, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	realBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return "", fmt.Errorf("resolve backup directory: %w", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve archive path: %w", err)
	}
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", fmt.Errorf("backup archive not found: %w", err)
	}
	if realPath != realBase && !strings.HasPrefix(realPath, realBase+string(filepath.Separator)) {
		return "", fmt.Errorf("path must reference a file under the managed backup directory")
	}
	info, err := os.Stat(realPath)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("backup archive not found")
	}
	return realPath, nil
}

// checkpointDatabaseIfExists dumps dbName's current contents to a
// timestamped file under backupBaseDir before a restore overwrites it — but
// only if dbName currently exists; restoring into a brand new database has
// nothing to check-point. Returns "" (no error) when there was nothing to
// checkpoint.
func checkpointDatabaseIfExists(ctx context.Context, progress Progress, dbName string) (string, error) {
	db, err := mariaDBConn()
	if err != nil {
		return "", err
	}
	defer db.Close()

	var exists int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(1) FROM information_schema.schemata WHERE schema_name = ?", dbName).Scan(&exists); err != nil {
		return "", fmt.Errorf("check target database: %w", err)
	}
	if exists == 0 {
		return "", nil
	}

	progress("checkpointing current contents of " + dbName + " before restore")
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	checkpointPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-pre-restore-checkpoint-%s.sql", dbName, stamp))
	out, err := run(ctx, "mysqldump", "--single-transaction", "--routines", "--events", dbName)
	if err != nil {
		return "", fmt.Errorf("checkpoint dump: %w: %s", err, out)
	}
	if err := os.WriteFile(checkpointPath, []byte(out), 0600); err != nil {
		return "", fmt.Errorf("write checkpoint: %w", err)
	}
	return checkpointPath, nil
}

// restoreDatabaseDump loads a plain-SQL mysqldump file into dbName,
// creating the database first if it doesn't already exist (restoring a
// backup into a new database — e.g. as part of a clone — is a supported
// path, not just restoring in place). The dump is streamed into the mysql
// client's stdin rather than interpolated into a shell command, so this
// never constructs a shell string from file contents.
func restoreDatabaseDump(ctx context.Context, dbName, dumpPath string) error {
	db, err := mariaDBConn()
	if err != nil {
		return err
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", dbName)); err != nil {
		return fmt.Errorf("ensure target database exists: %w", err)
	}

	f, err := os.Open(dumpPath)
	if err != nil {
		return fmt.Errorf("open dump file: %w", err)
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, "mysql", dbName)
	cmd.Stdin = f
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql import: %w: %s", err, strings.TrimSpace(string(out)))
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
