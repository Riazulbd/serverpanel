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
	// two backups of the same site/database never collide on filename —
	// including a pre-restore checkpoint racing the backup it's about to
	// restore from, which without this could silently overwrite the very
	// archive backup.restore is reading (caught by
	// TestHandleBackupRunThenRestoreFilesRoundTrip during development).
	suffix, err := randHex(4)
	if err != nil {
		return "", fmt.Errorf("generate backup filename suffix: %w", err)
	}
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s-%s.tar.gz", label, scope, stamp, suffix))

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
	Scope               string    `json:"scope"`
	ArchivePath         string    `json:"archive_path"`
	CheckpointPath      string    `json:"checkpoint_path"`
	CheckpointSizeBytes int64     `json:"checkpoint_size_bytes"`
	CheckpointSHA256    string    `json:"checkpoint_sha256"`
	RestoredAt          time.Time `json:"restored_at"`
}

// handleBackupRestore restores a backup archive previously produced by
// handleBackupRun. It never restores blind: the caller-supplied
// expected_sha256 (normally the checksum recorded on the control plane at
// backup time) must match the archive on disk before anything is touched,
// and a fresh "pre-restore checkpoint" backup of the current state is taken
// before any destructive change — so a bad restore is itself recoverable by
// restoring the checkpoint, matching the "pre-restore checkpoints" and
// "failure recovery" requirements in docs/product-plan.md.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	archivePath, _ := params["archive_path"].(string)
	expectedSHA256, _ := params["expected_sha256"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	ownerUser, _ := params["owner_user"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	// archivePath must be a backup this agent itself produced, never an
	// arbitrary caller-supplied filesystem path — this is the same "no
	// escaping a fixed, agent-owned directory" pattern used by the file
	// manager's resolveScopedPath.
	cleanArchive := filepath.Clean(archivePath)
	if !strings.HasPrefix(cleanArchive, backupBaseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("archive_path must be a backup previously created under %s", backupBaseDir)
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "files" || scope == "full") && !identifierRe.MatchString(ownerUser) {
		return "", fmt.Errorf("invalid owner_user %q", ownerUser)
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}
	if len(expectedSHA256) != 64 {
		return "", fmt.Errorf("expected_sha256 (64 hex chars) is required — the checksum recorded when this backup was created, so a modified or corrupt archive is never silently restored")
	}

	if _, err := os.Stat(cleanArchive); err != nil {
		return "", fmt.Errorf("backup archive not found: %w", err)
	}

	progress("verifying archive checksum")
	sum, err := sha256File(cleanArchive)
	if err != nil {
		return "", fmt.Errorf("checksum archive: %w", err)
	}
	if !strings.EqualFold(sum, expectedSHA256) {
		return "", fmt.Errorf("archive checksum %s does not match expected %s — refusing to restore from a modified or corrupt archive", sum, expectedSHA256)
	}

	progress("listing archive contents")
	listing, err := run(ctx, "tar", "-tzf", cleanArchive)
	if err != nil {
		return "", fmt.Errorf("read archive contents: %w: %s", err, listing)
	}
	entries := strings.Split(listing, "\n")

	var sqlEntry string
	if scope == "db" || scope == "full" {
		suffix := "/" + dbName + ".sql"
		for _, e := range entries {
			if e == dbName+".sql" || strings.HasSuffix(e, suffix) {
				sqlEntry = e
				break
			}
		}
		if sqlEntry == "" {
			return "", fmt.Errorf("archive does not contain a %s.sql dump — it may not be a %q-scope backup for this database", dbName, scope)
		}
	}
	if scope == "files" || scope == "full" {
		relSiteRoot := strings.TrimPrefix(siteRoot, "/")
		found := false
		for _, e := range entries {
			if e == relSiteRoot || strings.HasPrefix(e, relSiteRoot+"/") {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("archive does not contain files under %s — it may not be a %q-scope backup for this site", siteRoot, scope)
		}
	}

	// Pre-restore checkpoint: snapshot current state under the same scope
	// before changing anything. If this fails, the restore is aborted
	// before a single file or database row has been touched.
	progress("creating pre-restore checkpoint of current state")
	checkpointJSON, err := handleBackupRun(ctx, map[string]any{
		"scope": scope, "site_root": siteRoot, "db_name": dbName,
	}, func(string) {})
	if err != nil {
		return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore before any changes: %w", err)
	}
	var checkpoint backupResult
	json.Unmarshal([]byte(checkpointJSON), &checkpoint)

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting archive")
	if out, err := run(ctx, "tar", "-xzf", cleanArchive, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract archive: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		progress("recreating database " + dbName + " if needed")
		if err := ensureDatabaseExists(ctx, dbName); err != nil {
			return "", fmt.Errorf("ensure target database exists: %w", err)
		}
		progress("importing database dump into " + dbName)
		dumpPath := filepath.Join(workDir, sqlEntry)
		if out, err := runWithStdinFile(ctx, dumpPath, "mysql", dbName); err != nil {
			return "", fmt.Errorf("import database dump: %w: %s", err, out)
		}
	}

	if scope == "files" || scope == "full" {
		progress("restoring files to " + siteRoot)
		extractedRoot := filepath.Join(workDir, siteRoot)
		if _, err := os.Stat(extractedRoot); err != nil {
			return "", fmt.Errorf("extracted archive is missing expected site root %s: %w", extractedRoot, err)
		}
		if err := os.MkdirAll(siteRoot, 0750); err != nil {
			return "", fmt.Errorf("prepare site root: %w", err)
		}
		// rsync-free copy: tar the extracted subtree back out and into
		// place, preserving permissions/symlinks without adding a new
		// external dependency (rsync is not installed by stack.install).
		if out, err := run(ctx, "cp", "-a", "-T", extractedRoot, siteRoot); err != nil {
			return "", fmt.Errorf("copy restored files into place: %w: %s", err, out)
		}
		if out, err := run(ctx, "chown", "-R", ownerUser+":"+ownerUser, siteRoot); err != nil {
			return "", fmt.Errorf("restore file ownership: %w: %s", err, out)
		}
	}

	res := restoreResult{
		Scope: scope, ArchivePath: cleanArchive,
		CheckpointPath: checkpoint.Path, CheckpointSizeBytes: checkpoint.SizeBytes, CheckpointSHA256: checkpoint.SHA256,
		RestoredAt: time.Now().UTC(),
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
