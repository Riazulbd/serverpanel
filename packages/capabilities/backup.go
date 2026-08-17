package capabilities

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	if err := validateBackupScope(scope, siteRoot, dbName); err != nil {
		return "", err
	}

	res, err := performBackup(ctx, scope, siteRoot, dbName, "", progress)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// handleBackupRestore restores a previously created backup archive.
// Restoring is one of the highest-blast-radius operations the agent can
// perform, so it is deliberately more defensive than any other capability:
//
//  1. The archive path is required to be one this agent itself wrote (under
//     backupBaseDir), never an arbitrary caller-supplied filesystem path.
//  2. The caller must supply the checksum recorded at backup time
//     (expected_sha256, e.g. what the control plane stored in its backups
//     table) and restore refuses to proceed if the archive's actual
//     checksum doesn't match — this catches both accidental corruption and
//     a swapped/tampered archive before anything is touched.
//  3. Before any destructive step, a fresh "pre-restore checkpoint" backup
//     of the current live state is taken (reusing performBackup), so a
//     restore that turns out to be a mistake is itself recoverable. If the
//     checkpoint fails, the restore aborts before touching anything.
//  4. The archive is extracted to a scratch directory first and validated
//     (dump/site files located) before anything under the real db/site
//     path is modified.
//
// Known limitation (documented rather than silently assumed): file restore
// overlays the archived tree onto the live site directory (create/overwrite
// semantics) rather than first deleting the live directory outright, so
// files created after the backup was taken and not present in the archive
// are left in place, not removed. This trades "bit-for-bit identical to the
// backup" for "never blindly recursive-delete a customer's live site
// directory as a side effect of restore" — consistent with the project's
// disk-cleanup safety stance in docs/product-plan.md.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	backupPath, _ := params["backup_path"].(string)
	expectedSHA, _ := params["expected_sha256"].(string)

	if err := validateBackupScope(scope, siteRoot, dbName); err != nil {
		return "", err
	}
	if expectedSHA == "" {
		return "", fmt.Errorf("expected_sha256 is required: restore refuses to run against an unverified archive")
	}

	cleanPath := filepath.Clean(backupPath)
	if !strings.HasPrefix(cleanPath, backupBaseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("backup_path must be a backup archive under %s", backupBaseDir)
	}
	if info, err := os.Stat(cleanPath); err != nil || info.IsDir() {
		return "", fmt.Errorf("backup archive not found: %s", cleanPath)
	}

	progress("verifying backup archive integrity")
	actualSHA, err := sha256File(cleanPath)
	if err != nil {
		return "", fmt.Errorf("checksum backup archive: %w", err)
	}
	if actualSHA != expectedSHA {
		return "", fmt.Errorf("backup archive checksum mismatch (expected %s, got %s) — refusing to restore a corrupted or tampered archive", expectedSHA, actualSHA)
	}

	progress("creating pre-restore checkpoint of current state")
	checkpoint, err := performBackup(ctx, scope, siteRoot, dbName, "prerestore", progress)
	if err != nil {
		return "", fmt.Errorf("pre-restore checkpoint failed, aborting restore before touching anything: %w", err)
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if out, err := run(ctx, "tar", "-xzf", cleanPath, "-C", workDir); err != nil {
		return "", fmt.Errorf("extract archive: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		dumpPath, err := findFileBySuffix(workDir, string(filepath.Separator)+dbName+".sql")
		if err != nil {
			return "", fmt.Errorf("database dump for %q not found in archive: %w", dbName, err)
		}
		progress("restoring database " + dbName)
		f, err := os.Open(dumpPath)
		if err != nil {
			return "", fmt.Errorf("open dump: %w", err)
		}
		cmd := exec.CommandContext(ctx, "mysql", dbName)
		cmd.Stdin = f
		out, runErr := cmd.CombinedOutput()
		f.Close()
		if runErr != nil {
			return "", fmt.Errorf("mysql restore: %w: %s", runErr, strings.TrimSpace(string(out)))
		}
	}

	if scope == "files" || scope == "full" {
		// The archive was created with siteRoot's absolute path as a tar
		// input, so tar stores (and extracts) it without its leading "/" —
		// the extracted tree lands at workDir+siteRoot.
		extractedSiteRoot := filepath.Join(workDir, siteRoot)
		if info, err := os.Stat(extractedSiteRoot); err != nil || !info.IsDir() {
			return "", fmt.Errorf("site files not found in archive at the expected path")
		}
		progress("restoring files to " + siteRoot)
		if out, err := run(ctx, "cp", "-a", extractedSiteRoot+"/.", siteRoot+"/"); err != nil {
			return "", fmt.Errorf("restore files: %w: %s", err, out)
		}
		sysUser := filepath.Base(siteRoot)
		run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot)
	}

	res := struct {
		Scope                string       `json:"scope"`
		RestoredFrom         string       `json:"restored_from"`
		PreRestoreCheckpoint backupResult `json:"pre_restore_checkpoint"`
		RestoredAt           time.Time    `json:"restored_at"`
	}{Scope: scope, RestoredFrom: cleanPath, PreRestoreCheckpoint: checkpoint, RestoredAt: time.Now().UTC()}
	out, _ := json.Marshal(res)
	return string(out), nil
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

// performBackup does the actual archive creation shared by handleBackupRun
// (labelSuffix "") and handleBackupRestore's pre-restore checkpoint
// (labelSuffix "prerestore"). labelSuffix only affects the output filename,
// never res.Scope, so callers comparing scope values see the real scope.
func performBackup(ctx context.Context, scope, siteRoot, dbName, labelSuffix string, progress Progress) (backupResult, error) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return backupResult{}, fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	label := dbName
	if label == "" {
		label = filepath.Base(siteRoot)
	}
	scopeTag := scope
	if labelSuffix != "" {
		scopeTag = labelSuffix + "-" + scope
	}
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s.tar.gz", label, scopeTag, stamp))

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

var errFoundFile = errors.New("found")

// findFileBySuffix locates the first regular file under root whose path
// ends with suffix (e.g. "/mydb.sql"), used to find a database dump inside
// an extracted, restructured archive without assuming its exact temp-dir
// prefix from backup time.
func findFileBySuffix(root, suffix string) (string, error) {
	var found string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.IsDir() && strings.HasSuffix(path, suffix) {
			found = path
			return errFoundFile
		}
		return nil
	})
	if err != nil && !errors.Is(err, errFoundFile) {
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
