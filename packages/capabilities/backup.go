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
// (JSON) — see apps/controlplane/backups.go handleRestoreBackup, which
// records PreRestoreCheckpoint as its own backup row so it shows up
// alongside ordinary backups rather than only existing as a file on disk.
type restoreResult struct {
	Scope                string        `json:"scope"`
	RestoredFrom         string        `json:"restored_from"`
	PreRestoreCheckpoint *backupResult `json:"pre_restore_checkpoint"`
	CompletedAt          time.Time     `json:"completed_at"`
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

	res, err := createBackupArchive(ctx, scope, siteRoot, dbName, "", progress)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// createBackupArchive is the shared implementation behind backup.run and
// the automatic pre-restore checkpoint backup.restore takes before
// overwriting anything live: same validation, same archive layout, same
// checksum — just parameterized by an optional label prefix so a
// checkpoint's filename is visibly distinct from an ordinary on-demand
// backup on disk.
func createBackupArchive(ctx context.Context, scope, siteRoot, dbName, labelPrefix string, progress Progress) (*backupResult, error) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return nil, fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	label := dbName
	if label == "" {
		label = filepath.Base(siteRoot)
	}
	if labelPrefix != "" {
		label = labelPrefix + "-" + label
	}
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s.tar.gz", label, scope, stamp))

	workDir, err := os.MkdirTemp("", "sp-backup-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workDir)

	var tarInputs []string

	if scope == "db" || scope == "full" {
		progress("dumping database " + dbName)
		dumpPath := filepath.Join(workDir, dbName+".sql")
		out, err := run(ctx, "mysqldump", "--single-transaction", "--routines", "--events", dbName)
		if err != nil {
			return nil, fmt.Errorf("mysqldump: %w: %s", err, out)
		}
		if err := os.WriteFile(dumpPath, []byte(out), 0600); err != nil {
			return nil, fmt.Errorf("write dump: %w", err)
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
		return nil, fmt.Errorf("tar: %w: %s", err, out)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return nil, fmt.Errorf("stat backup archive: %w", err)
	}
	sum, err := sha256File(outPath)
	if err != nil {
		return nil, fmt.Errorf("checksum backup archive: %w", err)
	}

	return &backupResult{Scope: scope, Path: outPath, SizeBytes: info.Size(), SHA256: sum, CreatedAt: time.Now().UTC()}, nil
}

// handleBackupRestore restores a previously created backup.run archive.
// Before touching anything live it: (1) requires the archive to be one
// this agent itself created (must live under backupBaseDir — no restoring
// an arbitrary path the control plane happens to send), (2) verifies the
// archive's checksum against the caller-supplied expected_sha256 so a
// tampered or corrupted archive is never applied, and (3) takes a fresh
// checkpoint backup of whatever is live right now, so a bad restore is
// itself always recoverable. Only after all three does it overwrite
// anything.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	archivePath, _ := params["archive_path"].(string)
	expectedSHA, _ := params["expected_sha256"].(string)

	if err := validateBackupScope(scope, siteRoot, dbName); err != nil {
		return "", err
	}
	if expectedSHA == "" {
		return "", fmt.Errorf("expected_sha256 is required")
	}

	cleanArchive := filepath.Clean(archivePath)
	if !strings.HasPrefix(cleanArchive, backupBaseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("archive_path must be a backup under %s", backupBaseDir)
	}
	if _, err := os.Stat(cleanArchive); err != nil {
		return "", fmt.Errorf("archive not found: %w", err)
	}

	progress("verifying archive checksum")
	actualSHA, err := sha256File(cleanArchive)
	if err != nil {
		return "", fmt.Errorf("checksum archive: %w", err)
	}
	if !strings.EqualFold(actualSHA, expectedSHA) {
		return "", fmt.Errorf("archive checksum mismatch: expected %s, got %s — refusing to restore a corrupted or tampered archive", expectedSHA, actualSHA)
	}

	progress("creating pre-restore checkpoint of current state")
	checkpoint, err := createBackupArchive(ctx, scope, siteRoot, dbName, "prerestore", progress)
	if err != nil {
		return "", fmt.Errorf("pre-restore checkpoint failed, refusing to proceed with restore: %w", err)
	}

	extractDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(extractDir)

	progress("extracting archive")
	if out, err := run(ctx, "tar", "-xzf", cleanArchive, "-C", extractDir); err != nil {
		return "", fmt.Errorf("extract archive: %w: %s", err, out)
	}

	if scope == "db" || scope == "full" {
		dumpFile, err := findFileByName(extractDir, dbName+".sql")
		if err != nil {
			return "", fmt.Errorf("locate database dump in archive: %w", err)
		}
		progress("restoring database " + dbName)
		if err := restoreDatabaseDump(ctx, dbName, dumpFile); err != nil {
			return "", fmt.Errorf("database restore failed, current state is unmodified except as noted, pre-restore checkpoint preserved at %s: %w", checkpoint.Path, err)
		}
	}

	if scope == "files" || scope == "full" {
		extractedRoot := filepath.Join(extractDir, strings.TrimPrefix(filepath.Clean(siteRoot), "/"))
		if info, err := os.Stat(extractedRoot); err != nil || !info.IsDir() {
			return "", fmt.Errorf("archive does not contain files for site_root %q", siteRoot)
		}
		progress("restoring files to " + siteRoot)
		if err := replaceDir(ctx, extractedRoot, siteRoot); err != nil {
			return "", fmt.Errorf("file restore failed, pre-restore checkpoint preserved at %s: %w", checkpoint.Path, err)
		}
	}

	res := restoreResult{Scope: scope, RestoredFrom: cleanArchive, PreRestoreCheckpoint: checkpoint, CompletedAt: time.Now().UTC()}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// findFileByName walks root looking for exactly one file named name. The
// dump file's archive path is not deterministic across backups (it was
// written under a randomly-named temp directory at backup time — see
// createBackupArchive's workDir), so restore locates it by name instead of
// assuming a fixed path; an archive containing more than one match is
// refused as ambiguous rather than guessed at.
func findFileByName(root, name string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == name {
			if found != "" {
				return fmt.Errorf("archive contains more than one %s", name)
			}
			found = path
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("%s not found in archive", name)
	}
	return found, nil
}

// restoreDatabaseDump imports a SQL dump via mysql's stdin, over the same
// local-socket connection db.go's handlers use — no shell, no
// interpolation of the dump's contents into a command line.
func restoreDatabaseDump(ctx context.Context, dbName, dumpPath string) error {
	f, err := os.Open(dumpPath)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, "mysql", dbName)
	cmd.Stdin = f
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql import: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// replaceDir swaps dst's contents for src's. Rename is attempted first
// (instant, works when both paths share a filesystem); since src lives
// under the OS temp directory and dst under /home/sites, those are not
// guaranteed to share a filesystem, so a copy-then-remove fallback exists.
// dst is only ever removed after the replacement content is fully staged
// at a temporary sibling path, so a failure partway through never leaves
// dst half-written.
func replaceDir(ctx context.Context, src, dst string) error {
	staged := dst + ".restoring"
	os.RemoveAll(staged)
	if err := os.Rename(src, staged); err != nil {
		if out, cpErr := run(ctx, "cp", "-a", src, staged); cpErr != nil {
			return fmt.Errorf("copy restored files into place: %w: %s", cpErr, out)
		}
	}
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("remove existing site directory: %w", err)
	}
	if err := os.Rename(staged, dst); err != nil {
		return fmt.Errorf("move restored files into place: %w", err)
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
