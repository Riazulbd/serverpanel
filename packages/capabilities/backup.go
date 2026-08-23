package capabilities

import (
	"archive/tar"
	"compress/gzip"
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

// backupBaseDir is a var (not const) so tests can point it at a temp
// directory instead of the real system path.
var backupBaseDir = "/var/backups/serverpanel"

// maxRestoreExtractBytes bounds the total decompressed size handleBackupRestore
// will write to disk while extracting an archive, which is what stands
// between "restore a backup" and "a crafted or corrupted archive can exhaust
// disk via a decompression bomb."
const maxRestoreExtractBytes = 20 << 30 // 20GB

type backupResult struct {
	Scope     string    `json:"scope"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

type restoreResult struct {
	Scope       string `json:"scope"`
	ArchivePath string `json:"archive_path"`
	// Checkpoints are pre-restore safety backups taken (of the current, live
	// state) immediately before anything destructive happened, so a bad
	// restore is always recoverable rather than a one-way trip.
	Checkpoints []string  `json:"checkpoints"`
	RestoredAt  time.Time `json:"restored_at"`
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
	if (scope == "db" || scope == "full") && !IdentifierRe.MatchString(dbName) {
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

// handleBackupRestore restores a previously created backup.run archive.
// Design goals, all load-bearing for a root-equivalent operation like this:
//
//   - archive_path must resolve to a file directly inside backupBaseDir (the
//     only place backup.run ever writes to) — restore can never be pointed
//     at an arbitrary path on the host.
//   - if the caller supplies expected_sha256 (the checksum backup.run
//     originally returned), it is verified before any extraction happens.
//   - the archive is extracted with Go's archive/tar directly (never by
//     shelling out to `tar`), so every entry's path is validated to stay
//     inside a private temp directory before anything is written — this is
//     what defeats a "../../etc/cron.d/evil" entry planted in a tampered or
//     malicious archive. Only regular files and directories are extracted;
//     symlinks/hardlinks/devices inside the archive are rejected outright.
//   - immediately before doing anything destructive to the live database or
//     site files, a fresh checkpoint backup of the CURRENT state is taken
//     via handleBackupRun and its path is returned in the result — a bad
//     restore is always recoverable from that checkpoint, not a one-way
//     trip.
func handleBackupRestore(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	archivePath, _ := params["archive_path"].(string)
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)
	expectedSHA, _ := params["expected_sha256"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}

	cleanPath := filepath.Clean(archivePath)
	cleanBase := filepath.Clean(backupBaseDir)
	if filepath.Dir(cleanPath) != cleanBase {
		return "", fmt.Errorf("archive_path must be a backup file directly under %s", backupBaseDir)
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return "", fmt.Errorf("stat archive: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("archive_path is not a regular file")
	}

	if scope == "files" || scope == "full" {
		if !strings.HasPrefix(siteRoot, "/home/sites/") {
			return "", fmt.Errorf("site_root must be a managed site home directory")
		}
	}
	if scope == "db" || scope == "full" {
		if !IdentifierRe.MatchString(dbName) {
			return "", fmt.Errorf("invalid db_name %q", dbName)
		}
	}

	if expectedSHA != "" {
		progress("verifying archive checksum")
		sum, err := sha256File(cleanPath)
		if err != nil {
			return "", fmt.Errorf("checksum archive: %w", err)
		}
		if sum != expectedSHA {
			return "", fmt.Errorf("checksum mismatch: archive may be corrupt or tampered (expected %s, got %s)", expectedSHA, sum)
		}
	}

	workDir, err := os.MkdirTemp("", "sp-restore-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	progress("extracting backup archive")
	if err := extractTarGzSafely(cleanPath, workDir, maxRestoreExtractBytes); err != nil {
		return "", fmt.Errorf("extract archive: %w", err)
	}

	var checkpoints []string

	if scope == "db" || scope == "full" {
		dumpFile := filepath.Join(workDir, dbName+".sql")
		if st, err := os.Stat(dumpFile); err != nil || st.IsDir() {
			return "", fmt.Errorf("archive does not contain a database dump for %q (expected %s.sql)", dbName, dbName)
		}

		progress("creating pre-restore database checkpoint")
		cpPath, err := runCheckpointBackup(ctx, map[string]any{"scope": "db", "db_name": dbName})
		if err != nil {
			return "", fmt.Errorf("pre-restore database checkpoint failed, aborting before touching live data: %w", err)
		}
		checkpoints = append(checkpoints, cpPath)

		progress("restoring database " + dbName)
		if err := importSQLDump(ctx, dbName, dumpFile); err != nil {
			return "", fmt.Errorf("database restore failed (pre-restore checkpoint preserved at %s, database may be partially restored): %w", cpPath, err)
		}
	}

	if scope == "files" || scope == "full" {
		// backup.run tars siteRoot using its absolute path (e.g. tar -czf
		// out.tar.gz /home/sites/site_example), so the archive's entries are
		// rooted at siteRoot's absolute path with the leading slash stripped
		// (tar's own convention) — that's where extractTarGzSafely will have
		// placed the extracted files inside workDir.
		extractedRoot := filepath.Join(workDir, strings.TrimPrefix(siteRoot, "/"))
		if st, err := os.Stat(extractedRoot); err != nil || !st.IsDir() {
			return "", fmt.Errorf("archive does not contain files for %s", siteRoot)
		}

		progress("creating pre-restore files checkpoint")
		cpPath, err := runCheckpointBackup(ctx, map[string]any{"scope": "files", "site_root": siteRoot})
		if err != nil {
			return "", fmt.Errorf("pre-restore files checkpoint failed, aborting before touching live files: %w", err)
		}
		checkpoints = append(checkpoints, cpPath)

		progress("replacing site files")
		if err := replaceDirContents(siteRoot, extractedRoot); err != nil {
			return "", fmt.Errorf("file restore failed (pre-restore checkpoint preserved at %s): %w", cpPath, err)
		}

		// The isolated system user's name is siteRoot's basename by our own
		// naming convention (systemUserForDomain) — never caller-supplied —
		// matching how handleFileWrite restores ownership after a write.
		sysUser := filepath.Base(siteRoot)
		progress("restoring file ownership")
		if out, err := run(ctx, "chown", "-R", sysUser+":"+sysUser, siteRoot); err != nil {
			return "", fmt.Errorf("chown restored files (pre-restore checkpoint preserved at %s): %w: %s", cpPath, err, out)
		}
	}

	res := restoreResult{Scope: scope, ArchivePath: cleanPath, Checkpoints: checkpoints, RestoredAt: time.Now().UTC()}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// runCheckpointBackup runs handleBackupRun with a discarded progress
// reporter and returns just the resulting archive's path, or an error if
// the checkpoint itself couldn't be created — a restore must never proceed
// past this point on failure, since it's the caller's only safety net.
func runCheckpointBackup(ctx context.Context, params map[string]any) (string, error) {
	out, err := handleBackupRun(ctx, params, func(string) {})
	if err != nil {
		return "", err
	}
	var res backupResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		return "", fmt.Errorf("parse checkpoint result: %w", err)
	}
	return res.Path, nil
}

// extractTarGzSafely extracts a gzip-compressed tar archive into destDir,
// refusing anything that isn't a plain regular file or directory whose
// cleaned, joined path stays strictly inside destDir. It is deliberately
// not a shell-out to `tar -xzf`: doing the walk ourselves is what lets every
// entry be validated before a single byte is written, rather than trusting
// tar's own (platform-dependent) traversal handling.
func extractTarGzSafely(archivePath, destDir string, maxTotalBytes int64) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a valid gzip archive: %w", err)
	}
	defer gz.Close()

	realDest, err := filepath.EvalSymlinks(destDir)
	if err != nil {
		return fmt.Errorf("resolve destination: %w", err)
	}

	var totalBytes int64
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		if filepath.IsAbs(hdr.Name) {
			return fmt.Errorf("archive entry %q has an absolute path, refusing to extract", hdr.Name)
		}
		target := filepath.Join(realDest, hdr.Name)
		cleaned := filepath.Clean(target)
		if cleaned != realDest && !strings.HasPrefix(cleaned, realDest+string(filepath.Separator)) {
			return fmt.Errorf("archive entry %q escapes the extraction directory, refusing to extract", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(cleaned, 0750); err != nil {
				return fmt.Errorf("create directory %q: %w", hdr.Name, err)
			}
		case tar.TypeReg:
			totalBytes += hdr.Size
			if totalBytes > maxTotalBytes {
				return fmt.Errorf("archive exceeds the %d byte extraction limit", maxTotalBytes)
			}
			if err := os.MkdirAll(filepath.Dir(cleaned), 0750); err != nil {
				return fmt.Errorf("create parent directory for %q: %w", hdr.Name, err)
			}
			out, err := os.OpenFile(cleaned, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0777|0600)
			if err != nil {
				return fmt.Errorf("create file %q: %w", hdr.Name, err)
			}
			_, err = io.CopyN(out, tr, hdr.Size)
			out.Close()
			if err != nil && err != io.EOF {
				return fmt.Errorf("write file %q: %w", hdr.Name, err)
			}
		default:
			// Symlinks, hardlinks, char/block devices, FIFOs: none of these
			// are ever produced by backup.run, and accepting them from an
			// archive is exactly the symlink-escape / device-node risk
			// this function exists to avoid. Skip, don't fail the whole
			// restore over one unexpected entry type.
			continue
		}
	}
	return nil
}

// importSQLDump loads a plain-text SQL dump (as produced by mysqldump in
// handleBackupRun) into dbName via the `mysql` client, streaming the file
// directly as the child process's stdin — never read into memory as a
// string and never passed as a shell argument, so an arbitrarily large dump
// is handled safely and no dump content ever appears in a process argv
// (visible to other local users via /proc/<pid>/cmdline) or shell history.
func importSQLDump(ctx context.Context, dbName, dumpPath string) error {
	f, err := os.Open(dumpPath)
	if err != nil {
		return fmt.Errorf("open dump: %w", err)
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

// replaceDirContents atomically-as-possible swaps liveDir's contents for
// newContentDir's: newContentDir is renamed into liveDir's parent, the old
// liveDir is renamed aside, the new one is renamed into liveDir's place,
// and only then is the old one removed — so a failure partway through never
// leaves liveDir missing, and the "old" directory (still on disk until the
// very last step) is one more layer of recoverability on top of the
// pre-restore checkpoint archive the caller already took.
func replaceDirContents(liveDir, newContentDir string) error {
	staged := liveDir + ".sp-restore-incoming"
	old := liveDir + ".sp-restore-old"
	os.RemoveAll(staged)
	os.RemoveAll(old)

	if err := os.Rename(newContentDir, staged); err != nil {
		// newContentDir may be on a different filesystem than parent (e.g.
		// workDir under the system temp dir vs. /home/sites) — fall back to
		// a copy in that case rather than failing outright.
		if err := copyDirTree(newContentDir, staged); err != nil {
			return fmt.Errorf("stage new content: %w", err)
		}
	}

	if _, err := os.Stat(liveDir); err == nil {
		if err := os.Rename(liveDir, old); err != nil {
			return fmt.Errorf("move aside current content: %w", err)
		}
	}
	if err := os.Rename(staged, liveDir); err != nil {
		// Best-effort rollback: put the original back if we can.
		os.Rename(old, liveDir)
		return fmt.Errorf("promote restored content: %w", err)
	}
	os.RemoveAll(old)
	return nil
}

func copyDirTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0750)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
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
