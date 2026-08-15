package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newTestBackupBaseDir returns a fresh, unique subdirectory of the real
// backupBaseDir, cleaned up at test end — matching file_test.go's
// newTestSiteRoot convention (backupBaseDir is a fixed constant every
// handler in this package trusts, the same way site_root's "/home/sites/"
// prefix is, so tests exercise the real path rather than mocking it out).
// Requires root or an already-writable backupBaseDir, which is the case in
// this environment; tests that need it are skipped otherwise so this suite
// still runs in an unprivileged CI container.
func newTestBackupBaseDir(t *testing.T) string {
	t.Helper()
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
	dir, err := os.MkdirTemp(backupBaseDir, "sp_test_")
	if err != nil {
		t.Skipf("cannot create test backup dir under %s: %v", backupBaseDir, err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available in this environment", name)
	}
}

func TestValidateBackupPathRejectsOutsideBaseDir(t *testing.T) {
	newTestBackupBaseDir(t)
	if _, err := validateBackupPath("/etc/passwd"); err == nil {
		t.Fatal("expected a path outside backupBaseDir to be rejected")
	}
}

func TestValidateBackupPathRejectsTraversalEscape(t *testing.T) {
	dir := newTestBackupBaseDir(t)
	if _, err := validateBackupPath(filepath.Join(dir, "..", "..", "etc", "passwd")); err == nil {
		t.Fatal("expected a ../ escape to be rejected")
	}
}

func TestValidateBackupPathRejectsSymlinkEscape(t *testing.T) {
	dir := newTestBackupBaseDir(t)
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.tar.gz")
	if err := os.WriteFile(secret, []byte("nope"), 0600); err != nil {
		t.Fatalf("seed outside file: %v", err)
	}
	link := filepath.Join(dir, "escape.tar.gz")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := validateBackupPath(link); err == nil {
		t.Fatal("expected a symlink pointing outside backupBaseDir to be rejected")
	}
}

func TestValidateBackupPathAcceptsRealBackup(t *testing.T) {
	dir := newTestBackupBaseDir(t)
	f := filepath.Join(dir, "site-files-20260101T000000Z.tar.gz")
	if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
		t.Fatalf("seed backup file: %v", err)
	}
	got, err := validateBackupPath(f)
	if err != nil {
		t.Fatalf("validateBackupPath: %v", err)
	}
	real, _ := filepath.EvalSymlinks(f)
	if got != real {
		t.Fatalf("validateBackupPath = %q, want %q", got, real)
	}
}

func TestHandleBackupRunRejectsBadScope(t *testing.T) {
	newTestBackupBaseDir(t)
	if _, err := handleBackupRun(context.Background(), map[string]any{"scope": "everything"}, nil); err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestHandleBackupRestoreRejectsBadScope(t *testing.T) {
	newTestBackupBaseDir(t)
	if _, err := handleBackupRestore(context.Background(), map[string]any{"scope": "everything"}, nil); err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestHandleBackupRestoreRejectsBackupPathOutsideBaseDir(t *testing.T) {
	newTestBackupBaseDir(t)
	root := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "backup_path": "/etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected a backup_path outside backupBaseDir to be rejected")
	}
	if !strings.Contains(err.Error(), "backup_path") {
		t.Fatalf("error = %q, want it to mention backup_path", err.Error())
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	requireBinary(t, "tar")
	newTestBackupBaseDir(t)
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hello"), 0640); err != nil {
		t.Fatalf("seed site file: %v", err)
	}

	runOut, err := handleBackupRun(context.Background(), map[string]any{"scope": "files", "site_root": root}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var res backupResult
	if err := json.Unmarshal([]byte(runOut), &res); err != nil {
		t.Fatalf("decode backupResult: %v", err)
	}
	t.Cleanup(func() { os.Remove(res.Path) })

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "backup_path": res.Path,
		"sha256": strings.Repeat("0", 64),
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want it to mention a checksum mismatch", err.Error())
	}
}

// TestBackupRunRestoreFilesRoundTrip exercises the real backup.run ->
// backup.restore path end to end for the "files" scope (the "db"/"full"
// scopes additionally require mysqldump/mysql, which this environment does
// not have — see TestBackupRunRestoreFullRoundTripRequiresMySQL below):
// back up a site's files, mutate/delete them, restore, and confirm the
// original content came back — including that a pre-restore checkpoint of
// the mutated state was taken before anything was overwritten.
func TestBackupRunRestoreFilesRoundTrip(t *testing.T) {
	requireBinary(t, "tar")
	newTestBackupBaseDir(t)
	root := newTestSiteRoot(t)

	original := filepath.Join(root, "index.html")
	if err := os.WriteFile(original, []byte("original content"), 0640); err != nil {
		t.Fatalf("seed site file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "wp-content"), 0750); err != nil {
		t.Fatalf("seed subdirectory: %v", err)
	}

	runOut, err := handleBackupRun(context.Background(), map[string]any{"scope": "files", "site_root": root}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(runOut), &backup); err != nil {
		t.Fatalf("decode backupResult: %v", err)
	}
	if backup.SHA256 == "" || backup.SizeBytes == 0 {
		t.Fatalf("backupResult looks incomplete: %+v", backup)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })

	// Mutate the site's live files to simulate damage that a restore should undo.
	if err := os.WriteFile(original, []byte("corrupted!!!"), 0640); err != nil {
		t.Fatalf("mutate site file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "malware.php"), []byte("<?php evil(); ?>"), 0640); err != nil {
		t.Fatalf("seed extra file: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "backup_path": backup.Path, "sha256": backup.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("decode restoreResult: %v", err)
	}
	if restore.CheckpointPath == "" {
		t.Fatal("expected a pre-restore checkpoint path to be recorded")
	}
	t.Cleanup(func() { os.Remove(restore.CheckpointPath) })
	if _, err := os.Stat(restore.CheckpointPath); err != nil {
		t.Fatalf("pre-restore checkpoint archive missing on disk: %v", err)
	}

	got, err := os.ReadFile(original)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != "original content" {
		t.Fatalf("restored content = %q, want %q", got, "original content")
	}
	if _, err := os.Stat(filepath.Join(root, "malware.php")); !os.IsNotExist(err) {
		t.Fatal("expected the restore to remove files added after the backup was taken")
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content")); err != nil {
		t.Fatalf("expected wp-content subdirectory to survive the round trip: %v", err)
	}
}

func TestBackupRunRestoreFullRoundTripRequiresMySQL(t *testing.T) {
	requireBinary(t, "mysqldump")
	requireBinary(t, "mysql")
	t.Skip("db/full-scope round trip needs a live MariaDB instance; exercised manually per docs/TESTING.md")
}
