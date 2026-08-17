package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireBackupDir skips the test if backupBaseDir can't be created in this
// environment (e.g. an unprivileged CI container without /var/backups
// write access), matching file_test.go's newTestSiteRoot skip pattern.
func requireBackupDir(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
}

func TestBackupRunAndRestoreFilesRoundTrip(t *testing.T) {
	requireBackupDir(t)
	root := newTestSiteRoot(t)

	original := filepath.Join(root, "index.html")
	if err := os.WriteFile(original, []byte("original content"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	runOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("backup.run: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(runOut), &backup); err != nil {
		t.Fatalf("parse backup.run result: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(backup.Path) })

	// Simulate data loss/corruption after the backup was taken.
	if err := os.WriteFile(original, []byte("corrupted"), 0640); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "malware.php"), []byte("<?php evil(); ?>"), 0640); err != nil {
		t.Fatalf("plant extra file: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "path": backup.Path, "sha256": backup.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("backup.restore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("parse backup.restore result: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(restore.PreRestoreArchive) })

	if !restore.FilesRestored {
		t.Fatal("expected files_restored to be true")
	}
	if restore.PreRestoreArchive == "" {
		t.Fatal("expected a pre-restore checkpoint archive to have been created")
	}
	if _, err := os.Stat(restore.PreRestoreArchive); err != nil {
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
		t.Fatal("expected files introduced after the backup to be removed by restore")
	}
}

func TestBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	requireBackupDir(t)
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hi"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	runOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("backup.run: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(runOut), &backup); err != nil {
		t.Fatalf("parse backup.run result: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(backup.Path) })

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "path": backup.Path,
		"sha256": strings.Repeat("0", 64),
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want it to mention checksum mismatch", err.Error())
	}
}

func TestBackupRestoreRejectsInvalidScope(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "everything", "path": "/var/backups/serverpanel/x.tar.gz", "sha256": "abc",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "scope must be one of") {
		t.Fatalf("error = %v, want a scope validation error", err)
	}
}

func TestBackupRestoreRequiresSHA256(t *testing.T) {
	requireBackupDir(t)
	root := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "path": filepath.Join(backupBaseDir, "x.tar.gz"),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "sha256 is required") {
		t.Fatalf("error = %v, want a missing-checksum error", err)
	}
}

func TestResolveBackupArchivePathRejectsOutsideBackupDir(t *testing.T) {
	requireBackupDir(t)
	outside := t.TempDir()
	target := filepath.Join(outside, "not-a-backup.tar.gz")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := resolveBackupArchivePath(target); err == nil {
		t.Fatal("expected a path outside backupBaseDir to be rejected")
	}
	if _, err := resolveBackupArchivePath("../../etc/passwd"); err == nil {
		t.Fatal("expected a traversal path to be rejected")
	}
}

func TestResolveBackupArchivePathRejectsMissingFile(t *testing.T) {
	requireBackupDir(t)
	if _, err := resolveBackupArchivePath(filepath.Join(backupBaseDir, "does-not-exist.tar.gz")); err == nil {
		t.Fatal("expected a missing archive to be rejected")
	}
}

func TestFindFileByNameLocatesNestedDump(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "tmp", "sp-backup-12345")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dumpPath := filepath.Join(nested, "mydb.sql")
	if err := os.WriteFile(dumpPath, []byte("-- dump"), 0600); err != nil {
		t.Fatalf("seed dump: %v", err)
	}

	got, err := findFileByName(root, "mydb.sql")
	if err != nil {
		t.Fatalf("findFileByName: %v", err)
	}
	if got != dumpPath {
		t.Fatalf("findFileByName = %q, want %q", got, dumpPath)
	}

	if _, err := findFileByName(root, "missing.sql"); err == nil {
		t.Fatal("expected an error when the named file isn't present")
	}
}

func TestBackupRestoreRejectsUnmanagedSiteRoot(t *testing.T) {
	requireBackupDir(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/etc", "path": filepath.Join(backupBaseDir, "x.tar.gz"), "sha256": "abc",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "managed site home directory") {
		t.Fatalf("error = %v, want a site_root validation error", err)
	}
}
