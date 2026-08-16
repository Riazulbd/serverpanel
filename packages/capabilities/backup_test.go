package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noopProgress(string) {}

func TestValidateBackupScopeRejectsUnknownScope(t *testing.T) {
	if err := validateBackupScope("everything", "/home/sites/x", "db1"); err == nil {
		t.Fatal("expected an unknown scope to be rejected")
	}
}

func TestValidateBackupScopeRejectsUnmanagedSiteRoot(t *testing.T) {
	if err := validateBackupScope("files", "/etc", ""); err == nil {
		t.Fatal("expected a site_root outside /home/sites to be rejected")
	}
}

func TestValidateBackupScopeRejectsInvalidDBName(t *testing.T) {
	if err := validateBackupScope("db", "", "not valid; drop table"); err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

func TestValidateBackupScopeAcceptsValidFullScope(t *testing.T) {
	if err := validateBackupScope("full", "/home/sites/example", "app_db"); err != nil {
		t.Fatalf("expected a valid full-scope request to pass, got: %v", err)
	}
}

func TestHandleBackupRestoreRejectsArchiveOutsideBackupBaseDir(t *testing.T) {
	root := newTestSiteRoot(t)
	outside := filepath.Join(t.TempDir(), "evil.tar.gz")
	if err := os.WriteFile(outside, []byte("not a real archive"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": outside,
	}, noopProgress)
	if err == nil {
		t.Fatal("expected an archive_path outside backupBaseDir to be rejected")
	}
	if !strings.Contains(err.Error(), backupBaseDir) {
		t.Fatalf("error %q does not explain the backupBaseDir constraint", err.Error())
	}
}

func TestHandleBackupRestoreRejectsPathTraversalArchivePath(t *testing.T) {
	root := newTestSiteRoot(t)
	traversal := backupBaseDir + "/../../../etc/passwd"
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": traversal,
	}, noopProgress)
	if err == nil {
		t.Fatal("expected a path-traversal archive_path to be rejected")
	}
}

func TestHandleBackupRestoreRejectsMissingArchive(t *testing.T) {
	root := newTestSiteRoot(t)
	missing := filepath.Join(backupBaseDir, "does-not-exist.tar.gz")
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": missing,
	}, noopProgress)
	if err == nil {
		t.Fatal("expected a missing archive to be rejected")
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hello"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, noopProgress)
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var created backupResult
	if err := json.Unmarshal([]byte(backupOut), &created); err != nil {
		t.Fatalf("unmarshal backup result: %v", err)
	}
	t.Cleanup(func() { os.Remove(created.Path) })

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": created.Path, "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
	}, noopProgress)
	if err == nil {
		t.Fatal("expected a wrong checksum to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error %q does not mention checksum mismatch", err.Error())
	}
}

// TestBackupRunThenRestoreFilesRoundTrip exercises the real tar/cp pipeline
// end-to-end (no mocks): back up a site's files, mutate/delete them, restore
// from the archive, and confirm the original content is back. This also
// implicitly exercises the pre-restore checkpoint path (it must succeed, or
// the restore aborts before touching anything).
func TestBackupRunThenRestoreFilesRoundTrip(t *testing.T) {
	root := newTestSiteRoot(t)
	original := "original content that must survive a restore"
	seedFile := filepath.Join(root, "index.html")
	if err := os.WriteFile(seedFile, []byte(original), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, noopProgress)
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var created backupResult
	if err := json.Unmarshal([]byte(backupOut), &created); err != nil {
		t.Fatalf("unmarshal backup result: %v", err)
	}
	t.Cleanup(func() { os.Remove(created.Path) })
	if created.SHA256 == "" {
		t.Fatal("backup result has no checksum")
	}

	// Simulate data loss / a bad deploy.
	corrupted := "corrupted content"
	if err := os.WriteFile(seedFile, []byte(corrupted), 0640); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": created.Path, "sha256": created.SHA256,
	}, noopProgress)
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restored restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restored); err != nil {
		t.Fatalf("unmarshal restore result: %v", err)
	}
	t.Cleanup(func() { os.Remove(restored.CheckpointPath) })
	if restored.CheckpointPath == "" {
		t.Fatal("restore result has no pre-restore checkpoint path")
	}
	if _, err := os.Stat(restored.CheckpointPath); err != nil {
		t.Fatalf("pre-restore checkpoint archive missing on disk: %v", err)
	}

	got, err := os.ReadFile(seedFile)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != original {
		t.Fatalf("restored content = %q, want %q", string(got), original)
	}
}

func TestHandleBackupRestoreRejectsArchiveMissingExpectedDBDump(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("x"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, noopProgress)
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var created backupResult
	if err := json.Unmarshal([]byte(backupOut), &created); err != nil {
		t.Fatalf("unmarshal backup result: %v", err)
	}
	t.Cleanup(func() { os.Remove(created.Path) })

	// A files-only archive has no <db>.sql inside it; asking to restore it
	// as scope "full" (which expects both) must fail cleanly rather than
	// silently skip the database half.
	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "full", "site_root": root, "db_name": "some_db", "archive_path": created.Path,
	}, noopProgress)
	if err == nil {
		t.Fatal("expected restore to fail when the archive lacks the expected database dump")
	}
}
