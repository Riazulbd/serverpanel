package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateBackupScopeRejectsUnknownScope(t *testing.T) {
	if err := validateBackupScope("everything", "/home/sites/x", "db1"); err == nil {
		t.Fatal("expected an unknown scope to be rejected")
	}
}

func TestValidateBackupScopeRejectsSiteRootOutsideManagedPrefix(t *testing.T) {
	if err := validateBackupScope("files", "/etc", ""); err == nil {
		t.Fatal("expected a site_root outside /home/sites/ to be rejected")
	}
}

func TestValidateBackupScopeRejectsInvalidDBName(t *testing.T) {
	if err := validateBackupScope("db", "", "not a valid db name"); err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

func TestHandleBackupRestoreRequiresExpectedChecksum(t *testing.T) {
	root := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": filepath.Join(backupBaseDir, "x.tar.gz"),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "expected_sha256 is required") {
		t.Fatalf("error = %v, want it to require expected_sha256", err)
	}
}

func TestHandleBackupRestoreRejectsArchiveOutsideBackupBaseDir(t *testing.T) {
	root := newTestSiteRoot(t)
	outside := t.TempDir()
	evil := filepath.Join(outside, "evil.tar.gz")
	if err := os.WriteFile(evil, []byte("not a real archive"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": evil, "expected_sha256": "deadbeef",
	}, noopProgress)
	if err == nil || !strings.Contains(err.Error(), "must be a backup under") {
		t.Fatalf("error = %v, want it to reject an archive outside backupBaseDir", err)
	}
}

// TestHandleBackupRestoreRejectsPathTraversalIntoBackupBaseDir guards
// against an archive_path like "/var/backups/serverpanel/../../etc/passwd"
// that string-prefix-matches backupBaseDir before cleaning but resolves
// outside it.
func TestHandleBackupRestoreRejectsPathTraversalIntoBackupBaseDir(t *testing.T) {
	root := newTestSiteRoot(t)
	traversal := filepath.Join(backupBaseDir, "..", "..", "etc", "passwd")
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": traversal, "expected_sha256": "deadbeef",
	}, noopProgress)
	if err == nil || !strings.Contains(err.Error(), "must be a backup under") {
		t.Fatalf("error = %v, want a path-traversal archive_path to be rejected", err)
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hi"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	res, err := handleBackupRun(context.Background(), map[string]any{"scope": "files", "site_root": root}, noopProgress)
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var br backupResult
	mustUnmarshal(t, res, &br)
	t.Cleanup(func() { os.Remove(br.Path) })

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": br.Path, "expected_sha256": "0000000000000000000000000000000000000000000000000000000000000",
	}, noopProgress)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v, want a checksum mismatch to be rejected", err)
	}
}

// TestHandleBackupRunAndRestoreFilesRoundTrip exercises the real
// backup.run -> backup.restore path end to end for scope=files: seed a
// site, back it up, mutate it, restore, and confirm the original content
// came back. scope=db/full require a live MariaDB and are not exercised
// here — see docs/TESTING.md for what's manually verified against a real
// server instead.
func TestHandleBackupRunAndRestoreFilesRoundTrip(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
	root := newTestSiteRoot(t)
	original := filepath.Join(root, "index.html")
	if err := os.WriteFile(original, []byte("original content"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("keep me"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	runRes, err := handleBackupRun(context.Background(), map[string]any{"scope": "files", "site_root": root}, noopProgress)
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var br backupResult
	mustUnmarshal(t, runRes, &br)
	t.Cleanup(func() { os.Remove(br.Path) })
	if br.SizeBytes == 0 || br.SHA256 == "" {
		t.Fatalf("backup result missing size/checksum: %+v", br)
	}

	// Mutate the live site: overwrite one file, delete another, add a new
	// one — restore must undo all three.
	if err := os.WriteFile(original, []byte("corrupted!!"), 0640); err != nil {
		t.Fatalf("mutate file: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "keep.txt")); err != nil {
		t.Fatalf("delete file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "unwanted.txt"), []byte("should not survive restore"), 0640); err != nil {
		t.Fatalf("seed unwanted file: %v", err)
	}

	restoreRes, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": br.Path, "expected_sha256": br.SHA256,
	}, noopProgress)
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var rr restoreResult
	mustUnmarshal(t, restoreRes, &rr)
	if rr.PreRestoreCheckpoint == nil || rr.PreRestoreCheckpoint.Path == "" {
		t.Fatal("expected a pre-restore checkpoint to be recorded")
	}
	t.Cleanup(func() { os.Remove(rr.PreRestoreCheckpoint.Path) })

	got, err := os.ReadFile(original)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != "original content" {
		t.Fatalf("restored content = %q, want %q", got, "original content")
	}
	if _, err := os.Stat(filepath.Join(root, "keep.txt")); err != nil {
		t.Fatalf("expected keep.txt to be restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "unwanted.txt")); !os.IsNotExist(err) {
		t.Fatal("expected unwanted.txt (added after the backup) to be gone after restore")
	}

	// The checkpoint must be a distinct archive from the one being restored
	// (it captures the corrupted pre-restore state), proving the restore
	// itself is recoverable.
	if rr.PreRestoreCheckpoint.Path == br.Path {
		t.Fatal("pre-restore checkpoint must be a distinct archive from the one being restored")
	}
}

func noopProgress(string) {}

func mustUnmarshal(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("unmarshal %q: %v", s, err)
	}
}
