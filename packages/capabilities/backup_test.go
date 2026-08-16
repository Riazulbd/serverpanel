package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestBackupSiteRoot wraps file_test.go's newTestSiteRoot (a real
// directory under /home/sites, skipped if unwritable) and reports "root" —
// an OS user guaranteed to exist — as the owner to chown restored files to.
// Exercising real useradd-created system users is site.create's job
// (packages/capabilities/site.go), not this restore round trip; using a
// nonexistent username here would make the real `chown` call fail for an
// unrelated reason.
func newTestBackupSiteRoot(t *testing.T) (root string, ownerUser string) {
	t.Helper()
	dir := newTestSiteRoot(t)
	if err := os.MkdirAll(filepath.Join(dir, "public"), 0750); err != nil {
		t.Fatalf("create test site public dir: %v", err)
	}
	return dir, "root"
}

func withTestBackupBaseDir(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Fatalf("create backup base dir: %v", err)
	}
}

func TestHandleBackupRestoreRejectsBadScope(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{"scope": "everything"}, nil)
	if err == nil || !strings.Contains(err.Error(), "scope must be one of") {
		t.Fatalf("err = %v, want a scope validation error", err)
	}
}

func TestHandleBackupRestoreRejectsArchiveOutsideBackupBaseDir(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "archive_path": "/etc/passwd", "expected_sha256": strings.Repeat("a", 64),
		"site_root": "/home/sites/x", "owner_user": "sp_x",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "previously created under") {
		t.Fatalf("err = %v, want an archive_path scoping error", err)
	}
}

// TestHandleBackupRestoreRejectsArchiveTraversal guards the same
// path-confinement property resolveScopedPath enforces for the file
// manager: a caller-supplied archive_path crafted with ".." must not be
// able to walk out of backupBaseDir even though the literal string starts
// with the right prefix.
func TestHandleBackupRestoreRejectsArchiveTraversal(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope":           "files",
		"archive_path":    backupBaseDir + "/../../etc/passwd",
		"expected_sha256": strings.Repeat("a", 64),
		"site_root":       "/home/sites/x", "owner_user": "sp_x",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "previously created under") {
		t.Fatalf("err = %v, want traversal to be rejected", err)
	}
}

func TestHandleBackupRestoreRequiresChecksum(t *testing.T) {
	withTestBackupBaseDir(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "archive_path": filepath.Join(backupBaseDir, "x.tar.gz"),
		"site_root": "/home/sites/x", "owner_user": "sp_x",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "expected_sha256") {
		t.Fatalf("err = %v, want a missing-checksum error", err)
	}
}

func TestHandleBackupRestoreRejectsUnmanagedSiteRoot(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "archive_path": filepath.Join(backupBaseDir, "x.tar.gz"),
		"expected_sha256": strings.Repeat("a", 64),
		"site_root":       "/etc", "owner_user": "sp_x",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "managed site home directory") {
		t.Fatalf("err = %v, want a site_root validation error", err)
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	withTestBackupBaseDir(t)
	archive := filepath.Join(backupBaseDir, "checksum-mismatch-test.tar.gz")
	if err := os.WriteFile(archive, []byte("not a real archive but bytes exist"), 0600); err != nil {
		t.Fatalf("write fake archive: %v", err)
	}
	t.Cleanup(func() { os.Remove(archive) })

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "archive_path": archive,
		"expected_sha256": strings.Repeat("a", 64), // deliberately wrong
		"site_root":       "/home/sites/x", "owner_user": "sp_x",
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "does not match expected") {
		t.Fatalf("err = %v, want a checksum-mismatch error", err)
	}
}

// TestHandleBackupRunThenRestoreFilesRoundTrip exercises the real,
// non-mocked path end to end for the "files" scope (no MariaDB dependency,
// unlike "db"/"full" — those are covered by validation-only tests here and
// documented in docs/TESTING.md as manually verified against a real
// MariaDB instance, matching how the rest of this package already treats
// system-service-dependent capabilities): back up a site's files, mutate
// them, restore, and confirm both the restored content and the pre-restore
// checkpoint archive are correct.
func TestHandleBackupRunThenRestoreFilesRoundTrip(t *testing.T) {
	withTestBackupBaseDir(t)
	root, owner := newTestBackupSiteRoot(t)

	originalContent := "<h1>original site content</h1>"
	indexPath := filepath.Join(root, "public", "index.html")
	if err := os.WriteFile(indexPath, []byte(originalContent), 0640); err != nil {
		t.Fatalf("seed site content: %v", err)
	}

	backupJSON, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(backupJSON), &backup); err != nil {
		t.Fatalf("decode backup result: %v", err)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })
	if backup.SHA256 == "" || backup.Path == "" {
		t.Fatalf("backup result missing path/sha256: %+v", backup)
	}

	// Simulate damage: overwrite the file with something else entirely.
	if err := os.WriteFile(indexPath, []byte("corrupted!!"), 0640); err != nil {
		t.Fatalf("simulate damage: %v", err)
	}

	restoreJSON, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "archive_path": backup.Path, "expected_sha256": backup.SHA256,
		"site_root": root, "owner_user": owner,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreJSON), &restore); err != nil {
		t.Fatalf("decode restore result: %v", err)
	}
	t.Cleanup(func() { os.Remove(restore.CheckpointPath) })

	got, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != originalContent {
		t.Fatalf("restored content = %q, want %q", got, originalContent)
	}

	// The pre-restore checkpoint must itself be a real, valid backup of the
	// (corrupted) state that existed immediately before the restore ran —
	// this is what makes a bad restore recoverable.
	if restore.CheckpointPath == "" || restore.CheckpointSHA256 == "" {
		t.Fatalf("restore result missing checkpoint info: %+v", restore)
	}
	if _, err := os.Stat(restore.CheckpointPath); err != nil {
		t.Fatalf("checkpoint archive does not exist: %v", err)
	}
	sum, err := sha256File(restore.CheckpointPath)
	if err != nil {
		t.Fatalf("checksum checkpoint archive: %v", err)
	}
	if sum != restore.CheckpointSHA256 {
		t.Fatalf("checkpoint archive checksum = %s, want %s", sum, restore.CheckpointSHA256)
	}
}

// TestHandleBackupRestoreRejectsArchiveMissingClaimedScope confirms a
// files-scope archive can't be restored into a db-scope request (or vice
// versa) purely because the two scopes happen to share a prefix check —
// the archive's actual contents are what's authoritative.
func TestHandleBackupRestoreRejectsArchiveMissingClaimedScope(t *testing.T) {
	withTestBackupBaseDir(t)
	root, owner := newTestBackupSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "public", "index.html"), []byte("hi"), 0640); err != nil {
		t.Fatalf("seed content: %v", err)
	}

	backupJSON, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	json.Unmarshal([]byte(backupJSON), &backup)
	t.Cleanup(func() { os.Remove(backup.Path) })

	// This is a files-only archive; asking to restore it as a db backup
	// must fail before anything is touched, not silently no-op.
	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "db", "archive_path": backup.Path, "expected_sha256": backup.SHA256,
		"db_name": "sp_test_db",
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "does not contain a sp_test_db.sql dump") {
		t.Fatalf("err = %v, want a scope-content mismatch error", err)
	}
	_ = owner
}
