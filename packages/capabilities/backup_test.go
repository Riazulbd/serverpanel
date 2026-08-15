package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// backupBaseDir is a package-level const pointing at /var/backups/serverpanel
// in production. These tests run as root against the real path (matching
// this codebase's "no mocks for anything with a cheap real implementation"
// policy — see docs/TESTING.md) and clean up everything they create.

func TestHandleBackupRestoreRejectsPathOutsideBackupBaseDir(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "path": "/etc/passwd", "site_root": "/home/sites/site_x",
	}, nil)
	if err == nil {
		t.Fatal("expected a restore path outside backupBaseDir to be rejected")
	}
}

func TestHandleBackupRestoreRejectsPathTraversalOutOfBackupBaseDir(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "path": backupBaseDir + "/../../etc/passwd", "site_root": "/home/sites/site_x",
	}, nil)
	if err == nil {
		t.Fatal("expected a path that Clean()s outside backupBaseDir to be rejected")
	}
}

func TestHandleBackupRestoreRejectsInvalidScope(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "everything", "path": backupBaseDir + "/x.tar.gz",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestHandleBackupRestoreRejectsMissingArchive(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "path": backupBaseDir + "/does-not-exist.tar.gz", "site_root": "/home/sites/site_x",
	}, nil)
	if err == nil {
		t.Fatal("expected a nonexistent archive path to be rejected")
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Fatalf("mkdir backupBaseDir: %v", err)
	}
	archive := filepath.Join(backupBaseDir, "checksum-mismatch-test.tar.gz")
	if err := os.WriteFile(archive, []byte("not a real archive, contents don't matter for this test"), 0600); err != nil {
		t.Fatalf("write fake archive: %v", err)
	}
	t.Cleanup(func() { os.Remove(archive) })

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "path": archive, "sha256": "0000000000000000000000000000000000000000000000000000000000000",
		"site_root": "/home/sites/site_x",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected before extraction")
	}
}

func TestHandleBackupRestoreFilesScopeRoundTrip(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Fatalf("mkdir backupBaseDir: %v", err)
	}

	// Set up a fake site root with content, back it up, then destructively
	// modify it, restore, and confirm the original content came back — a
	// full backup.run -> backup.restore round trip through real tar, not a
	// mock. mysqldump/mysql aren't available in this sandbox (no MariaDB
	// installed), so this exercises the "files" scope only; the "db" scope's
	// mysql-import step is the one part of this capability that remains
	// manually verified against a real MariaDB instance rather than
	// automated here — see docs/TESTING.md.
	siteRoot := newTestSiteRoot(t)
	originalContent := "<h1>original content</h1>"
	if err := os.WriteFile(filepath.Join(siteRoot, "index.html"), []byte(originalContent), 0640); err != nil {
		t.Fatalf("write index.html: %v", err)
	}

	runDetail, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": siteRoot,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(runDetail), &backup); err != nil {
		t.Fatalf("unmarshal backup result: %v", err)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })

	// Destructively modify the site: overwrite the file and add a new one
	// that isn't in the backup.
	if err := os.WriteFile(filepath.Join(siteRoot, "index.html"), []byte("<h1>corrupted</h1>"), 0640); err != nil {
		t.Fatalf("corrupt index.html: %v", err)
	}

	restoreDetail, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "path": backup.Path, "sha256": backup.SHA256, "site_root": siteRoot,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreDetail), &restore); err != nil {
		t.Fatalf("unmarshal restore result: %v", err)
	}
	if !restore.RestoredFiles {
		t.Fatal("expected restored_files=true")
	}
	if restore.CheckpointPath == "" {
		t.Fatal("expected a pre-restore checkpoint to have been created")
	}
	t.Cleanup(func() { os.Remove(restore.CheckpointPath) })

	got, err := os.ReadFile(filepath.Join(siteRoot, "index.html"))
	if err != nil {
		t.Fatalf("read restored index.html: %v", err)
	}
	if string(got) != originalContent {
		t.Fatalf("index.html after restore = %q, want %q", got, originalContent)
	}
}

func TestFindFileWithSuffixAndFindSiteFilesDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tmp", "sp-backup-xyz"), 0755); err != nil {
		t.Fatal(err)
	}
	sqlPath := filepath.Join(root, "tmp", "sp-backup-xyz", "mydb.sql")
	if err := os.WriteFile(sqlPath, []byte("-- dump"), 0600); err != nil {
		t.Fatal(err)
	}
	found, err := findFileWithSuffix(root, ".sql")
	if err != nil || found != sqlPath {
		t.Fatalf("findFileWithSuffix = %q, %v; want %q, nil", found, err, sqlPath)
	}

	if err := os.MkdirAll(filepath.Join(root, "home", "sites", "site_example"), 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := findSiteFilesDir(root)
	want := filepath.Join(root, "home", "sites", "site_example")
	if err != nil || dir != want {
		t.Fatalf("findSiteFilesDir = %q, %v; want %q, nil", dir, err, want)
	}
}

func TestFindFileWithSuffixErrorsWhenAbsent(t *testing.T) {
	root := t.TempDir()
	if _, err := findFileWithSuffix(root, ".sql"); err == nil {
		t.Fatal("expected an error when no matching file exists")
	}
}
