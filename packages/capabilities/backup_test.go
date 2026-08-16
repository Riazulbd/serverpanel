package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBackupRejectsInvalidScope(t *testing.T) {
	if _, err := runBackup(context.Background(), nil, "bogus", "", "", ""); err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestRunBackupRejectsSiteRootOutsideManagedPrefix(t *testing.T) {
	dir := t.TempDir() // NOT under /home/sites/
	if _, err := runBackup(context.Background(), nil, "files", dir, "", ""); err == nil {
		t.Fatal("expected a site_root outside /home/sites to be rejected")
	}
}

func TestRunBackupRejectsInvalidDBName(t *testing.T) {
	if _, err := runBackup(context.Background(), nil, "db", "", "not a valid name; drop table", ""); err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

// TestBackupFilesRestoreRoundTrip exercises the full backup.run ->
// backup.restore path for the "files" scope end-to-end against the real
// filesystem (tar/cp), the only scope this sandbox can test without a
// MariaDB instance available (db/full scopes are validated separately
// below, and were manually verified against a real MariaDB 10.11 instance
// per docs/TESTING.md).
func TestBackupFilesRestoreRoundTrip(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("original content"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0750); err != nil {
		t.Fatalf("seed subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "style.css"), []byte("body{}"), 0640); err != nil {
		t.Fatalf("seed nested file: %v", err)
	}

	runOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(runOut), &backup); err != nil {
		t.Fatalf("unmarshal backup result: %v", err)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })
	if backup.Path == "" || backup.SHA256 == "" {
		t.Fatalf("backup result missing path/checksum: %+v", backup)
	}
	if _, err := os.Stat(backup.Path); err != nil {
		t.Fatalf("backup archive not found on disk: %v", err)
	}

	// Mutate the live site so the restore has something to undo.
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("corrupted"), 0640); err != nil {
		t.Fatalf("mutate file: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "assets", "style.css")); err != nil {
		t.Fatalf("remove nested file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "junk.txt"), []byte("should be gone after restore"), 0640); err != nil {
		t.Fatalf("add junk file: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": backup.Path, "expected_sha256": backup.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore backupRestoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("unmarshal restore result: %v", err)
	}
	t.Cleanup(func() { os.Remove(restore.PreRestoreBackup) })
	if restore.PreRestoreBackup == "" {
		t.Fatal("expected a pre-restore checkpoint path in the restore result")
	}
	if _, err := os.Stat(restore.PreRestoreBackup); err != nil {
		t.Fatalf("pre-restore checkpoint archive not found on disk: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil || string(got) != "original content" {
		t.Fatalf("index.html after restore = %q, %v, want %q", got, err, "original content")
	}
	if _, err := os.ReadFile(filepath.Join(root, "assets", "style.css")); err != nil {
		t.Fatalf("assets/style.css was not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "junk.txt")); !os.IsNotExist(err) {
		t.Fatal("expected junk.txt (added after the backup) to be removed by the restore")
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hi"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	runOut, err := handleBackupRun(context.Background(), map[string]any{"scope": "files", "site_root": root}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(runOut), &backup); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": backup.Path,
		"expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want it to mention checksum mismatch", err.Error())
	}
}

func TestHandleBackupRestoreRejectsArchiveOutsideBackupDir(t *testing.T) {
	root := newTestSiteRoot(t)
	outside := t.TempDir()
	evil := filepath.Join(outside, "evil.tar.gz")
	if err := os.WriteFile(evil, []byte("not a real archive"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	for _, path := range []string{evil, "../../../../etc/passwd"} {
		_, err := handleBackupRestore(context.Background(), map[string]any{
			"scope": "files", "site_root": root, "archive_path": path,
		}, func(string) {})
		if err == nil {
			t.Fatalf("expected archive_path %q outside backupBaseDir to be rejected", path)
		}
	}
}

func TestHandleBackupRestoreRejectsMissingArchive(t *testing.T) {
	root := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": filepath.Join(backupBaseDir, "does-not-exist.tar.gz"),
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a missing archive to be rejected")
	}
}
