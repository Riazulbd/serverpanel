package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func canUseBackupBaseDir(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
}

func TestHandleBackupRestoreRejectsInvalidScope(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "everything", "backup_path": "/var/backups/serverpanel/x.tar.gz",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "scope must be one of") {
		t.Fatalf("err = %v, want a scope-validation error", err)
	}
}

func TestHandleBackupRestoreRejectsBackupPathOutsideManagedDir(t *testing.T) {
	canUseBackupBaseDir(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "backup_path": "/etc/passwd", "site_root": "/home/sites/site_x",
	}, nil)
	if err == nil {
		t.Fatal("expected a backup_path outside backupBaseDir to be rejected")
	}
	if !strings.Contains(err.Error(), "managed backup archive") {
		t.Fatalf("error = %q, want it to mention the managed backup directory", err.Error())
	}
}

func TestHandleBackupRestoreRejectsPathTraversalInBackupPath(t *testing.T) {
	canUseBackupBaseDir(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "backup_path": backupBaseDir + "/../../etc/passwd", "site_root": "/home/sites/site_x",
	}, nil)
	if err == nil {
		t.Fatal("expected a ../ escape in backup_path to be rejected")
	}
}

func TestHandleBackupRestoreRejectsMissingArchive(t *testing.T) {
	canUseBackupBaseDir(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "backup_path": backupBaseDir + "/does-not-exist.tar.gz", "site_root": "/home/sites/site_x",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want a not-found error for a missing archive", err)
	}
}

func TestHandleBackupRestoreRejectsSiteRootOutsideManagedPrefix(t *testing.T) {
	canUseBackupBaseDir(t)
	path := filepath.Join(backupBaseDir, "fake.tar.gz")
	if err := os.WriteFile(path, []byte("not a real archive"), 0600); err != nil {
		t.Fatalf("seed fake archive: %v", err)
	}
	defer os.Remove(path)

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "backup_path": path, "site_root": "/etc",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "managed site home directory") {
		t.Fatalf("err = %v, want a site_root-validation error", err)
	}
}

func TestHandleBackupRestoreRejectsInvalidDBName(t *testing.T) {
	canUseBackupBaseDir(t)
	path := filepath.Join(backupBaseDir, "fake2.tar.gz")
	if err := os.WriteFile(path, []byte("not a real archive"), 0600); err != nil {
		t.Fatalf("seed fake archive: %v", err)
	}
	defer os.Remove(path)

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "db", "backup_path": path, "db_name": "app; DROP TABLE users;--",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid db_name") {
		t.Fatalf("err = %v, want a db_name-validation error", err)
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	canUseBackupBaseDir(t)
	path := filepath.Join(backupBaseDir, "fake3.tar.gz")
	if err := os.WriteFile(path, []byte("not a real archive"), 0600); err != nil {
		t.Fatalf("seed fake archive: %v", err)
	}
	defer os.Remove(path)

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "backup_path": path, "site_root": "/home/sites/site_x",
		"sha256": strings.Repeat("0", 64),
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want a checksum-mismatch error", err)
	}
}

// TestBackupRunRestoreFilesRoundTrip exercises the real backup.run ->
// backup.restore path end to end against a real filesystem and the real
// `tar`/`cp` binaries: create a site with known content, back it up, mutate
// it (simulating data loss / a bad deploy), restore, and confirm the
// original content came back — including that a pre-restore checkpoint of
// the *mutated* state was itself taken before the restore touched anything.
// Skipped if this environment can't write to /home/sites or
// /var/backups/serverpanel (matches the pattern in file_test.go).
func TestBackupRunRestoreFilesRoundTrip(t *testing.T) {
	canUseBackupBaseDir(t)
	if err := os.MkdirAll("/home/sites", 0755); err != nil {
		t.Skipf("cannot create /home/sites in this environment: %v", err)
	}
	root, err := os.MkdirTemp("/home/sites", "sp_restore_test_")
	if err != nil {
		t.Skipf("cannot create test site root under /home/sites: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	original := "original content v1"
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(original), 0640); err != nil {
		t.Fatalf("seed original file: %v", err)
	}

	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(backupOut), &backup); err != nil {
		t.Fatalf("decode backup result: %v", err)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })
	if backup.Path == "" || backup.SHA256 == "" {
		t.Fatalf("backup result missing path/sha256: %+v", backup)
	}

	// Simulate data loss / a bad deploy: overwrite and add stray files.
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("corrupted!!"), 0640); err != nil {
		t.Fatalf("mutate file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "stray.txt"), []byte("should not survive restore"), 0640); err != nil {
		t.Fatalf("seed stray file: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "backup_path": backup.Path, "site_root": root, "sha256": backup.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("decode restore result: %v", err)
	}
	t.Cleanup(func() {
		var checkpoint backupResult
		if json.Unmarshal([]byte(restore.CheckpointDetail), &checkpoint) == nil {
			os.Remove(checkpoint.Path)
		}
	})

	restored, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(restored) != original {
		t.Fatalf("restored content = %q, want %q", restored, original)
	}
	if _, err := os.Stat(filepath.Join(root, "stray.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected stray.txt (added after the backup) to be removed by restore, stat err = %v", err)
	}
	if restore.CheckpointDetail == "" {
		t.Fatal("expected a pre-restore checkpoint to have been recorded")
	}
}

func TestHandleBackupRunRejectsInvalidScope(t *testing.T) {
	_, err := handleBackupRun(context.Background(), map[string]any{"scope": "everything"}, nil)
	if err == nil || !strings.Contains(err.Error(), "scope must be one of") {
		t.Fatalf("err = %v, want a scope-validation error", err)
	}
}

func TestFindFileWithSuffixWalksSubdirectories(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	want := filepath.Join(nested, "mydb.sql")
	if err := os.WriteFile(want, []byte("-- dump"), 0600); err != nil {
		t.Fatalf("seed sql file: %v", err)
	}
	got, err := findFileWithSuffix(dir, "mydb.sql")
	if err != nil {
		t.Fatalf("findFileWithSuffix: %v", err)
	}
	if got != want {
		t.Fatalf("findFileWithSuffix = %q, want %q", got, want)
	}
}

func TestFindFileWithSuffixReturnsErrorWhenNotFound(t *testing.T) {
	dir := t.TempDir()
	if _, err := findFileWithSuffix(dir, "missing.sql"); err == nil {
		t.Fatal("expected an error when no matching file exists")
	}
}
