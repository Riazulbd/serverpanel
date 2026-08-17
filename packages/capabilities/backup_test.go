package capabilities

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateBackupScopeRejectsUnknownScope(t *testing.T) {
	if err := validateBackupScope("everything", "/home/sites/x", "mydb"); err == nil {
		t.Fatal("expected an unknown scope to be rejected")
	}
}

func TestValidateBackupScopeRejectsSiteRootOutsideManagedPrefix(t *testing.T) {
	if err := validateBackupScope("files", "/etc", ""); err == nil {
		t.Fatal("expected a site_root outside /home/sites to be rejected")
	}
	if err := validateBackupScope("full", "/etc", "mydb"); err == nil {
		t.Fatal("expected a site_root outside /home/sites to be rejected for scope=full")
	}
}

func TestValidateBackupScopeRejectsInvalidDBName(t *testing.T) {
	if err := validateBackupScope("db", "", "not a valid name; DROP TABLE users;"); err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

func TestHandleBackupRestoreRequiresChecksum(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/home/sites/x", "backup_path": "/var/backups/serverpanel/x.tar.gz",
	}, nil)
	if err == nil {
		t.Fatal("expected a missing expected_sha256 to be rejected")
	}
	if !strings.Contains(err.Error(), "expected_sha256") {
		t.Fatalf("error = %q, want it to mention expected_sha256", err.Error())
	}
}

func TestHandleBackupRestoreRejectsPathOutsideBackupBaseDir(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/home/sites/x",
		"backup_path": "/etc/passwd", "expected_sha256": "deadbeef",
	}, nil)
	if err == nil {
		t.Fatal("expected a backup_path outside backupBaseDir to be rejected")
	}
	if !strings.Contains(err.Error(), backupBaseDir) {
		t.Fatalf("error = %q, want it to mention %s", err.Error(), backupBaseDir)
	}
}

func TestHandleBackupRestoreRejectsPathTraversalEscape(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/home/sites/x",
		"backup_path":     backupBaseDir + "/../../etc/passwd",
		"expected_sha256": "deadbeef",
	}, nil)
	if err == nil {
		t.Fatal("expected a ../ escape out of backupBaseDir to be rejected")
	}
}

func TestHandleBackupRestoreRejectsNonexistentArchive(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/home/sites/x",
		"backup_path":     filepath.Join(backupBaseDir, "does-not-exist.tar.gz"),
		"expected_sha256": "deadbeef",
	}, nil)
	if err == nil {
		t.Fatal("expected a nonexistent archive to be rejected")
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("original"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	res, err := performBackup(context.Background(), "files", root, "", "", func(string) {})
	if err != nil {
		t.Skipf("performBackup (needs tar) unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { os.Remove(res.Path) })

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
		"backup_path": res.Path, "expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want it to mention checksum mismatch", err.Error())
	}
}

// TestHandleBackupRestoreFilesRoundTrip exercises the full files-scope
// restore path end to end against real tar/cp/chown commands (no mocks):
// back up a site directory, mutate it, restore, and confirm the original
// content came back — plus that a pre-restore checkpoint archive of the
// mutated state was created before the restore touched anything.
func TestHandleBackupRestoreFilesRoundTrip(t *testing.T) {
	root := newTestSiteRoot(t)
	original := filepath.Join(root, "index.html")
	if err := os.WriteFile(original, []byte("original content"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	backup, err := performBackup(context.Background(), "files", root, "", "", func(string) {})
	if err != nil {
		t.Skipf("performBackup (needs tar) unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })

	// Mutate the live site after the backup was taken, exactly what restore
	// is meant to undo.
	if err := os.WriteFile(original, []byte("mutated content"), 0640); err != nil {
		t.Fatalf("mutate file: %v", err)
	}

	out, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
		"backup_path": backup.Path, "expected_sha256": backup.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	if !strings.Contains(out, "pre_restore_checkpoint") {
		t.Fatalf("restore result = %q, want it to report a pre_restore_checkpoint", out)
	}

	data, err := os.ReadFile(original)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(data) != "original content" {
		t.Fatalf("restored content = %q, want %q", string(data), "original content")
	}
}

func TestFindFileBySuffixLocatesNestedFile(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(nested, "mydb.sql")
	if err := os.WriteFile(target, []byte("-- dump"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := findFileBySuffix(dir, string(filepath.Separator)+"mydb.sql")
	if err != nil {
		t.Fatalf("findFileBySuffix: %v", err)
	}
	if got != target {
		t.Fatalf("found = %q, want %q", got, target)
	}
}

func TestFindFileBySuffixReturnsErrorWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	if _, err := findFileBySuffix(dir, "/nope.sql"); err == nil {
		t.Fatal("expected an error when no matching file exists")
	}
}
