package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestBackupBaseDir points backupBaseDir at a throwaway temp directory
// for the duration of one test, restoring the real production path
// (/var/backups/serverpanel) afterwards, so the test suite never depends on
// — or pollutes — that real path.
func newTestBackupBaseDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := backupBaseDir
	backupBaseDir = dir
	t.Cleanup(func() { backupBaseDir = orig })
	return dir
}

// newTestSystemUser creates a real system user with a "site_" prefix (as
// site.create would) so restore's chown step has a real account to target,
// exercised end-to-end rather than skipped/mocked. Skipped if useradd isn't
// available or usable in this environment (e.g. an unprivileged container).
func newTestSystemUser(t *testing.T) string {
	t.Helper()
	name := "site_test" + strings.ToLower(t.Name())
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, name)
	if len(name) > 32 {
		name = name[:32]
	}
	if _, err := runHelperForTest("useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", name); err != nil {
		t.Skipf("cannot create a real test system user in this environment: %v", err)
	}
	t.Cleanup(func() { runHelperForTest("userdel", name) })
	return name
}

func runHelperForTest(name string, args ...string) (string, error) {
	return run(context.Background(), name, args...)
}

func seedSiteFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0750); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0640); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
}

func TestBackupRestoreFilesRoundTrip(t *testing.T) {
	newTestBackupBaseDir(t)
	srcRoot := newTestSiteRoot(t)
	seedSiteFiles(t, srcRoot, map[string]string{
		"public/index.html": "<h1>original</h1>",
		"public/app.js":     "console.log('v1');",
	})

	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope":     "files",
		"site_root": srcRoot,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(backupOut), &backup); err != nil {
		t.Fatalf("unmarshal backup result: %v", err)
	}

	// Simulate the site changing (and getting corrupted) after the backup
	// was taken, then restore into a *different* site root/system user —
	// the cross-server/cross-site restore scenario, not just in-place.
	dstRoot := newTestSiteRoot(t)
	seedSiteFiles(t, dstRoot, map[string]string{
		"public/index.html": "<h1>corrupted</h1>",
	})
	dstSysUser := newTestSystemUser(t)

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path":        backup.Path,
		"expected_sha256":     backup.SHA256,
		"scope":               "files",
		"restore_site_root":   dstRoot,
		"restore_system_user": dstSysUser,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("unmarshal restore result: %v", err)
	}
	if !restore.ChecksumVerified {
		t.Fatal("expected checksum_verified=true when expected_sha256 was supplied and matched")
	}
	if restore.CheckpointPath == "" {
		t.Fatal("expected a pre-restore checkpoint to be created, since dstRoot had existing content")
	}
	if _, err := os.Stat(restore.CheckpointPath); err != nil {
		t.Fatalf("checkpoint archive missing on disk: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dstRoot, "public", "index.html"))
	if err != nil {
		t.Fatalf("read restored index.html: %v", err)
	}
	if string(got) != "<h1>original</h1>" {
		t.Fatalf("restored index.html = %q, want the backed-up content, not the corrupted version", got)
	}
	if _, err := os.Stat(filepath.Join(dstRoot, "public", "app.js")); err != nil {
		t.Fatalf("restored app.js missing: %v", err)
	}
}

func TestBackupRestoreSkipsCheckpointWhenTargetEmpty(t *testing.T) {
	newTestBackupBaseDir(t)
	srcRoot := newTestSiteRoot(t)
	seedSiteFiles(t, srcRoot, map[string]string{"public/index.html": "hi"})

	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": srcRoot,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	json.Unmarshal([]byte(backupOut), &backup)

	dstRoot := newTestSiteRoot(t) // freshly created, empty
	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path":        backup.Path,
		"scope":               "files",
		"restore_site_root":   dstRoot,
		"restore_system_user": newTestSystemUser(t),
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	json.Unmarshal([]byte(restoreOut), &restore)
	if restore.CheckpointPath != "" {
		t.Fatalf("expected no checkpoint for an empty restore target, got %q", restore.CheckpointPath)
	}
}

func TestBackupRestoreHonorsSkipCheckpoint(t *testing.T) {
	newTestBackupBaseDir(t)
	srcRoot := newTestSiteRoot(t)
	seedSiteFiles(t, srcRoot, map[string]string{"public/index.html": "hi"})
	backupOut, _ := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": srcRoot,
	}, func(string) {})
	var backup backupResult
	json.Unmarshal([]byte(backupOut), &backup)

	dstRoot := newTestSiteRoot(t)
	seedSiteFiles(t, dstRoot, map[string]string{"public/index.html": "existing"})

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path":        backup.Path,
		"scope":               "files",
		"restore_site_root":   dstRoot,
		"restore_system_user": newTestSystemUser(t),
		"skip_checkpoint":     true,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	json.Unmarshal([]byte(restoreOut), &restore)
	if restore.CheckpointPath != "" {
		t.Fatalf("expected skip_checkpoint=true to suppress the checkpoint, got %q", restore.CheckpointPath)
	}
}

func TestBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	newTestBackupBaseDir(t)
	srcRoot := newTestSiteRoot(t)
	seedSiteFiles(t, srcRoot, map[string]string{"public/index.html": "hi"})
	backupOut, _ := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": srcRoot,
	}, func(string) {})
	var backup backupResult
	json.Unmarshal([]byte(backupOut), &backup)

	dstRoot := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path":        backup.Path,
		"expected_sha256":     "0000000000000000000000000000000000000000000000000000000000000",
		"scope":               "files",
		"restore_site_root":   dstRoot,
		"restore_system_user": "site_dummy",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want it to mention the checksum mismatch", err.Error())
	}
	// Nothing should have been written into dstRoot.
	if entries, _ := os.ReadDir(dstRoot); len(entries) != 0 {
		t.Fatalf("expected no files restored after a checksum mismatch, found %d entries", len(entries))
	}
}

func TestBackupRestoreRejectsArchiveOutsideBackupBaseDir(t *testing.T) {
	newTestBackupBaseDir(t)
	outside := filepath.Join(t.TempDir(), "evil.tar.gz")
	if err := os.WriteFile(outside, []byte("not a real archive"), 0600); err != nil {
		t.Fatalf("seed outside file: %v", err)
	}
	dstRoot := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path":        outside,
		"scope":               "files",
		"restore_site_root":   dstRoot,
		"restore_system_user": "site_dummy",
	}, nil)
	if err == nil {
		t.Fatal("expected an archive_path outside backupBaseDir to be rejected")
	}
	if !strings.Contains(err.Error(), "must be a file under") {
		t.Fatalf("error = %q, want it to mention the required base directory", err.Error())
	}
}

func TestBackupRestoreRejectsPathTraversalArchivePath(t *testing.T) {
	base := newTestBackupBaseDir(t)
	dstRoot := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path":        filepath.Join(base, "..", "etc", "passwd"),
		"scope":               "files",
		"restore_site_root":   dstRoot,
		"restore_system_user": "site_dummy",
	}, nil)
	if err == nil {
		t.Fatal("expected a ../ escape in archive_path to be rejected")
	}
}

func TestBackupRestoreRejectsMissingScope(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path": "/var/backups/serverpanel/x.tar.gz",
		"scope":        "everything",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestBackupRestoreRejectsInvalidRestoreSiteRoot(t *testing.T) {
	newTestBackupBaseDir(t)
	srcRoot := newTestSiteRoot(t)
	seedSiteFiles(t, srcRoot, map[string]string{"public/index.html": "hi"})
	backupOut, _ := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": srcRoot,
	}, func(string) {})
	var backup backupResult
	json.Unmarshal([]byte(backupOut), &backup)

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path":        backup.Path,
		"scope":               "files",
		"restore_site_root":   "/etc/passwd-dir",
		"restore_system_user": "site_x",
	}, nil)
	if err == nil {
		t.Fatal("expected a restore_site_root outside /home/sites/ to be rejected")
	}
}

func TestBackupRestoreRejectsInvalidRestoreDBName(t *testing.T) {
	newTestBackupBaseDir(t)
	srcRoot := newTestSiteRoot(t)
	seedSiteFiles(t, srcRoot, map[string]string{"public/index.html": "hi"})
	backupOut, _ := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": srcRoot,
	}, func(string) {})
	var backup backupResult
	json.Unmarshal([]byte(backupOut), &backup)

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path":    backup.Path,
		"scope":           "db",
		"restore_db_name": "'; DROP TABLE users; --",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid restore_db_name to be rejected")
	}
}

func TestBackupRestoreRejectsMissingArchive(t *testing.T) {
	base := newTestBackupBaseDir(t)
	dstRoot := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"archive_path":        filepath.Join(base, "does-not-exist.tar.gz"),
		"scope":               "files",
		"restore_site_root":   dstRoot,
		"restore_system_user": "site_dummy",
	}, nil)
	if err == nil {
		t.Fatal("expected a nonexistent archive to be rejected")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %q, want it to mention the archive was not found", err.Error())
	}
}

func TestFindSQLDumpRejectsAmbiguousArchive(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.sql"), []byte("SELECT 1;"), 0600)
	os.WriteFile(filepath.Join(dir, "b.sql"), []byte("SELECT 2;"), 0600)
	if _, err := findSQLDump(dir); err == nil {
		t.Fatal("expected multiple .sql files to be treated as ambiguous")
	}
}

func TestFindFilesRootRejectsMissingContent(t *testing.T) {
	dir := t.TempDir()
	if _, err := findFilesRoot(dir); err == nil {
		t.Fatal("expected an archive with no home/sites/* entry to error")
	}
}
