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
	if err := validateBackupScope("everything", "", ""); err == nil {
		t.Fatal("expected an unknown scope to be rejected")
	}
}

func TestValidateBackupScopeRequiresSiteRootForFilesAndFull(t *testing.T) {
	if err := validateBackupScope("files", "", ""); err == nil {
		t.Fatal("expected scope=files with no site_root to be rejected")
	}
	if err := validateBackupScope("full", "/tmp/not-a-managed-site", "somedb"); err == nil {
		t.Fatal("expected a site_root outside /home/sites to be rejected")
	}
}

func TestValidateBackupScopeRequiresDBNameForDBAndFull(t *testing.T) {
	if err := validateBackupScope("db", "", ""); err == nil {
		t.Fatal("expected scope=db with no db_name to be rejected")
	}
	if err := validateBackupScope("db", "", "not a valid identifier"); err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

func TestBackupRunRejectsMissingScope(t *testing.T) {
	if _, err := handleBackupRun(context.Background(), map[string]any{}, nil); err == nil {
		t.Fatal("expected missing scope to be rejected")
	}
}

func TestResolveBackupPathRejectsOutsideBackupBaseDir(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "not-a-backup.tar.gz")
	if err := os.WriteFile(outside, []byte("nope"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := resolveBackupPath(outside); err == nil {
		t.Fatal("expected a path outside the managed backup directory to be rejected")
	}
}

func TestResolveBackupPathRejectsDotDotEscape(t *testing.T) {
	if _, err := resolveBackupPath("../../../../etc/passwd"); err == nil {
		t.Fatal("expected a ../ escape to be rejected")
	}
}

func TestResolveBackupPathRejectsDirectory(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
	dir, err := os.MkdirTemp(backupBaseDir, "sp_test_dir_")
	if err != nil {
		t.Skipf("cannot create test dir under %s: %v", backupBaseDir, err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if _, err := resolveBackupPath(dir); err == nil {
		t.Fatal("expected a directory path to be rejected (must be a backup file)")
	}
}

func TestBackupRunAndRestoreFilesRoundTrip(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'v1';"), 0640); err != nil {
		t.Fatalf("seed site file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "wp-content", "uploads"), 0750); err != nil {
		t.Fatalf("seed subdirectory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-content", "uploads", "photo.jpg"), []byte("binary-ish"), 0640); err != nil {
		t.Fatalf("seed nested file: %v", err)
	}

	out, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(out), &backup); err != nil {
		t.Fatalf("decode backup result: %v", err)
	}
	if backup.SizeBytes == 0 || backup.SHA256 == "" {
		t.Fatalf("expected a non-empty archive with a checksum, got %+v", backup)
	}
	if !strings.HasPrefix(backup.Path, backupBaseDir) {
		t.Fatalf("backup path %q not under %q", backup.Path, backupBaseDir)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })

	// Mutate the site after the backup, so restore has something to undo:
	// change the existing file and add a file that shouldn't survive restore.
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'v2 - corrupted';"), 0640); err != nil {
		t.Fatalf("mutate site file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "should-not-survive.txt"), []byte("junk"), 0640); err != nil {
		t.Fatalf("seed extra file: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"path": backup.Path, "scope": "files", "site_root": root, "checkpoint": false,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("decode restore result: %v", err)
	}
	if restore.CheckpointPath != "" {
		t.Fatalf("checkpoint=false but got a checkpoint path %q", restore.CheckpointPath)
	}

	got, err := os.ReadFile(filepath.Join(root, "index.php"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != "<?php echo 'v1';" {
		t.Fatalf("restored index.php = %q, want the pre-mutation content", got)
	}
	if _, err := os.Stat(filepath.Join(root, "should-not-survive.txt")); !os.IsNotExist(err) {
		t.Fatal("expected the post-backup file to be removed by restore")
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content", "uploads", "photo.jpg")); err != nil {
		t.Fatalf("expected the nested subdirectory to survive restore: %v", err)
	}
}

func TestBackupRestoreWithCheckpointCreatesRecoverableSnapshot(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "state.txt"), []byte("original"), 0640); err != nil {
		t.Fatalf("seed site file: %v", err)
	}

	out, err := handleBackupRun(context.Background(), map[string]any{"scope": "files", "site_root": root}, nil)
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	json.Unmarshal([]byte(out), &backup)
	t.Cleanup(func() { os.Remove(backup.Path) })

	if err := os.WriteFile(filepath.Join(root, "state.txt"), []byte("changed-before-restore"), 0640); err != nil {
		t.Fatalf("mutate site file: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"path": backup.Path, "scope": "files", "site_root": root,
	}, nil)
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("decode restore result: %v", err)
	}
	if restore.CheckpointPath == "" {
		t.Fatal("expected a checkpoint archive to be created by default")
	}
	t.Cleanup(func() { os.Remove(restore.CheckpointPath) })
	if _, err := os.Stat(restore.CheckpointPath); err != nil {
		t.Fatalf("checkpoint archive does not exist on disk: %v", err)
	}

	// The checkpoint must contain the pre-restore ("changed-before-restore")
	// state, not the restored-to state — that's the whole point of taking
	// it before touching anything.
	checkOut, err := handleBackupRestore(context.Background(), map[string]any{
		"path": restore.CheckpointPath, "scope": "files", "site_root": root, "checkpoint": false,
	}, nil)
	if err != nil {
		t.Fatalf("restoring the checkpoint itself: %v", err)
	}
	_ = checkOut
	got, err := os.ReadFile(filepath.Join(root, "state.txt"))
	if err != nil {
		t.Fatalf("read file after restoring checkpoint: %v", err)
	}
	if string(got) != "changed-before-restore" {
		t.Fatalf("state.txt after restoring checkpoint = %q, want the pre-restore value", got)
	}
}

func TestBackupRestoreRejectsPathOutsideBackupDirectory(t *testing.T) {
	root := newTestSiteRoot(t)
	outside := filepath.Join(t.TempDir(), "fake.tar.gz")
	os.WriteFile(outside, []byte("not a real archive"), 0600)

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"path": outside, "scope": "files", "site_root": root, "checkpoint": false,
	}, nil)
	if err == nil {
		t.Fatal("expected a restore path outside the managed backup directory to be rejected")
	}
}

func TestBackupRestoreRejectsMissingArchive(t *testing.T) {
	root := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"path": filepath.Join(backupBaseDir, "does-not-exist.tar.gz"), "scope": "files", "site_root": root, "checkpoint": false,
	}, nil)
	if err == nil {
		t.Fatal("expected restoring a nonexistent archive to fail")
	}
}
