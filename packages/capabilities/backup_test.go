package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestBackupSiteRoot is newTestSiteRoot's sibling: a real site_root plus
// a matching, really-existing sysUser (handleBackupRestore's files path
// chowns to it, exactly like handleSiteCreate does for a real site), skipping
// gracefully in the same environments file_test.go already skips in or where
// useradd isn't available/permitted.
func newTestBackupSiteRoot(t *testing.T) (siteRoot, sysUser string) {
	t.Helper()
	root := newTestSiteRoot(t)
	user := "site_" + filepath.Base(root)
	if _, err := run(context.Background(), "useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", user); err != nil {
		t.Skipf("cannot create test system user %q in this environment: %v", user, err)
	}
	t.Cleanup(func() { run(context.Background(), "userdel", user) })
	return root, user
}

// cleanupBackupArchives removes every file handleBackupRun/handleBackupRestore
// wrote under backupBaseDir during a test, since that directory is a shared,
// real filesystem path rather than a per-test temp dir.
func cleanupBackupArchives(t *testing.T) {
	t.Helper()
	var existing map[string]bool
	if entries, err := os.ReadDir(backupBaseDir); err == nil {
		existing = map[string]bool{}
		for _, e := range entries {
			existing[e.Name()] = true
		}
	}
	t.Cleanup(func() {
		entries, err := os.ReadDir(backupBaseDir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if existing == nil || !existing[e.Name()] {
				os.Remove(filepath.Join(backupBaseDir, e.Name()))
			}
		}
	})
}

func TestBackupRunAndRestoreFilesRoundTrip(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
	cleanupBackupArchives(t)

	root, sysUser := newTestBackupSiteRoot(t)
	original := "hello from the original site"
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(original), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(backupOut), &backup); err != nil {
		t.Fatalf("parse backup result: %v", err)
	}
	if backup.SHA256 == "" || backup.Path == "" {
		t.Fatalf("backup result missing path/checksum: %+v", backup)
	}

	// Simulate drift/corruption after the backup was taken.
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("corrupted!!"), 0640); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "malware.php"), []byte("<?php system($_GET['c']); ?>"), 0640); err != nil {
		t.Fatalf("seed extra file: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "system_user": sysUser,
		"backup_path": backup.Path, "expected_sha256": backup.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("parse restore result: %v", err)
	}
	if !restore.FilesRestored {
		t.Fatalf("restore result says files were not restored: %+v", restore)
	}
	if restore.CheckpointPath == "" {
		t.Fatal("expected a pre-restore checkpoint archive to have been taken")
	}
	if restore.CheckpointPath == backup.Path {
		t.Fatal("checkpoint archive must be a fresh backup, not the original one being restored from")
	}

	got, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != original {
		t.Fatalf("restored content = %q, want %q", got, original)
	}
}

func TestBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
	cleanupBackupArchives(t)

	root, sysUser := newTestBackupSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("v1"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	json.Unmarshal([]byte(backupOut), &backup)

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "system_user": sysUser,
		"backup_path": backup.Path, "expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want it to mention checksum mismatch", err.Error())
	}
}

func TestBackupRestoreRejectsArchivePathOutsideBackupBaseDir(t *testing.T) {
	root, sysUser := newTestBackupSiteRoot(t)
	outside := filepath.Join(t.TempDir(), "not-a-real-backup.tar.gz")
	if err := os.WriteFile(outside, []byte("not a real archive"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "system_user": sysUser,
		"backup_path": outside,
	}, nil)
	if err == nil {
		t.Fatal("expected a backup_path outside the managed backup directory to be rejected")
	}
	if !strings.Contains(err.Error(), "managed backup directory") {
		t.Fatalf("error = %q, want it to mention the managed backup directory", err.Error())
	}
}

func TestBackupRestoreRejectsInvalidScope(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{"scope": "everything"}, nil)
	if err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestBackupRestoreRejectsSiteRootOutsideManagedPrefix(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/etc", "system_user": "site_x", "backup_path": "/tmp/x.tar.gz",
	}, nil)
	if err == nil {
		t.Fatal("expected a site_root outside /home/sites/ to be rejected")
	}
}
