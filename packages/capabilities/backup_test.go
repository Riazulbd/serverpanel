package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newTestBackupSite creates a real site directory under /home/sites with a
// "site_" prefix (required by siteSystemUserFromPath) and a matching real
// system user (required for the chown step in handleBackupRestore), both
// torn down at test end. Requires root, matching every other capability
// test that touches /home/sites — skipped otherwise so the suite still runs
// in an unprivileged CI container.
func newTestBackupSite(t *testing.T) (dir, sysUser string) {
	t.Helper()
	if err := os.MkdirAll("/home/sites", 0755); err != nil {
		t.Skipf("cannot create /home/sites in this environment: %v", err)
	}
	dir, err := os.MkdirTemp("/home/sites", "site_sp_test_")
	if err != nil {
		t.Skipf("cannot create test site root under /home/sites: %v", err)
	}
	sysUser = filepath.Base(dir)
	if out, err := exec.Command("useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", sysUser).CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		t.Skipf("cannot create test system user %q in this environment: %v: %s", sysUser, err, out)
	}
	t.Cleanup(func() {
		os.RemoveAll(dir)
		exec.Command("userdel", sysUser).Run()
	})
	return dir, sysUser
}

// cleanupBackupArchive removes a backup.run/backup.restore-created archive
// (and, for restore, its pre-restore checkpoint) so tests don't leak files
// into the shared backupBaseDir across runs.
func cleanupBackupArchive(t *testing.T, path string) {
	t.Helper()
	if path != "" {
		t.Cleanup(func() { os.Remove(path) })
	}
}

func TestHandleBackupRunRejectsInvalidScope(t *testing.T) {
	_, err := handleBackupRun(context.Background(), map[string]any{"scope": "everything"}, nil)
	if err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestHandleBackupRunRejectsSiteRootOutsideManagedPrefix(t *testing.T) {
	_, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": "/etc",
	}, nil)
	if err == nil {
		t.Fatal("expected a site_root outside /home/sites to be rejected")
	}
}

func TestHandleBackupRunRejectsInvalidDBName(t *testing.T) {
	_, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "db", "db_name": "not a db; rm -rf /",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

func TestHandleBackupRestoreRejectsInvalidScope(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{"scope": "everything"}, nil)
	if err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestHandleBackupRestoreRequiresChecksum(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/home/sites/site_x", "archive_path": "x.tar.gz",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "expected_sha256 is required") {
		t.Fatalf("error = %v, want it to require expected_sha256", err)
	}
}

func TestHandleBackupRestoreRejectsSiteRootOutsideManagedPrefix(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/etc", "archive_path": "x.tar.gz", "expected_sha256": "deadbeef",
	}, nil)
	if err == nil {
		t.Fatal("expected a site_root outside /home/sites to be rejected")
	}
}

func TestHandleBackupRestoreRejectsInvalidDBName(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "db", "db_name": "not a db; rm -rf /", "archive_path": "x.tar.gz", "expected_sha256": "deadbeef",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

func TestResolveBackupArchivePathRejectsEscape(t *testing.T) {
	if _, err := resolveBackupArchivePath("../../../../etc/passwd"); err == nil {
		t.Fatal("expected a ../ escape to be rejected")
	}
	if _, err := resolveBackupArchivePath(""); err == nil {
		t.Fatal("expected an empty archive_path to be rejected")
	}
}

func noopProgress(string) {}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	dir, _ := newTestBackupSite(t)
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("original"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	res, err := createBackupArchive(context.Background(), "files", dir, "", noopProgress)
	if err != nil {
		t.Fatalf("createBackupArchive: %v", err)
	}
	cleanupBackupArchive(t, res.Path)

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": dir, "archive_path": res.Path, "expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
	}, noopProgress)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v, want a checksum mismatch rejection", err)
	}
}

// TestHandleBackupRestoreRejectsTamperedArchiveMembers is the defense-in-
// depth check: even an archive whose checksum matches exactly what's
// expected must still be rejected if its entries don't match the declared
// restore scope, because scope (site_root/db_name) is supplied by the
// control plane per-request and a stale or mismatched pairing (e.g. an
// archive from a different site passed in as expected_sha256) must never
// silently extract into the wrong place.
func TestHandleBackupRestoreRejectsTamperedArchiveMembers(t *testing.T) {
	dirA, _ := newTestBackupSite(t)
	dirB, _ := newTestBackupSite(t)
	if err := os.WriteFile(filepath.Join(dirA, "a.txt"), []byte("from a"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	res, err := createBackupArchive(context.Background(), "files", dirA, "", noopProgress)
	if err != nil {
		t.Fatalf("createBackupArchive: %v", err)
	}
	cleanupBackupArchive(t, res.Path)

	// A correctly-checksummed archive of dirA's contents, restored as if it
	// were dirB's backup — the member paths won't match dirB's scope.
	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": dirB, "archive_path": res.Path, "expected_sha256": res.SHA256,
	}, noopProgress)
	if err == nil || !strings.Contains(err.Error(), "outside what this restore is scoped to") {
		t.Fatalf("error = %v, want the mismatched archive to be rejected", err)
	}
}

func TestBackupRunAndRestoreFilesRoundTrip(t *testing.T) {
	dir, sysUser := newTestBackupSite(t)
	original := []byte("hello from before the restore")
	seedPath := filepath.Join(dir, "index.html")
	if err := os.WriteFile(seedPath, original, 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	runOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": dir,
	}, nil)
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(runOut), &backup); err != nil {
		t.Fatalf("unmarshal backup.run result: %v", err)
	}
	cleanupBackupArchive(t, backup.Path)
	if backup.SHA256 == "" || backup.SizeBytes == 0 {
		t.Fatalf("backup result looks empty: %+v", backup)
	}

	// Simulate data loss / drift since the backup was taken.
	if err := os.WriteFile(seedPath, []byte("corrupted after the backup"), 0640); err != nil {
		t.Fatalf("simulate drift: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new-since-backup.txt"), []byte("new"), 0640); err != nil {
		t.Fatalf("seed extra file: %v", err)
	}

	var progressed []string
	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": dir, "archive_path": backup.Path, "expected_sha256": backup.SHA256,
	}, func(msg string) { progressed = append(progressed, msg) })
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}

	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("unmarshal backup.restore result: %v", err)
	}
	if restore.CheckpointPath == "" {
		t.Fatal("expected a pre-restore checkpoint to have been recorded")
	}
	cleanupBackupArchive(t, restore.CheckpointPath)

	got, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("restored content = %q, want %q", got, original)
	}

	info, err := os.Stat(seedPath)
	if err != nil {
		t.Fatalf("stat restored file: %v", err)
	}
	u, err := exec.Command("stat", "-c", "%U", seedPath).Output()
	if err != nil {
		t.Fatalf("stat owner: %v", err)
	}
	if owner := strings.TrimSpace(string(u)); owner != sysUser {
		t.Fatalf("restored file owner = %q, want %q", owner, sysUser)
	}
	_ = info

	joined := strings.Join(progressed, " | ")
	if !strings.Contains(joined, "checkpoint") {
		t.Fatalf("progress messages = %q, want a pre-restore checkpoint step reported", joined)
	}
}
