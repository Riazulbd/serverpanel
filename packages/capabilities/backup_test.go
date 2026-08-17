package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveBackupPathAllowsFileInsideBaseDir(t *testing.T) {
	base := t.TempDir()
	archive := filepath.Join(base, "site-full-20260101T000000Z.tar.gz")
	if err := os.WriteFile(archive, []byte("fake archive"), 0600); err != nil {
		t.Fatalf("seed archive: %v", err)
	}
	got, err := resolveBackupPath(base, archive)
	if err != nil {
		t.Fatalf("resolveBackupPath: %v", err)
	}
	realBase, _ := filepath.EvalSymlinks(base)
	if got != filepath.Join(realBase, "site-full-20260101T000000Z.tar.gz") {
		t.Fatalf("resolved = %q, want it inside %q", got, realBase)
	}
}

func TestResolveBackupPathRejectsFileOutsideBaseDir(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	archive := filepath.Join(outside, "not-a-backup.tar.gz")
	if err := os.WriteFile(archive, []byte("x"), 0600); err != nil {
		t.Fatalf("seed archive: %v", err)
	}
	if _, err := resolveBackupPath(base, archive); err == nil {
		t.Fatal("expected a path outside the managed backup directory to be rejected")
	}
}

func TestResolveBackupPathRejectsDotDotEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	archive := filepath.Join(outside, "secret.tar.gz")
	if err := os.WriteFile(archive, []byte("x"), 0600); err != nil {
		t.Fatalf("seed archive: %v", err)
	}
	escaped := filepath.Join(base, "..", filepath.Base(outside), "secret.tar.gz")
	if _, err := resolveBackupPath(base, escaped); err == nil {
		t.Fatal("expected a ../ escape to be rejected")
	}
}

func TestResolveBackupPathRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.tar.gz")
	if err := os.WriteFile(secret, []byte("nope"), 0600); err != nil {
		t.Fatalf("seed outside file: %v", err)
	}
	link := filepath.Join(base, "escape.tar.gz")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := resolveBackupPath(base, link); err == nil {
		t.Fatal("expected a symlink pointing outside the backup directory to be rejected")
	}
}

func TestResolveBackupPathRejectsDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "not-a-file")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := resolveBackupPath(base, dir); err == nil {
		t.Fatal("expected a directory to be rejected — only archive files are restorable")
	}
}

func TestResolveBackupPathRejectsMissingFile(t *testing.T) {
	base := t.TempDir()
	if _, err := resolveBackupPath(base, filepath.Join(base, "does-not-exist.tar.gz")); err == nil {
		t.Fatal("expected a nonexistent path to be rejected")
	}
}

func TestHandleBackupRunRejectsInvalidScope(t *testing.T) {
	_, err := handleBackupRun(context.Background(), map[string]any{"scope": "everything"}, nil)
	if err == nil || !strings.Contains(err.Error(), "scope must be one of") {
		t.Fatalf("err = %v, want a scope validation error", err)
	}
}

func TestHandleBackupRunRejectsFilesScopeOutsideManagedSites(t *testing.T) {
	_, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": "/etc",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "managed site home directory") {
		t.Fatalf("err = %v, want a site_root validation error", err)
	}
}

func TestHandleBackupRunRejectsInvalidDBName(t *testing.T) {
	_, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "db", "db_name": "app'; DROP TABLE users; --",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

// The following handleBackupRestore validation cases all fail before the
// handler ever touches backupBaseDir, MariaDB, or the filesystem, so they
// run safely in an unprivileged CI container.

func TestHandleBackupRestoreRejectsInvalidScope(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "everything", "sha256": "deadbeef",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "scope must be one of") {
		t.Fatalf("err = %v, want a scope validation error", err)
	}
}

func TestHandleBackupRestoreRequiresChecksum(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "db", "db_name": "app", "path": "/var/backups/serverpanel/app-db-x.tar.gz",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "sha256 is required") {
		t.Fatalf("err = %v, want a missing-checksum error", err)
	}
}

func TestHandleBackupRestoreRejectsInvalidDBName(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "db", "sha256": "deadbeef", "db_name": "app; DROP TABLE users",
	}, nil)
	if err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

func TestHandleBackupRestoreRejectsFilesScopeOutsideManagedSites(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "sha256": "deadbeef", "site_root": "/etc", "owner_user": "site_x",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "managed site home directory") {
		t.Fatalf("err = %v, want a site_root validation error", err)
	}
}

func TestHandleBackupRestoreRejectsInvalidOwnerUser(t *testing.T) {
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "sha256": "deadbeef", "site_root": "/home/sites/site_x", "owner_user": "root",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid owner_user") {
		t.Fatalf("err = %v, want an owner_user validation error", err)
	}
}

// TestBackupRunThenRestoreRoundTripFilesScope exercises the full
// files-scope backup.run -> backup.restore path for real: real tar/gzip,
// real manifest read/write, the real checksum gate, and a real chown to a
// real (test-created) system user — everything except MariaDB, which this
// environment doesn't have installed (db-scope is covered by the
// validation-only tests above; mysqldump/mysql themselves are exercised
// manually against a live Ubuntu host, same as every other capability that
// shells out to a system service — see docs/TESTING.md).
func TestBackupRunThenRestoreRoundTripFilesScope(t *testing.T) {
	if _, err := exec.LookPath("useradd"); err != nil {
		t.Skip("useradd not available in this environment")
	}
	if err := os.MkdirAll("/home/sites", 0755); err != nil {
		t.Skipf("cannot create /home/sites in this environment: %v", err)
	}
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}

	testUser := fmt.Sprintf("site_bkuptest%d", os.Getpid())
	siteRoot := filepath.Join("/home/sites", testUser)
	if out, err := exec.Command("useradd", "--create-home", "--home-dir", siteRoot, "--shell", "/usr/sbin/nologin", testUser).CombinedOutput(); err != nil {
		t.Skipf("cannot create test system user in this environment: %v: %s", err, out)
	}
	t.Cleanup(func() {
		exec.Command("userdel", "--remove", testUser).Run()
		os.RemoveAll(siteRoot)
	})

	docroot := filepath.Join(siteRoot, "public")
	if err := os.MkdirAll(docroot, 0750); err != nil {
		t.Fatalf("create docroot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.html"), []byte("hello from backup"), 0640); err != nil {
		t.Fatalf("seed site file: %v", err)
	}

	noopProgress := func(string) {}
	ctx := context.Background()
	runOut, err := handleBackupRun(ctx, map[string]any{"scope": "files", "site_root": docroot}, noopProgress)
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}

	var backup struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(runOut), &backup); err != nil {
		t.Fatalf("parse backup result %q: %v", runOut, err)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })

	// Mutate the live site after the backup, then restore over it, so a
	// successful round trip is observable (restored content must match the
	// backed-up content, not the mutated content).
	if err := os.WriteFile(filepath.Join(docroot, "index.html"), []byte("mutated after backup"), 0640); err != nil {
		t.Fatalf("mutate site file: %v", err)
	}

	restoreOut, err := handleBackupRestore(ctx, map[string]any{
		"scope": "files", "path": backup.Path, "sha256": backup.SHA256,
		"site_root": docroot, "owner_user": testUser,
	}, noopProgress)
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}

	var restore struct {
		PreRestoreSiteDir string `json:"pre_restore_site_dir"`
	}
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("parse restore result %q: %v", restoreOut, err)
	}
	if restore.PreRestoreSiteDir != "" {
		t.Cleanup(func() { os.RemoveAll(restore.PreRestoreSiteDir) })
	}

	got, err := os.ReadFile(filepath.Join(docroot, "index.html"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != "hello from backup" {
		t.Fatalf("restored content = %q, want the pre-mutation backed-up content", got)
	}
	if restore.PreRestoreSiteDir == "" {
		t.Fatal("expected a pre-restore checkpoint directory to be recorded since docroot already existed")
	}
	if _, err := os.Stat(filepath.Join(restore.PreRestoreSiteDir, "index.html")); err != nil {
		t.Fatalf("pre-restore checkpoint should preserve the mutated file: %v", err)
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
	archive := filepath.Join(backupBaseDir, "checksum-mismatch-test.tar.gz")
	if err := os.WriteFile(archive, []byte("not actually a valid archive"), 0600); err != nil {
		t.Fatalf("seed fake archive: %v", err)
	}
	t.Cleanup(func() { os.Remove(archive) })

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "path": archive, "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
		"site_root": "/home/sites/site_x", "owner_user": "site_x",
	}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want a checksum mismatch error", err)
	}
}
