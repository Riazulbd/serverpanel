package capabilities

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// backupsAvailable skips a test if this environment can't write to
// backupBaseDir (mirrors newTestSiteRoot's skip pattern in file_test.go), so
// the suite still runs in an unprivileged CI container.
func backupsAvailable(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
}

// newTestSiteRootForRestore is like newTestSiteRoot but names the directory
// so its basename passes handleBackupRestore's system_user validation
// (system_user must have the "site_" prefix real site.create-provisioned
// users always have) — restore needs a real, plausible system user to chown
// restored files to, unlike the read/write file-manager tests that don't
// care about the directory's name.
func newTestSiteRootForRestore(t *testing.T) string {
	t.Helper()
	if err := os.MkdirAll("/home/sites", 0755); err != nil {
		t.Skipf("cannot create /home/sites in this environment: %v", err)
	}
	dir, err := os.MkdirTemp("/home/sites", "site_test_*")
	if err != nil {
		t.Skipf("cannot create test site root under /home/sites: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0750); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0640); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

func readTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		out[rel] = string(data)
		return nil
	})
	return out
}

// TestBackupFilesRoundTrip exercises the real backup.run -> backup.restore
// lifecycle end to end for a files-scope backup — the one part of this
// capability that doesn't require a live MySQL/MariaDB server, so it runs
// with only tar/cp (both stdlib-adjacent tools present in this container).
// This is the concrete regression test for the single largest documented
// gap in docs/SYSTEM.md §19/§21: "no restore capability".
func TestBackupFilesRoundTrip(t *testing.T) {
	backupsAvailable(t)
	src := newTestSiteRootForRestore(t)
	writeTree(t, src, map[string]string{
		"public/index.html":   "<h1>original</h1>",
		"public/assets/a.css": "body{}",
	})

	res, err := runBackup(context.Background(), "files", src, "", func(string) {})
	if err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	if res.SHA256 == "" || res.SizeBytes == 0 {
		t.Fatalf("backup result missing checksum/size: %+v", res)
	}
	t.Cleanup(func() { os.Remove(res.Path) })

	// Mutate the site after the backup, simulating drift/damage that a
	// restore should undo.
	if err := os.WriteFile(filepath.Join(src, "public", "index.html"), []byte("<h1>corrupted</h1>"), 0640); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	if err := os.Remove(filepath.Join(src, "public", "assets", "a.css")); err != nil {
		t.Fatalf("remove: %v", err)
	}

	sysUser := filepath.Base(src)
	detail, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": src, "system_user": sysUser,
		"archive_path": res.Path, "expected_sha256": res.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	if !strings.Contains(detail, "checkpoint_path") {
		t.Fatalf("restore detail missing checkpoint_path: %s", detail)
	}

	got := readTree(t, src)
	want := map[string]string{"public/index.html": "<h1>original</h1>", "public/assets/a.css": "body{}"}
	for rel, content := range want {
		if got[rel] != content {
			t.Errorf("after restore, %s = %q, want %q", rel, got[rel], content)
		}
	}
}

func TestHandleBackupRestoreRejectsArchivePathOutsideBackupDir(t *testing.T) {
	backupsAvailable(t)
	outside := filepath.Join(t.TempDir(), "not-a-real-backup.tar.gz")
	os.WriteFile(outside, []byte("not a real archive"), 0600)

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/home/sites/site_x", "system_user": "site_x",
		"archive_path": outside,
	}, nil)
	if err == nil {
		t.Fatal("expected an archive_path outside the managed backup directory to be rejected")
	}
	if !strings.Contains(err.Error(), "managed backup directory") {
		t.Fatalf("error = %q, want it to mention the managed backup directory", err.Error())
	}
}

func TestHandleBackupRestoreRejectsDotDotEscape(t *testing.T) {
	backupsAvailable(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": "/home/sites/site_x", "system_user": "site_x",
		"archive_path": backupBaseDir + "/../../etc/passwd",
	}, nil)
	if err == nil {
		t.Fatal("expected a ../ escape in archive_path to be rejected")
	}
}

// TestHandleBackupRestoreRejectsChecksumMismatch guards the integrity check
// docs/product-plan.md calls for: a restore must refuse a possibly
// corrupted/tampered archive rather than silently applying it, and it must
// do so before touching the restore target.
func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	backupsAvailable(t)
	src := newTestSiteRootForRestore(t)
	writeTree(t, src, map[string]string{"public/index.html": "<h1>untouched</h1>"})

	res, err := runBackup(context.Background(), "files", src, "", func(string) {})
	if err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	t.Cleanup(func() { os.Remove(res.Path) })

	sysUser := filepath.Base(src)
	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": src, "system_user": sysUser,
		"archive_path": res.Path, "expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
	}, nil)
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want it to mention checksum mismatch", err.Error())
	}

	got := readTree(t, src)
	if got["public/index.html"] != "<h1>untouched</h1>" {
		t.Fatalf("restore target was modified despite the checksum mismatch: %v", got)
	}
}

func TestValidateBackupScopeRejectsInvalidScope(t *testing.T) {
	if err := validateBackupScope("everything", "", ""); err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestValidateBackupScopeRejectsSiteRootOutsideManaged(t *testing.T) {
	if err := validateBackupScope("files", "/tmp/not-managed", ""); err == nil {
		t.Fatal("expected a site_root outside /home/sites to be rejected")
	}
}

func TestValidateBackupScopeRejectsInvalidDBName(t *testing.T) {
	if err := validateBackupScope("db", "", "not-a-valid-name; DROP TABLE users"); err == nil {
		t.Fatal("expected an invalid db_name to be rejected")
	}
}

func TestHandleBackupRestoreRejectsInvalidSystemUser(t *testing.T) {
	backupsAvailable(t)
	src := newTestSiteRoot(t)
	res, err := runBackup(context.Background(), "files", src, "", func(string) {})
	if err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	t.Cleanup(func() { os.Remove(res.Path) })

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": src, "system_user": "root",
		"archive_path": res.Path, "expected_sha256": res.SHA256,
	}, nil)
	if err == nil {
		t.Fatal("expected a non site_ system_user to be rejected")
	}
}
