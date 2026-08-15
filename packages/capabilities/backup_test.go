package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateBackupScopeParams(t *testing.T) {
	cases := []struct {
		name     string
		scope    string
		siteRoot string
		dbName   string
		wantErr  bool
	}{
		{"invalid scope", "bogus", "/home/sites/x", "db1", true},
		{"files missing site_root prefix", "files", "/tmp/x", "", true},
		{"files valid", "files", "/home/sites/x", "", false},
		{"db invalid name", "db", "", "Not Valid", true},
		{"db valid", "db", "", "db1", false},
		{"full missing both", "full", "/tmp/x", "bad name", true},
		{"full valid", "full", "/home/sites/x", "db1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBackupScopeParams(tc.scope, tc.siteRoot, tc.dbName)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestResolveBackupPathRejectsOutsideBaseDir(t *testing.T) {
	if _, err := resolveBackupPath("/etc/passwd"); err == nil {
		t.Fatal("expected a path outside backupBaseDir to be rejected")
	}
	if _, err := resolveBackupPath(""); err == nil {
		t.Fatal("expected an empty path to be rejected")
	}
}

func TestResolveBackupPathRejectsTraversalAndSymlink(t *testing.T) {
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}

	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}

	traversal := filepath.Join(backupBaseDir, "..", filepath.Base(outside))
	if _, err := resolveBackupPath(traversal); err == nil {
		t.Fatal("expected a traversal path to be rejected")
	}

	link := filepath.Join(backupBaseDir, "sp_test_symlink.tar.gz")
	os.Remove(link)
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("cannot create symlink in this environment: %v", err)
	}
	t.Cleanup(func() { os.Remove(link) })
	if _, err := resolveBackupPath(link); err == nil {
		t.Fatal("expected a symlink to be rejected")
	}
}

// TestBackupRunAndRestoreFilesRoundTrip is the core proof that
// backup.restore actually undoes damage: it backs up a site, corrupts the
// live copy (simulating a bad deploy or compromise), restores from the
// backup, and asserts the live copy is back to exactly the backed-up state
// — including that files added after the backup are gone.
func TestBackupRunAndRestoreFilesRoundTrip(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("original"), 0640); err != nil {
		t.Fatal(err)
	}

	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("backup.run: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(backupOut), &backup); err != nil {
		t.Fatalf("unmarshal backup result: %v", err)
	}
	t.Cleanup(func() { os.Remove(backup.Path) })
	if backup.SHA256 == "" || backup.SizeBytes == 0 {
		t.Fatalf("unexpected backup result: %+v", backup)
	}

	// Mutate the live site so the restore has something real to undo.
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("corrupted by a bad deploy"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "malware.php"), []byte("<?php system($_GET['c']); ?>"), 0640); err != nil {
		t.Fatal(err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "path": backup.Path,
	}, func(string) {})
	if err != nil {
		t.Fatalf("backup.restore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("unmarshal restore result: %v", err)
	}
	if restore.CheckpointPath == "" {
		t.Fatal("expected a pre-restore checkpoint to have been recorded")
	}
	t.Cleanup(func() { os.Remove(restore.CheckpointPath) })

	got, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("restore did not bring back the original content, got %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "malware.php")); !os.IsNotExist(err) {
		t.Fatal("restore should have removed files added after the backup was taken")
	}
	if _, err := os.Stat(restore.CheckpointPath); err != nil {
		t.Fatalf("checkpoint archive missing on disk: %v", err)
	}
}

func TestBackupRestoreRejectsPathOutsideBackupBaseDir(t *testing.T) {
	root := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "path": "/etc/passwd",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected restore with a path outside backupBaseDir to be rejected")
	}
}

// TestBackupRestoreAbortsWithoutChangesWhenArchiveMismatchesSiteRoot proves
// the failure path is safe: restoring one site's archive against a
// different site's root must fail loudly and leave the target untouched,
// not silently write into the wrong place.
func TestBackupRestoreAbortsWithoutChangesWhenArchiveMismatchesSiteRoot(t *testing.T) {
	rootA := newTestSiteRoot(t)
	rootB := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(rootA, "index.html"), []byte("site A"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootB, "index.html"), []byte("site B, untouched"), 0640); err != nil {
		t.Fatal(err)
	}

	backupOut, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": rootA,
	}, func(string) {})
	if err != nil {
		t.Fatalf("backup.run: %v", err)
	}
	var backup backupResult
	json.Unmarshal([]byte(backupOut), &backup)
	t.Cleanup(func() { os.Remove(backup.Path) })

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": rootB, "path": backup.Path,
	}, func(string) {})
	if err == nil {
		t.Fatal("expected restoring site A's archive into site B's root to fail")
	}

	got, err := os.ReadFile(filepath.Join(rootB, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "site B, untouched" {
		t.Fatalf("site B was modified despite the restore failing: %q", got)
	}

	// The aborted restore still took its own pre-restore checkpoint of site
	// B before discovering the mismatch; clean it up.
	matches, _ := filepath.Glob(filepath.Join(backupBaseDir, filepath.Base(rootB)+"-prerestore-*"))
	for _, m := range matches {
		os.Remove(m)
	}
}
