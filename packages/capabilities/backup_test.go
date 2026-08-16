package capabilities

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireBackupBaseDir skips the test if backupBaseDir (a real, fixed system
// path — /var/backups/serverpanel) isn't writable in this environment,
// mirroring newTestSiteRoot's skip-if-unprivileged pattern in file_test.go
// rather than mocking the filesystem.
func requireBackupBaseDir(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		t.Skipf("cannot create %s in this environment: %v", backupBaseDir, err)
	}
}

func mustBackupResult(t *testing.T, detail string) backupResult {
	t.Helper()
	var res backupResult
	if err := json.Unmarshal([]byte(detail), &res); err != nil {
		t.Fatalf("unmarshal backup result %q: %v", detail, err)
	}
	t.Cleanup(func() { os.Remove(res.Path) })
	return res
}

func TestValidateBackupScopeParamsRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name            string
		scope, root, db string
	}{
		{"bad scope", "everything", "/home/sites/x", ""},
		{"files without managed root", "files", "/tmp/not-managed", ""},
		{"full without managed root", "full", "/etc", "somedb"},
		{"db without valid identifier", "db", "", "not-a-valid-name; rm -rf /"},
		{"full without valid db identifier", "full", "/home/sites/x", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := validateBackupScopeParams(c.scope, c.root, c.db); err == nil {
				t.Fatalf("expected scope=%q root=%q db=%q to be rejected", c.scope, c.root, c.db)
			}
		})
	}
}

func TestHandleBackupRunRejectsInvalidParamsBeforeAnySystemCall(t *testing.T) {
	if _, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": "/tmp/escape-managed-dir",
	}, nil); err == nil {
		t.Fatal("expected backup.run to reject a site_root outside /home/sites")
	}
}

func TestHandleBackupRestoreRejectsPathOutsideBackupBaseDir(t *testing.T) {
	root := newTestSiteRoot(t)
	_, err := handleBackupRestore(context.Background(), map[string]any{
		"backup_path": "/etc/passwd",
		"scope":       "files",
		"site_root":   root,
	}, nil)
	if err == nil {
		t.Fatal("expected a backup_path outside backupBaseDir to be rejected")
	}
	if !strings.Contains(err.Error(), backupBaseDir) {
		t.Fatalf("error = %q, want it to mention %s", err.Error(), backupBaseDir)
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	requireBackupBaseDir(t)
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("original"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	detail, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	res := mustBackupResult(t, detail)

	_, err = handleBackupRestore(context.Background(), map[string]any{
		"backup_path":     res.Path,
		"scope":           "files",
		"site_root":       root,
		"expected_sha256": "0000000000000000000000000000000000000000000000000000000000000",
		"skip_checkpoint": true,
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want it to mention checksum mismatch", err.Error())
	}
}

// TestBackupRunAndRestoreFilesRoundTrip exercises the real flow end to end:
// back up a site's files, mutate them (simulating a bad deploy), restore
// from the backup, and confirm the original content came back — plus that a
// pre-restore checkpoint of the mutated state was captured along the way,
// which is the actual safety property this capability exists to provide.
func TestBackupRunAndRestoreFilesRoundTrip(t *testing.T) {
	requireBackupBaseDir(t)
	root := newTestSiteRoot(t)
	indexPath := filepath.Join(root, "public", "index.html")
	if err := os.MkdirAll(filepath.Dir(indexPath), 0750); err != nil {
		t.Fatalf("seed docroot: %v", err)
	}
	if err := os.WriteFile(indexPath, []byte("original content"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	backupDetail, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "files", "site_root": root,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	backup := mustBackupResult(t, backupDetail)
	if backup.SHA256 == "" || backup.SizeBytes == 0 {
		t.Fatalf("backup result looks empty: %+v", backup)
	}

	// Simulate a bad deploy overwriting the site after the backup was taken.
	if err := os.WriteFile(indexPath, []byte("BROKEN DEPLOY"), 0640); err != nil {
		t.Fatalf("mutate file: %v", err)
	}

	restoreDetail, err := handleBackupRestore(context.Background(), map[string]any{
		"backup_path":     backup.Path,
		"scope":           "files",
		"site_root":       root,
		"expected_sha256": backup.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}

	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreDetail), &restore); err != nil {
		t.Fatalf("unmarshal restore result: %v", err)
	}
	if restore.CheckpointPath == "" {
		t.Fatal("expected a pre-restore checkpoint to have been taken by default")
	}
	t.Cleanup(func() { os.Remove(restore.CheckpointPath) })

	got, err := os.ReadFile(filepath.Join(root, "public", "index.html"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != "original content" {
		t.Fatalf("restored content = %q, want %q", got, "original content")
	}

	// The checkpoint must have captured the mutated ("broken deploy") state,
	// not the restored one — that's the whole point of taking it first.
	checkpointDir := t.TempDir()
	if out, err := run(context.Background(), "tar", "-xzf", restore.CheckpointPath, "-C", checkpointDir); err != nil {
		t.Fatalf("extract checkpoint: %v: %s", err, out)
	}
	checkpointed, err := findFileByName(checkpointDir, "index.html")
	if err != nil {
		t.Fatalf("checkpoint archive missing index.html: %v", err)
	}
	checkpointedContent, err := os.ReadFile(checkpointed)
	if err != nil {
		t.Fatalf("read checkpointed content: %v", err)
	}
	if string(checkpointedContent) != "BROKEN DEPLOY" {
		t.Fatalf("checkpoint content = %q, want the pre-restore (broken) content", checkpointedContent)
	}
}

func TestAtomicSwapDirReplacesTargetContents(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("keep me"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	newDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(newDir, "new.txt"), []byte("new content"), 0640); err != nil {
		t.Fatalf("seed new dir: %v", err)
	}

	if err := atomicSwapDir(context.Background(), newDir, root); err != nil {
		t.Fatalf("atomicSwapDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "new.txt")); err != nil {
		t.Fatalf("expected swapped-in content at %s: %v", root, err)
	}
	if _, err := os.Stat(filepath.Join(root, "keep.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected the old content to be gone after a successful swap, got err=%v", err)
	}
}
