package capabilities

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestSiteRoot creates a real directory under /home/sites (required by
// resolveScopedPath's prefix check) with a unique name per test, cleaned up
// at test end. Requires root or an already-writable /home/sites, which is
// the case in this environment; tests that need it are skipped otherwise so
// this suite still runs in an unprivileged CI container.
func newTestSiteRoot(t *testing.T) string {
	t.Helper()
	if err := os.MkdirAll("/home/sites", 0755); err != nil {
		t.Skipf("cannot create /home/sites in this environment: %v", err)
	}
	dir, err := os.MkdirTemp("/home/sites", "sp_test_")
	if err != nil {
		t.Skipf("cannot create test site root under /home/sites: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestResolveScopedPathRejectsRootOutsideManagedPrefix(t *testing.T) {
	dir := t.TempDir() // NOT under /home/sites/
	if _, err := resolveScopedPath(dir, "file.txt"); err == nil {
		t.Fatal("expected a site_root outside /home/sites to be rejected")
	}
}

func TestResolveScopedPathAllowsPlainRelativePath(t *testing.T) {
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	got, err := resolveScopedPath(root, "index.php")
	if err != nil {
		t.Fatalf("resolveScopedPath: %v", err)
	}
	realRoot, _ := filepath.EvalSymlinks(root)
	if got != filepath.Join(realRoot, "index.php") {
		t.Fatalf("resolved = %q, want %q", got, filepath.Join(realRoot, "index.php"))
	}
}

func TestResolveScopedPathRejectsDotDotEscape(t *testing.T) {
	root := newTestSiteRoot(t)
	if _, err := resolveScopedPath(root, "../../../../etc/passwd"); err == nil {
		t.Fatal("expected a ../ escape to be rejected")
	}
}

func TestResolveScopedPathRejectsDotDotEscapeForNewFile(t *testing.T) {
	root := newTestSiteRoot(t)
	// A path that doesn't exist yet (about to be written) but whose parent
	// resolves outside the root must still be rejected.
	if _, err := resolveScopedPath(root, "../outside.txt"); err == nil {
		t.Fatal("expected a ../ escape targeting a not-yet-existing file to be rejected")
	}
}

func TestResolveScopedPathRejectsSymlinkEscape(t *testing.T) {
	root := newTestSiteRoot(t)
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("nope"), 0600); err != nil {
		t.Fatalf("seed outside file: %v", err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := resolveScopedPath(root, "escape/secret.txt"); err == nil {
		t.Fatal("expected a symlink pointing outside the site root to be rejected")
	}
}

func TestHandleFileReadRejectsOversizedFile(t *testing.T) {
	root := newTestSiteRoot(t)
	big := make([]byte, maxFileManagerReadBytes+1)
	if err := os.WriteFile(filepath.Join(root, "big.bin"), big, 0640); err != nil {
		t.Fatalf("seed big file: %v", err)
	}
	_, err := handleFileRead(context.Background(), map[string]any{"site_root": root, "path": "big.bin"}, nil)
	if err == nil {
		t.Fatal("expected reading an over-limit file to be rejected")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("error = %q, want it to mention the size limit", err.Error())
	}
}

func TestHandleFileDeleteRefusesSiteRootItself(t *testing.T) {
	root := newTestSiteRoot(t)
	for _, p := range []string{"", ".", "/"} {
		if _, err := handleFileDelete(context.Background(), map[string]any{"site_root": root, "path": p}, nil); err == nil {
			t.Fatalf("expected deleting path %q to be refused", p)
		}
	}
}

func TestHandleFileListAndWriteRoundTrip(t *testing.T) {
	root := newTestSiteRoot(t)
	_, err := handleFileWrite(context.Background(), map[string]any{
		"site_root": root, "path": "hello.txt", "content": "hi",
	}, nil)
	if err != nil {
		t.Fatalf("handleFileWrite: %v", err)
	}
	out, err := handleFileList(context.Background(), map[string]any{"site_root": root, "path": "."}, nil)
	if err != nil {
		t.Fatalf("handleFileList: %v", err)
	}
	if !strings.Contains(out, "hello.txt") {
		t.Fatalf("listing = %q, want it to contain hello.txt", out)
	}
}
