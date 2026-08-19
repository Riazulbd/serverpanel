package capabilities

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestSite points sitesRoot at a temp directory and creates one site
// home inside it, returning that home. Using the real package var (rather
// than a parallel code path) means these tests exercise exactly the
// containment logic that runs in production.
func newTestSite(t *testing.T) string {
	t.Helper()

	// t.TempDir() on macOS/Linux can itself sit behind a symlink
	// (/tmp -> /private/tmp); resolve it up front so the test is asserting
	// containment, not fighting its own fixture.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}

	prev := sitesRoot
	sitesRoot = filepath.Join(base, "sites")
	t.Cleanup(func() { sitesRoot = prev })

	home := siteHome("site_example_com")
	if err := os.MkdirAll(filepath.Join(home, "public"), 0750); err != nil {
		t.Fatalf("create site home: %v", err)
	}
	return home
}

func TestResolveScopedPathAllowsPathsInsideTheSite(t *testing.T) {
	home := newTestSite(t)

	// Note "public/new-file.txt": a not-yet-existing leaf inside an
	// existing directory must resolve (that's how file.write creates a
	// file). A path whose parent directory doesn't exist is separately
	// expected to fail — see TestResolveScopedPathRejectsMissingParent.
	for _, rel := range []string{"public", "public/index.php", "public/new-file.txt", "."} {
		got, err := resolveScopedPath(home, rel)
		if err != nil {
			t.Errorf("resolveScopedPath(%q) unexpectedly rejected: %v", rel, err)
			continue
		}
		if !strings.HasPrefix(got, home) {
			t.Errorf("resolveScopedPath(%q) = %q, which escapes %q", rel, got, home)
		}
	}
}

// TestResolveScopedPathRejectsMissingParent documents that the file
// manager will not create intermediate directories implicitly: writing to
// a path whose parent doesn't exist fails the containment resolve rather
// than silently succeeding somewhere unexpected.
func TestResolveScopedPathRejectsMissingParent(t *testing.T) {
	home := newTestSite(t)

	if got, err := resolveScopedPath(home, "public/does-not-exist/file.txt"); err == nil {
		t.Errorf("resolveScopedPath resolved a path with a missing parent dir to %q", got)
	}
}

func TestResolveScopedPathRejectsTraversal(t *testing.T) {
	home := newTestSite(t)

	traversals := []string{
		"../",
		"../../etc/passwd",
		"public/../../../etc/shadow",
		"/etc/passwd",
		"public/../../site_other_com/public/wp-config.php",
	}
	for _, rel := range traversals {
		got, err := resolveScopedPath(home, rel)
		if err == nil {
			t.Errorf("resolveScopedPath(%q) allowed escape to %q", rel, got)
		}
	}
}

// TestResolveScopedPathRejectsSymlinkEscape is the attack a pure
// lexical ".." check would miss: a symlink planted *inside* the site
// (e.g. by a compromised app) pointing at something outside it.
func TestResolveScopedPathRejectsSymlinkEscape(t *testing.T) {
	home := newTestSite(t)

	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("top secret"), 0600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	link := filepath.Join(home, "public", "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if got, err := resolveScopedPath(home, "public/escape"); err == nil {
		t.Errorf("symlink escape allowed, resolved to %q", got)
	}
}

// TestResolveScopedPathRejectsSymlinkedParentDir covers the variant where
// the symlink is a *directory* in the middle of the path rather than the
// leaf file.
func TestResolveScopedPathRejectsSymlinkedParentDir(t *testing.T) {
	home := newTestSite(t)

	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("x"), 0600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(home, "public", "linkdir")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if got, err := resolveScopedPath(home, "public/linkdir/secret.txt"); err == nil {
		t.Errorf("escape via symlinked parent dir allowed, resolved to %q", got)
	}
}

// TestResolveScopedPathRejectsUnmanagedRoot ensures site_root itself can't
// be pointed at an arbitrary directory — otherwise the containment check
// would be trivially bypassable by just claiming a different root.
func TestResolveScopedPathRejectsUnmanagedRoot(t *testing.T) {
	newTestSite(t) // sets sitesRoot

	for _, root := range []string{"/etc", "/", "/root", "/home", sitesRoot, sitesRoot + "-evil/x"} {
		if _, err := resolveScopedPath(root, "passwd"); err == nil {
			t.Errorf("resolveScopedPath accepted unmanaged site_root %q", root)
		}
	}
}

func TestFileDeleteRefusesSiteRootItself(t *testing.T) {
	home := newTestSite(t)

	for _, rel := range []string{"", ".", "/"} {
		if _, err := handleFileDelete(context.Background(), map[string]any{
			"site_root": home, "path": rel,
		}, func(string) {}); err == nil {
			t.Errorf("file.delete accepted path %q, which targets the site root", rel)
		}
	}
	if _, err := os.Stat(home); err != nil {
		t.Fatalf("site root was damaged by a delete that should have been refused: %v", err)
	}
}

func TestFileWriteThenReadRoundTrips(t *testing.T) {
	home := newTestSite(t)

	const content = "hello from the file manager"
	if _, err := handleFileWrite(context.Background(), map[string]any{
		"site_root": home, "path": "public/note.txt", "content": content,
	}, func(string) {}); err != nil {
		t.Fatalf("file.write: %v", err)
	}

	got, err := handleFileRead(context.Background(), map[string]any{
		"site_root": home, "path": "public/note.txt",
	}, func(string) {})
	if err != nil {
		t.Fatalf("file.read: %v", err)
	}
	if got != content {
		t.Errorf("round-trip mismatch: wrote %q, read %q", content, got)
	}
}

func TestFileWriteRejectsOversizeContent(t *testing.T) {
	home := newTestSite(t)

	huge := strings.Repeat("a", maxFileManagerReadBytes+1)
	if _, err := handleFileWrite(context.Background(), map[string]any{
		"site_root": home, "path": "public/huge.txt", "content": huge,
	}, func(string) {}); err == nil {
		t.Error("file.write accepted content over the size limit")
	}
}

func TestFileReadRejectsDirectory(t *testing.T) {
	home := newTestSite(t)

	if _, err := handleFileRead(context.Background(), map[string]any{
		"site_root": home, "path": "public",
	}, func(string) {}); err == nil {
		t.Error("file.read returned a directory as if it were a file")
	}
}
