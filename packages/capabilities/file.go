package capabilities

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveScopedPath maps a caller-supplied relative path onto a real
// filesystem path guaranteed to stay inside siteRoot, which must itself be
// one of our own site home directories (/home/sites/<system_user>) — never
// an arbitrary path taken from a task's params. This is what stands
// between "per-site file manager" and "arbitrary filesystem access via
// path traversal or a symlink planted inside the site's own directory."
//
// Both the requested path AND siteRoot are resolved through
// EvalSymlinks (falling back to the nearest existing ancestor for a path
// that doesn't exist yet, e.g. a file about to be created) so a symlink
// planted inside the site root that points outside of it is rejected, not
// just a literal "..".
func resolveScopedPath(siteRoot, relPath string) (string, error) {
	if !strings.HasPrefix(siteRoot, "/home/sites/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	realRoot, err := filepath.EvalSymlinks(siteRoot)
	if err != nil {
		return "", fmt.Errorf("resolve site root: %w", err)
	}

	joined := filepath.Join(siteRoot, relPath)
	cleaned := filepath.Clean(joined)
	if cleaned != realRoot && !strings.HasPrefix(cleaned, realRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the site's isolated directory")
	}

	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		// Target doesn't exist yet (e.g. a file about to be written) —
		// walk up to the nearest existing ancestor and verify that.
		parent := filepath.Dir(cleaned)
		realParent, perr := filepath.EvalSymlinks(parent)
		if perr != nil {
			return "", fmt.Errorf("resolve parent directory: %w", perr)
		}
		if realParent != realRoot && !strings.HasPrefix(realParent, realRoot+string(filepath.Separator)) {
			return "", fmt.Errorf("path escapes the site's isolated directory")
		}
		return cleaned, nil
	}
	if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("path (via symlink) escapes the site's isolated directory")
	}
	return resolved, nil
}

const maxFileManagerReadBytes = 5 << 20 // 5MB: this is a config/code editor, not a bulk download path

func handleFileList(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	siteRoot, _ := params["site_root"].(string)
	relPath, _ := params["path"].(string)
	target, err := resolveScopedPath(siteRoot, relPath)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return "", fmt.Errorf("list directory: %w", err)
	}
	var lines []string
	for _, e := range entries {
		info, err := e.Info()
		size := int64(0)
		if err == nil {
			size = info.Size()
		}
		kind := "file"
		if e.IsDir() {
			kind = "dir"
		}
		lines = append(lines, fmt.Sprintf("%s\t%s\t%d", kind, e.Name(), size))
	}
	return strings.Join(lines, "\n"), nil
}

func handleFileRead(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	siteRoot, _ := params["site_root"].(string)
	relPath, _ := params["path"].(string)
	target, err := resolveScopedPath(siteRoot, relPath)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(target)
	if err != nil {
		return "", fmt.Errorf("stat file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%q is a directory, not a file", relPath)
	}
	if info.Size() > maxFileManagerReadBytes {
		return "", fmt.Errorf("file is %d bytes, larger than the %dMB file manager read limit", info.Size(), maxFileManagerReadBytes>>20)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	return string(data), nil
}

func handleFileWrite(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	siteRoot, _ := params["site_root"].(string)
	relPath, _ := params["path"].(string)
	content, _ := params["content"].(string)
	if len(content) > maxFileManagerReadBytes {
		return "", fmt.Errorf("content is larger than the %dMB file manager write limit", maxFileManagerReadBytes>>20)
	}
	target, err := resolveScopedPath(siteRoot, relPath)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(target, []byte(content), 0640); err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}
	// A written file must never be left root-owned inside a pool that's
	// supposed to run entirely as the site's unprivileged user; the
	// isolated system user's name is the site root's basename by our own
	// naming convention (systemUserForDomain), not caller-supplied.
	sysUser := filepath.Base(siteRoot)
	run(ctx, "chown", sysUser+":"+sysUser, target)
	return fmt.Sprintf("wrote %d bytes to %s", len(content), relPath), nil
}

func handleFileDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	siteRoot, _ := params["site_root"].(string)
	relPath, _ := params["path"].(string)
	if relPath == "" || relPath == "." || relPath == "/" {
		return "", fmt.Errorf("refusing to delete the site root itself")
	}
	target, err := resolveScopedPath(siteRoot, relPath)
	if err != nil {
		return "", err
	}
	if err := os.RemoveAll(target); err != nil {
		return "", fmt.Errorf("delete: %w", err)
	}
	return "deleted " + relPath, nil
}
