package capabilities

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const backupBaseDir = "/var/backups/serverpanel"

type backupResult struct {
	Scope     string    `json:"scope"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// handleBackupRun creates a local, checksummed backup archive. It never
// shells out to a recursive-delete anything — this capability only ever
// creates files under backupBaseDir; cleanup of old backups is a separate,
// explicitly-scoped capability (not implemented in this skeleton) rather
// than folded in here, matching "never implement disk cleanup as an
// unrestricted recursive deletion command" from docs/product-plan.md.
func handleBackupRun(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	scope, _ := params["scope"].(string)
	siteRoot, _ := params["site_root"].(string)
	dbName, _ := params["db_name"].(string)

	if scope != "db" && scope != "files" && scope != "full" {
		return "", fmt.Errorf("scope must be one of db, files, full")
	}
	if (scope == "files" || scope == "full") && !strings.HasPrefix(siteRoot, sitesRoot+"/") {
		return "", fmt.Errorf("site_root must be a managed site home directory")
	}
	if (scope == "db" || scope == "full") && !identifierRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid db_name %q", dbName)
	}

	if err := os.MkdirAll(backupBaseDir, 0700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	label := dbName
	if label == "" {
		label = filepath.Base(siteRoot)
	}
	outPath := filepath.Join(backupBaseDir, fmt.Sprintf("%s-%s-%s.tar.gz", label, scope, stamp))

	workDir, err := os.MkdirTemp("", "sp-backup-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	var tarInputs []string

	if scope == "db" || scope == "full" {
		progress("dumping database " + dbName)
		dumpPath := filepath.Join(workDir, dbName+".sql")
		out, err := run(ctx, "mysqldump", "--single-transaction", "--routines", "--events", dbName)
		if err != nil {
			return "", fmt.Errorf("mysqldump: %w: %s", err, out)
		}
		if err := os.WriteFile(dumpPath, []byte(out), 0600); err != nil {
			return "", fmt.Errorf("write dump: %w", err)
		}
		tarInputs = append(tarInputs, dumpPath)
	}

	if scope == "files" || scope == "full" {
		progress("archiving files from " + siteRoot)
		tarInputs = append(tarInputs, siteRoot)
	}

	progress("compressing archive")
	args := append([]string{"-czf", outPath}, tarInputs...)
	if out, err := run(ctx, "tar", args...); err != nil {
		return "", fmt.Errorf("tar: %w: %s", err, out)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return "", fmt.Errorf("stat backup archive: %w", err)
	}
	sum, err := sha256File(outPath)
	if err != nil {
		return "", fmt.Errorf("checksum backup archive: %w", err)
	}

	res := backupResult{Scope: scope, Path: outPath, SizeBytes: info.Size(), SHA256: sum, CreatedAt: time.Now().UTC()}
	out, _ := json.Marshal(res)
	return string(out), nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
