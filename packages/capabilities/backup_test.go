package capabilities

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ensureTestSystemUser creates a real, homeless, login-disabled system user
// with the given name (skipping the test if this environment can't run
// useradd/userdel, e.g. an unprivileged CI container), and removes it at
// test end.
func ensureTestSystemUser(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath("useradd"); err != nil {
		t.Skipf("useradd not available in this environment: %v", err)
	}
	if out, err := exec.Command("useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", name).CombinedOutput(); err != nil {
		t.Skipf("cannot create test system user %q in this environment: %v: %s", name, err, out)
	}
	t.Cleanup(func() { exec.Command("userdel", name).Run() })
}

// newTestBackupBaseDir points backupBaseDir at a temp directory for the
// duration of one test, restoring the real value afterward.
func newTestBackupBaseDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := backupBaseDir
	backupBaseDir = dir
	t.Cleanup(func() { backupBaseDir = orig })
	return dir
}

func TestHandleBackupRunRejectsBadScope(t *testing.T) {
	newTestBackupBaseDir(t)
	if _, err := handleBackupRun(context.Background(), map[string]any{"scope": "everything"}, nil); err == nil {
		t.Fatal("expected an invalid scope to be rejected")
	}
}

func TestHandleBackupRunFilesRoundTripsAndChecksums(t *testing.T) {
	newTestBackupBaseDir(t)
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'v1';"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	out, err := handleBackupRun(context.Background(), map[string]any{"scope": "files", "site_root": root}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var res backupResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if res.Scope != "files" || res.SizeBytes == 0 || res.SHA256 == "" {
		t.Fatalf("unexpected backup result: %+v", res)
	}
	sum, err := sha256File(res.Path)
	if err != nil {
		t.Fatalf("sha256File: %v", err)
	}
	if sum != res.SHA256 {
		t.Fatalf("checksum mismatch: file=%s reported=%s", sum, res.SHA256)
	}
}

func TestHandleBackupRestoreRejectsArchiveOutsideBackupBaseDir(t *testing.T) {
	newTestBackupBaseDir(t)
	root := newTestSiteRoot(t)
	outside := filepath.Join(t.TempDir(), "not-a-real-backup.tar.gz")
	os.WriteFile(outside, []byte("not actually a tarball"), 0600)

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": outside,
	}, nil)
	if err == nil {
		t.Fatal("expected an archive_path outside backupBaseDir to be rejected")
	}
	if !strings.Contains(err.Error(), "must be a backup file directly under") {
		t.Fatalf("error = %q, want it to explain the directory restriction", err.Error())
	}
}

func TestHandleBackupRestoreRejectsPathTraversalInArchivePath(t *testing.T) {
	base := newTestBackupBaseDir(t)
	root := newTestSiteRoot(t)
	// A subdirectory-nested path (even one that stays technically under
	// backupBaseDir once cleaned) must be rejected: backup.run only ever
	// writes flat files directly inside backupBaseDir, so anything else is
	// suspicious by construction.
	nested := filepath.Join(base, "sub", "evil.tar.gz")
	os.MkdirAll(filepath.Dir(nested), 0755)
	os.WriteFile(nested, []byte("x"), 0600)

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": nested,
	}, nil)
	if err == nil {
		t.Fatal("expected a nested archive_path to be rejected")
	}
}

func TestHandleBackupRestoreRejectsChecksumMismatch(t *testing.T) {
	base := newTestBackupBaseDir(t)
	root := newTestSiteRoot(t)
	archive := filepath.Join(base, "tampered.tar.gz")
	writeTestTarGz(t, archive, map[string]string{
		strings.TrimPrefix(root, "/") + "/index.php": "<?php echo 'v2';",
	})

	_, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": archive,
		"expected_sha256": "0000000000000000000000000000000000000000000000000000000000000",
	}, func(string) {})
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want it to mention checksum mismatch", err.Error())
	}
}

func TestHandleBackupRestoreFilesRoundTripReplacesContent(t *testing.T) {
	newTestBackupBaseDir(t)
	root := newTestSiteRoot(t)
	// handleBackupRestore chowns the restored files to filepath.Base(siteRoot)
	// afterward (matching real site directories, whose basename is always a
	// real system user created by site.create) — create a matching throwaway
	// system user so that step succeeds here too, instead of masking it.
	ensureTestSystemUser(t, filepath.Base(root))
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'original';"), 0640); err != nil {
		t.Fatalf("seed original content: %v", err)
	}

	backupOut, err := handleBackupRun(context.Background(), map[string]any{"scope": "files", "site_root": root}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun: %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(backupOut), &backup); err != nil {
		t.Fatalf("parse backup result: %v", err)
	}

	// Simulate the site changing (or being damaged) after the backup was
	// taken, then restore it back.
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'corrupted';"), 0640); err != nil {
		t.Fatalf("overwrite content: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "new-file-not-in-backup.txt"), []byte("junk"), 0640); err != nil {
		t.Fatalf("seed extra file: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "files", "site_root": root, "archive_path": backup.Path, "expected_sha256": backup.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore: %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("parse restore result: %v", err)
	}
	if len(restore.Checkpoints) != 1 {
		t.Fatalf("expected exactly one pre-restore checkpoint, got %v", restore.Checkpoints)
	}
	if _, err := os.Stat(restore.Checkpoints[0]); err != nil {
		t.Fatalf("checkpoint archive should exist on disk: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "index.php"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != "<?php echo 'original';" {
		t.Fatalf("restored content = %q, want the original pre-corruption content", got)
	}
	if _, err := os.Stat(filepath.Join(root, "new-file-not-in-backup.txt")); !os.IsNotExist(err) {
		t.Fatal("expected the file added after the backup to be gone after restore")
	}
}

// TestHandleBackupRunAndRestoreDBScopeRoundTrip exercises the db-scope path
// of handleBackupRun/handleBackupRestore against a real MariaDB instance —
// closing the gap SYSTEM.md/SERVERAVATAR_PARITY.md previously recorded as
// "not exercised by go test in this environment (no MariaDB here)". Seeds a
// row, dumps it via handleBackupRun, corrupts the live table, then proves
// handleBackupRestore's mysqldump/mysql-import round trip actually brings
// the original row back (including taking a pre-restore checkpoint).
func TestHandleBackupRunAndRestoreDBScopeRoundTrip(t *testing.T) {
	admin := requireMariaDB(t)
	newTestBackupBaseDir(t)

	dbName := fmt.Sprintf("sp_bktest_%d", randSuffix())
	if _, err := admin.Exec(fmt.Sprintf("CREATE DATABASE `%s`", dbName)); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() { admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName)) })

	dbConn, err := sql.Open("mysql", "root@unix(/var/run/mysqld/mysqld.sock)/"+dbName)
	if err != nil {
		t.Fatalf("open test database connection: %v", err)
	}
	defer dbConn.Close()
	if _, err := dbConn.Exec("CREATE TABLE widgets (id INT PRIMARY KEY, name VARCHAR(64))"); err != nil {
		t.Fatalf("create test table: %v", err)
	}
	if _, err := dbConn.Exec("INSERT INTO widgets (id, name) VALUES (1, 'original')"); err != nil {
		t.Fatalf("seed test row: %v", err)
	}

	backupOut, err := handleBackupRun(context.Background(), map[string]any{"scope": "db", "db_name": dbName}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun (db scope): %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(backupOut), &backup); err != nil {
		t.Fatalf("parse backup result: %v", err)
	}
	if backup.Scope != "db" || backup.SizeBytes == 0 {
		t.Fatalf("unexpected db-scope backup result: %+v", backup)
	}

	// Simulate the database changing (or being damaged) after the backup.
	if _, err := dbConn.Exec("UPDATE widgets SET name = 'corrupted' WHERE id = 1"); err != nil {
		t.Fatalf("corrupt live row: %v", err)
	}
	if _, err := dbConn.Exec("INSERT INTO widgets (id, name) VALUES (2, 'should not survive restore')"); err != nil {
		t.Fatalf("seed extra row: %v", err)
	}

	restoreOut, err := handleBackupRestore(context.Background(), map[string]any{
		"scope": "db", "db_name": dbName, "archive_path": backup.Path, "expected_sha256": backup.SHA256,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRestore (db scope): %v", err)
	}
	var restore restoreResult
	if err := json.Unmarshal([]byte(restoreOut), &restore); err != nil {
		t.Fatalf("parse restore result: %v", err)
	}
	if len(restore.Checkpoints) != 1 {
		t.Fatalf("expected exactly one pre-restore checkpoint, got %v", restore.Checkpoints)
	}
	if _, err := os.Stat(restore.Checkpoints[0]); err != nil {
		t.Fatalf("checkpoint archive should exist on disk: %v", err)
	}

	var name string
	if err := dbConn.QueryRow("SELECT name FROM widgets WHERE id = 1").Scan(&name); err != nil {
		t.Fatalf("query restored row: %v", err)
	}
	if name != "original" {
		t.Fatalf("restored widgets.name = %q, want %q", name, "original")
	}
	var count int
	dbConn.QueryRow("SELECT COUNT(1) FROM widgets WHERE id = 2").Scan(&count)
	if count != 0 {
		t.Fatal("expected the row added after the backup to be gone after restore (mysqldump dumps the whole database, restore replaces it)")
	}
}

// TestHandleBackupRunFullScopeArchivesBothDBAndFiles proves the "full"
// scope's combined tar invocation (db dump flattened via "-C workDir",
// site files kept nested at their absolute path — see handleBackupRun)
// produces one archive containing both, each restorable independently.
func TestHandleBackupRunFullScopeArchivesBothDBAndFiles(t *testing.T) {
	admin := requireMariaDB(t)
	newTestBackupBaseDir(t)
	root := newTestSiteRoot(t)
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'full-scope';"), 0640); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	dbName := fmt.Sprintf("sp_fulltest_%d", randSuffix())
	if _, err := admin.Exec(fmt.Sprintf("CREATE DATABASE `%s`", dbName)); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() { admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName)) })
	dbConn, err := sql.Open("mysql", "root@unix(/var/run/mysqld/mysqld.sock)/"+dbName)
	if err != nil {
		t.Fatalf("open test database connection: %v", err)
	}
	defer dbConn.Close()
	if _, err := dbConn.Exec("CREATE TABLE widgets (id INT PRIMARY KEY)"); err != nil {
		t.Fatalf("create test table: %v", err)
	}

	out, err := handleBackupRun(context.Background(), map[string]any{
		"scope": "full", "site_root": root, "db_name": dbName,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleBackupRun (full scope): %v", err)
	}
	var backup backupResult
	if err := json.Unmarshal([]byte(out), &backup); err != nil {
		t.Fatalf("parse backup result: %v", err)
	}

	entries := listTarGzEntries(t, backup.Path)
	if !containsExact(entries, dbName+".sql") {
		t.Fatalf("full-scope archive entries = %v, want a flat %q entry", entries, dbName+".sql")
	}
	wantFileEntry := strings.TrimPrefix(root, "/") + "/index.php"
	if !containsExact(entries, wantFileEntry) {
		t.Fatalf("full-scope archive entries = %v, want %q", entries, wantFileEntry)
	}
}

func listTarGzEntries(t *testing.T, path string) []string {
	t.Helper()
	out, err := exec.Command("tar", "-tzf", path).CombinedOutput()
	if err != nil {
		t.Fatalf("list archive entries: %v: %s", err, out)
	}
	return strings.Fields(string(out))
}

func containsExact(entries []string, want string) bool {
	for _, e := range entries {
		if e == want {
			return true
		}
	}
	return false
}

func TestExtractTarGzSafelyRejectsPathTraversal(t *testing.T) {
	dest := t.TempDir()
	src := filepath.Join(t.TempDir(), "evil.tar.gz")
	writeTestTarGz(t, src, map[string]string{"../../../../etc/cron.d/evil": "* * * * * root touch /tmp/pwned"})

	if err := extractTarGzSafely(src, dest, maxRestoreExtractBytes); err == nil {
		t.Fatal("expected a path-traversal archive entry to be rejected")
	}
}

func TestExtractTarGzSafelyRejectsAbsolutePath(t *testing.T) {
	dest := t.TempDir()
	src := filepath.Join(t.TempDir(), "evil2.tar.gz")
	writeTestTarGz(t, src, map[string]string{"/etc/passwd": "root:x:0:0"})

	if err := extractTarGzSafely(src, dest, maxRestoreExtractBytes); err == nil {
		t.Fatal("expected an absolute-path archive entry to be rejected")
	}
}

func TestExtractTarGzSafelyEnforcesSizeLimit(t *testing.T) {
	dest := t.TempDir()
	src := filepath.Join(t.TempDir(), "big.tar.gz")
	writeTestTarGz(t, src, map[string]string{"file.bin": strings.Repeat("a", 1024)})

	if err := extractTarGzSafely(src, dest, 10); err == nil {
		t.Fatal("expected extraction to be rejected once the size limit is exceeded")
	}
}

// writeTestTarGz builds a minimal tar.gz with the given path -> content
// entries, without going through tar's own path-safety logic — used to
// simulate a maliciously or accidentally crafted archive.
func writeTestTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0640, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
}
