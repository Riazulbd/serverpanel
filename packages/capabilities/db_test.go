package capabilities

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
)

// requireMariaDB skips the test unless this environment has a MariaDB/MySQL
// instance reachable exactly the way mariaDBConn connects: root over the
// local Unix socket, no password. This is what lets these tests run for
// real (not mocked) wherever that's available, while staying a clean skip
// (not a failure) in a container/CI environment without MariaDB installed —
// matching the pattern ensureTestSystemUser/newTestSiteRoot already use for
// other environment-dependent capabilities.
func requireMariaDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := mariaDBConn()
	if err != nil {
		t.Skipf("cannot open MariaDB connection: %v", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Skipf("MariaDB not reachable over the local unix socket in this environment: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestHandleDBCreateRejectsInvalidNames(t *testing.T) {
	cases := []map[string]any{
		{"name": "not-valid", "owner_user": "ok_owner", "owner_password": "0123456789abcdef"},
		{"name": "ok_db", "owner_user": "Not-Valid", "owner_password": "0123456789abcdef"},
		{"name": "ok_db", "owner_user": "ok_owner", "owner_password": "short"},
		{"name": "", "owner_user": "ok_owner", "owner_password": "0123456789abcdef"},
	}
	for i, params := range cases {
		if _, err := handleDBCreate(context.Background(), params, nil); err == nil {
			t.Fatalf("case %d: expected rejection for params %v", i, params)
		}
	}
}

func TestHandleDBDeleteRejectsInvalidName(t *testing.T) {
	if _, err := handleDBDelete(context.Background(), map[string]any{"name": "Not Valid"}, nil); err == nil {
		t.Fatal("expected an invalid database name to be rejected")
	}
}

// TestHandleDBCreateAndDeleteRoundTrip exercises handleDBCreate/handleDBDelete
// against a real MariaDB instance: creates a database and a least-privilege
// owner user, verifies that user can connect and use exactly that database
// (and only that database — the whole point of DB-001's security model),
// then deletes both and verifies they're gone.
func TestHandleDBCreateAndDeleteRoundTrip(t *testing.T) {
	admin := requireMariaDB(t)

	dbName := fmt.Sprintf("sp_test_%d", randSuffix())
	owner := fmt.Sprintf("sp_owner_%d", randSuffix())
	password := "a-strong-test-password-1234"

	out, err := handleDBCreate(context.Background(), map[string]any{
		"name": dbName, "owner_user": owner, "owner_password": password,
	}, func(string) {})
	if err != nil {
		t.Fatalf("handleDBCreate: %v", err)
	}
	var created dbResult
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("parse create result: %v", err)
	}
	if created.Name != dbName || created.OwnerUser != owner {
		t.Fatalf("create result = %+v, want name=%s owner_user=%s", created, dbName, owner)
	}
	t.Cleanup(func() {
		admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName))
		admin.Exec(fmt.Sprintf("DROP USER IF EXISTS `%s`@'localhost'", owner))
	})

	// The database must actually exist.
	var exists string
	if err := admin.QueryRow("SHOW DATABASES LIKE ?", dbName).Scan(&exists); err != nil {
		t.Fatalf("created database %q not visible via SHOW DATABASES: %v", dbName, err)
	}

	// The owner user must be able to connect with the generated password and
	// use exactly this database.
	ownerDB, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/%s", owner, password, dbName))
	if err != nil {
		t.Fatalf("open owner connection: %v", err)
	}
	defer ownerDB.Close()
	if _, err := ownerDB.Exec("CREATE TABLE t (id INT PRIMARY KEY)"); err != nil {
		t.Fatalf("owner user could not create a table in its own database: %v", err)
	}

	// ... but must NOT have any grant on a second, unrelated database — this
	// is the least-privilege property db.create is supposed to guarantee.
	otherDB := fmt.Sprintf("sp_other_%d", randSuffix())
	if _, err := admin.Exec(fmt.Sprintf("CREATE DATABASE `%s`", otherDB)); err != nil {
		t.Fatalf("create unrelated database: %v", err)
	}
	t.Cleanup(func() { admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", otherDB)) })

	otherDBConn, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/%s", owner, password, otherDB))
	if err != nil {
		t.Fatalf("open connection to unrelated database: %v", err)
	}
	defer otherDBConn.Close()
	if _, err := otherDBConn.Exec("CREATE TABLE t (id INT PRIMARY KEY)"); err == nil {
		t.Fatal("owner user should NOT be able to create a table in a database it was never granted")
	}

	// Delete: both the database and the user should be gone afterward.
	delOut, err := handleDBDelete(context.Background(), map[string]any{"name": dbName, "owner_user": owner}, nil)
	if err != nil {
		t.Fatalf("handleDBDelete: %v", err)
	}
	var deleted dbResult
	if err := json.Unmarshal([]byte(delOut), &deleted); err != nil {
		t.Fatalf("parse delete result: %v", err)
	}
	if deleted.Name != dbName {
		t.Fatalf("delete result = %+v, want name=%s", deleted, dbName)
	}

	var count int
	admin.QueryRow("SELECT COUNT(1) FROM information_schema.schemata WHERE schema_name = ?", dbName).Scan(&count)
	if count != 0 {
		t.Fatalf("database %q still exists after handleDBDelete", dbName)
	}
	admin.QueryRow("SELECT COUNT(1) FROM mysql.user WHERE User = ?", owner).Scan(&count)
	if count != 0 {
		t.Fatalf("owner user %q still exists after handleDBDelete", owner)
	}
}

func TestHandleDBListExcludesSystemDatabases(t *testing.T) {
	requireMariaDB(t)
	out, err := handleDBList(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("handleDBList: %v", err)
	}
	for _, sys := range []string{"information_schema", "mysql", "performance_schema", "sys"} {
		if contains(out, sys) {
			t.Fatalf("handleDBList output %q should not include system database %q", out, sys)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

var randCounter int64

// randSuffix returns a small counter-based suffix so parallel/sequential
// test runs never collide on database/user names. It doesn't need to be
// cryptographically random — just unique within one test binary run.
func randSuffix() int64 {
	randCounter++
	return randCounter
}
