package capabilities

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"

	_ "github.com/go-sql-driver/mysql"
)

// dbCreateResult is db.create's structured detail, mirroring backupResult
// (packages/capabilities/backup.go) — the control plane parses this to
// persist a databases row without ever storing the password.
type dbCreateResult struct {
	Name  string `json:"name"`
	Owner string `json:"owner_user"`
}

// dbUserResult is db.create_user's structured detail.
type dbUserResult struct {
	DBName   string `json:"db_name"`
	Username string `json:"username"`
}

// identifierRe is the allow-list for database/user names. MySQL has no
// placeholder syntax for identifiers (only for values), so the standard
// safe approach — used here — is to validate against a strict charset
// before backtick-quoting and interpolating, never to accept an arbitrary
// string into a CREATE DATABASE/USER statement.
var identifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

func mariaDBConn() (*sql.DB, error) {
	// Connects as root over the local Unix socket, matching MariaDB's
	// default Debian/Ubuntu package configuration (unix_socket auth
	// plugin: the OS-level identity of the connecting process — root, same
	// as this agent — is what's authenticated, no password stored
	// anywhere). This never talks to MariaDB over the network.
	//
	// interpolateParams=true makes the driver safely escape and inline "?"
	// placeholder values client-side instead of using the server-side
	// prepared-statement protocol (COM_STMT_PREPARE) — required here
	// because MariaDB rejects a "?" placeholder inside CREATE USER ...
	// IDENTIFIED BY (confirmed against a live MariaDB 10.11 instance: "You
	// have an error in your SQL syntax ... near '?'"). This is still safe
	// parameter handling, just done in the client library rather than the
	// server; it is not raw string concatenation of untrusted input.
	return sql.Open("mysql", "root@unix(/var/run/mysqld/mysqld.sock)/?interpolateParams=true")
}

func handleDBCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	name, _ := params["name"].(string)
	owner, _ := params["owner_user"].(string)
	password, _ := params["owner_password"].(string)

	if !identifierRe.MatchString(name) {
		return "", fmt.Errorf("invalid database name %q (must match %s)", name, identifierRe.String())
	}
	if !identifierRe.MatchString(owner) {
		return "", fmt.Errorf("invalid owner_user %q (must match %s)", owner, identifierRe.String())
	}
	if len(password) < 16 {
		return "", fmt.Errorf("owner_password must be at least 16 characters")
	}

	db, err := mariaDBConn()
	if err != nil {
		return "", err
	}
	defer db.Close()

	progress("creating database " + name)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", name)); err != nil {
		return "", fmt.Errorf("create database: %w", err)
	}

	progress("creating scoped owner user")
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE USER IF NOT EXISTS `%s`@'localhost' IDENTIFIED BY ?", owner), password); err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}

	// Least-privilege grant: only on this one database, never GRANT ALL at
	// the server/global scope — this is what keeps one app's database
	// credentials from being useful against any other app's data.
	if _, err := db.ExecContext(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO `%s`@'localhost'", name, owner)); err != nil {
		return "", fmt.Errorf("grant privileges: %w", err)
	}
	if _, err := db.ExecContext(ctx, "FLUSH PRIVILEGES"); err != nil {
		return "", fmt.Errorf("flush privileges: %w", err)
	}

	out, _ := json.Marshal(dbCreateResult{Name: name, Owner: owner})
	return string(out), nil
}

// handleDBCreateUser adds an additional user scoped to exactly one
// already-existing database — the same least-privilege grant pattern
// handleDBCreate uses for the owner user, split out so a caller can hand a
// second app (e.g. a read-only integration, a staging copy) its own
// credential without reusing or widening the owner user's grants.
func handleDBCreateUser(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	name, _ := params["db_name"].(string)
	username, _ := params["username"].(string)
	password, _ := params["password"].(string)

	if !identifierRe.MatchString(name) {
		return "", fmt.Errorf("invalid db_name %q (must match %s)", name, identifierRe.String())
	}
	if !identifierRe.MatchString(username) {
		return "", fmt.Errorf("invalid username %q (must match %s)", username, identifierRe.String())
	}
	if len(password) < 16 {
		return "", fmt.Errorf("password must be at least 16 characters")
	}

	db, err := mariaDBConn()
	if err != nil {
		return "", err
	}
	defer db.Close()

	var exists string
	if err := db.QueryRowContext(ctx, "SHOW DATABASES LIKE ?", name).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("database %q does not exist", name)
		}
		return "", fmt.Errorf("check database exists: %w", err)
	}

	progress("creating scoped user " + username)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE USER IF NOT EXISTS `%s`@'localhost' IDENTIFIED BY ?", username), password); err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO `%s`@'localhost'", name, username)); err != nil {
		return "", fmt.Errorf("grant privileges: %w", err)
	}
	if _, err := db.ExecContext(ctx, "FLUSH PRIVILEGES"); err != nil {
		return "", fmt.Errorf("flush privileges: %w", err)
	}

	out, _ := json.Marshal(dbUserResult{DBName: name, Username: username})
	return string(out), nil
}

// handleDBDeleteUser drops a single scoped user without touching the
// database itself — the counterpart to handleDBCreateUser, and separate
// from handleDBDelete so removing one of several users on a shared
// database never risks the DROP DATABASE codepath.
func handleDBDeleteUser(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	username, _ := params["username"].(string)
	if !identifierRe.MatchString(username) {
		return "", fmt.Errorf("invalid username %q", username)
	}

	db, err := mariaDBConn()
	if err != nil {
		return "", err
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS `%s`@'localhost'", username)); err != nil {
		return "", fmt.Errorf("drop user: %w", err)
	}
	return fmt.Sprintf("user %q deleted", username), nil
}

func handleDBDelete(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	name, _ := params["name"].(string)
	owner, _ := params["owner_user"].(string)
	if !identifierRe.MatchString(name) {
		return "", fmt.Errorf("invalid database name %q", name)
	}

	db, err := mariaDBConn()
	if err != nil {
		return "", err
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", name)); err != nil {
		return "", fmt.Errorf("drop database: %w", err)
	}
	if owner != "" {
		if !identifierRe.MatchString(owner) {
			return "", fmt.Errorf("invalid owner_user %q", owner)
		}
		db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS `%s`@'localhost'", owner))
	}
	return fmt.Sprintf("database %q deleted", name), nil
}

func handleDBList(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	db, err := mariaDBConn()
	if err != nil {
		return "", err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, "SHOW DATABASES")
	if err != nil {
		return "", fmt.Errorf("show databases: %w", err)
	}
	defer rows.Close()

	systemDBs := map[string]bool{"information_schema": true, "mysql": true, "performance_schema": true, "sys": true}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			continue
		}
		if !systemDBs[n] {
			names = append(names, n)
		}
	}
	return fmt.Sprintf("%v", names), nil
}
