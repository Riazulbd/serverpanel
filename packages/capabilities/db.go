package capabilities

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"

	_ "github.com/go-sql-driver/mysql"
)

// identifierRe is the allow-list for database/user names. MySQL has no
// placeholder syntax for identifiers (only for values), so the standard
// safe approach — used here — is to validate against a strict charset
// before backtick-quoting and interpolating, never to accept an arbitrary
// string into a CREATE DATABASE/USER statement.
var identifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// ValidIdentifier reports whether s is safe to use as a MySQL/MariaDB
// database or user name by db.create/db.delete. Exported so callers that
// need to validate a name before ever dispatching a task to the agent
// (e.g. the control plane's HTTP handlers) can fail fast using the exact
// same rule the agent will enforce, instead of maintaining a second copy
// of the pattern that could drift out of sync.
func ValidIdentifier(s string) bool {
	return identifierRe.MatchString(s)
}

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

	return fmt.Sprintf("database %q created, owned by user %q with grants scoped to that database only", name, owner), nil
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
