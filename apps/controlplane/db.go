package main

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// openDB opens (creating if necessary) the control plane's persistent
// SQLite database and applies the schema. SQLite is a pragmatic choice for
// the Phase 1 skeleton: a single durable file, no external service to run,
// real transactions/persistence across restarts. docs/architecture.md
// already calls out Postgres as the production backing store — swapping it
// in later only touches this file and the DSN, since every caller goes
// through the store type's method set, never raw SQL.
//
// SetMaxOpenConns(1) avoids SQLITE_BUSY errors under concurrent goroutines;
// this control plane's write volume (server/task/audit events) is nowhere
// near where that serialization would matter.
func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrateSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	return db, nil
}

// migrateSchema adds columns that were introduced after a table's initial
// CREATE TABLE IF NOT EXISTS — that statement only ever creates a brand new
// table, so a database file from before a column was added needs an
// explicit, idempotent ALTER TABLE here. This is deliberately a small,
// hand-written list rather than a migration framework: additive-only
// (never drops/renames a column, never touches existing data), which is all
// this project's schema evolution has needed so far — see db.go's package
// doc comment on Postgres being the eventual production store.
func migrateSchema(db *sql.DB) error {
	migrations := []struct {
		table, column, ddl string
	}{
		{"backups", "db_name", `ALTER TABLE backups ADD COLUMN db_name TEXT NOT NULL DEFAULT ''`},
	}
	for _, m := range migrations {
		has, err := columnExists(db, m.table, m.column)
		if err != nil {
			return fmt.Errorf("check column %s.%s: %w", m.table, m.column, err)
		}
		if has {
			continue
		}
		if _, err := db.Exec(m.ddl); err != nil {
			return fmt.Errorf("add column %s.%s: %w", m.table, m.column, err)
		}
	}
	return nil
}

// columnExists uses PRAGMA table_info rather than a schema string match, so
// it can't be fooled by column ordering or formatting differences. table is
// always one of this file's own fixed constants (see migrateSchema), never
// caller-supplied, so building the PRAGMA statement with fmt.Sprintf here
// is safe — SQLite's PRAGMA syntax doesn't accept a bound parameter for the
// table name anyway.
func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

const schema = `
CREATE TABLE IF NOT EXISTS servers (
	id             TEXT PRIMARY KEY,
	name           TEXT NOT NULL,
	grp            TEXT NOT NULL DEFAULT '',
	tags_json      TEXT NOT NULL DEFAULT '[]',
	status         TEXT NOT NULL,
	cert_serial    TEXT NOT NULL DEFAULT '',
	created_at     TEXT NOT NULL,
	last_seen      TEXT,
	agent_version  TEXT NOT NULL DEFAULT '',
	heartbeat_json TEXT
);

CREATE TABLE IF NOT EXISTS bootstrap_tokens (
	hash       TEXT PRIMARY KEY,
	server_id  TEXT NOT NULL REFERENCES servers(id),
	expires_at TEXT NOT NULL,
	used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS revoked_certs (
	serial     TEXT PRIMARY KEY,
	server_id  TEXT NOT NULL,
	revoked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
	seq       INTEGER PRIMARY KEY AUTOINCREMENT,
	at        TEXT NOT NULL,
	server_id TEXT NOT NULL DEFAULT '',
	actor     TEXT NOT NULL DEFAULT '',
	action    TEXT NOT NULL,
	detail    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS users (
	id            TEXT PRIMARY KEY,
	email         TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	totp_secret   TEXT NOT NULL DEFAULT '',
	totp_enabled  INTEGER NOT NULL DEFAULT 0,
	created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	token_hash   TEXT PRIMARY KEY,
	user_id      TEXT NOT NULL REFERENCES users(id),
	created_at   TEXT NOT NULL,
	expires_at   TEXT NOT NULL,
	mfa_verified INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sites (
	id           TEXT PRIMARY KEY,
	server_id    TEXT NOT NULL REFERENCES servers(id),
	domain       TEXT NOT NULL,
	system_user  TEXT NOT NULL,
	docroot      TEXT NOT NULL,
	app_type     TEXT NOT NULL,
	php_version  TEXT NOT NULL DEFAULT '',
	status       TEXT NOT NULL DEFAULT 'active',
	created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backups (
	id         TEXT PRIMARY KEY,
	server_id  TEXT NOT NULL REFERENCES servers(id),
	site_id    TEXT NOT NULL DEFAULT '',
	scope      TEXT NOT NULL,
	path       TEXT NOT NULL,
	size_bytes INTEGER NOT NULL DEFAULT 0,
	sha256     TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL,
	created_at TEXT NOT NULL,
	db_name    TEXT NOT NULL DEFAULT ''
);
`
