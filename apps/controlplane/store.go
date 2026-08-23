package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// store is the control plane's persistence layer, backed by SQLite (see
// db.go). Every method is a small, focused SQL statement — no caller
// builds queries itself, which is what keeps this swappable for Postgres
// later without touching apps/controlplane/http.go or gateway.go.
type store struct {
	db *sql.DB
}

type serverStatus string

const (
	statusPending      serverStatus = "pending"      // created, awaiting agent registration
	statusConnected    serverStatus = "connected"    // mTLS session currently open
	statusOffline      serverStatus = "offline"      // registered, no active connection
	statusDisconnected serverStatus = "disconnected" // explicitly revoked by the user
)

type serverRecord struct {
	ID            string
	Name          string
	Group         string
	Tags          []string
	Status        serverStatus
	CertSerial    string
	CreatedAt     time.Time
	LastSeen      time.Time
	AgentVer      string
	LastHeartbeat *heartbeatSnapshot
}

type heartbeatSnapshot struct {
	UptimeSecs  int64
	LoadAvg1    float64
	MemUsedPct  float64
	DiskUsedPct float64
	At          time.Time
}

type auditEntry struct {
	Seq      int
	At       time.Time
	ServerID string
	Actor    string
	Action   string
	Detail   string
}

func newStore(db *sql.DB) *store {
	return &store{db: db}
}

// log appends an audit entry. actor is the authenticated user's email/id
// for user-initiated actions, or "" for system/agent-originated events
// (e.g. a heartbeat-driven status change).
func (s *store) log(serverID, actor, action, detail string) {
	_, err := s.db.Exec(
		`INSERT INTO audit_log (at, server_id, actor, action, detail) VALUES (?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano), serverID, actor, action, detail,
	)
	if err != nil {
		// Audit logging failures must never be silently swallowed in a
		// production system (they'd undermine the audit trail's
		// completeness guarantee); for this skeleton, surface it loudly.
		fmt.Printf("AUDIT LOG WRITE FAILED: %v (action=%s server=%s)\n", err, action, serverID)
	}
}

// createServer creates a pending server record and a fresh single-use,
// short-lived bootstrap token for it. Only the token's hash is retained;
// the plaintext is returned once, to the caller, for embedding in the
// one-time install command.
func (s *store) createServer(name, group string, tags []string, ttl time.Duration, actor string) (id string, token string, err error) {
	id = randID("srv")
	tagsJSON, _ := json.Marshal(tags)

	_, err = s.db.Exec(
		`INSERT INTO servers (id, name, grp, tags_json, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, name, group, string(tagsJSON), string(statusPending), time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return "", "", fmt.Errorf("insert server: %w", err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])
	expiresAt := time.Now().Add(ttl)

	_, err = s.db.Exec(
		`INSERT INTO bootstrap_tokens (hash, server_id, expires_at) VALUES (?, ?, ?)`,
		hashHex, id, expiresAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return "", "", fmt.Errorf("insert bootstrap token: %w", err)
	}

	s.log(id, actor, "server.created", fmt.Sprintf("name=%q group=%q", name, group))
	s.log(id, actor, "bootstrap_token.issued", fmt.Sprintf("expires_at=%s", expiresAt.Format(time.RFC3339)))
	return id, token, nil
}

// redeemToken atomically validates and consumes a bootstrap token inside a
// transaction, so two concurrent registration attempts with the same token
// can never both succeed. The plaintext token is never logged by this
// method or its caller — only the server ID and outcome are.
func (s *store) redeemToken(token string) (serverID string, err error) {
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var used int
	var expiresAt string
	row := tx.QueryRow(`SELECT server_id, used, expires_at FROM bootstrap_tokens WHERE hash = ?`, hashHex)
	if err := row.Scan(&serverID, &used, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("unknown or already-consumed token")
		}
		return "", err
	}
	if used != 0 {
		return "", fmt.Errorf("token already used")
	}
	exp, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || time.Now().After(exp) {
		tx.Exec(`DELETE FROM bootstrap_tokens WHERE hash = ?`, hashHex)
		tx.Commit()
		return "", fmt.Errorf("token expired")
	}

	// Single-use: consumed tokens are deleted outright rather than merely
	// flagged, so they can never be inspected or replayed even by direct
	// DB access.
	if _, err := tx.Exec(`DELETE FROM bootstrap_tokens WHERE hash = ?`, hashHex); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return serverID, nil
}

func (s *store) revokeToken(serverID, actor string) {
	s.db.Exec(`DELETE FROM bootstrap_tokens WHERE server_id = ?`, serverID)
	s.log(serverID, actor, "bootstrap_token.revoked", "")
}

func (s *store) markIssuedCert(serverID, serial string) {
	s.db.Exec(`UPDATE servers SET cert_serial = ?, status = ? WHERE id = ?`, serial, string(statusOffline), serverID)
	s.log(serverID, "", "agent.registered", fmt.Sprintf("cert_serial=%s", serial))
}

func (s *store) isRevoked(serial string) bool {
	var n int
	s.db.QueryRow(`SELECT COUNT(1) FROM revoked_certs WHERE serial = ?`, serial).Scan(&n)
	return n > 0
}

// revokeServer revokes the server's issued certificate and marks it
// disconnected. Re-connecting requires a brand new bootstrap token —
// there is no path back to trust from a revoked certificate.
func (s *store) revokeServer(serverID, actor string) error {
	rec, ok := s.get(serverID)
	if !ok {
		return fmt.Errorf("server not found")
	}
	if rec.CertSerial != "" {
		_, err := s.db.Exec(
			`INSERT OR REPLACE INTO revoked_certs (serial, server_id, revoked_at) VALUES (?, ?, ?)`,
			rec.CertSerial, serverID, time.Now().UTC().Format(time.RFC3339Nano),
		)
		if err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`UPDATE servers SET status = ? WHERE id = ?`, string(statusDisconnected), serverID); err != nil {
		return err
	}
	s.log(serverID, actor, "agent.revoked", fmt.Sprintf("cert_serial=%s", rec.CertSerial))
	return nil
}

func (s *store) setConnected(serverID string, connected bool) {
	rec, ok := s.get(serverID)
	if !ok {
		return
	}
	newStatus := statusOffline
	if connected {
		newStatus = statusConnected
	} else if rec.Status == statusDisconnected {
		newStatus = statusDisconnected
	}
	s.db.Exec(`UPDATE servers SET status = ?, last_seen = ? WHERE id = ?`,
		string(newStatus), time.Now().UTC().Format(time.RFC3339Nano), serverID)
}

func (s *store) setAgentVersion(serverID, version string) {
	s.db.Exec(`UPDATE servers SET agent_version = ? WHERE id = ?`, version, serverID)
}

func (s *store) recordHeartbeat(serverID string, hb heartbeatSnapshot) {
	hbJSON, _ := json.Marshal(hb)
	s.db.Exec(`UPDATE servers SET heartbeat_json = ?, last_seen = ? WHERE id = ?`,
		string(hbJSON), hb.At.Format(time.RFC3339Nano), serverID)
}

func (s *store) get(serverID string) (*serverRecord, bool) {
	row := s.db.QueryRow(
		`SELECT id, name, grp, tags_json, status, cert_serial, created_at, last_seen, agent_version, heartbeat_json
		 FROM servers WHERE id = ?`, serverID)
	rec, err := scanServer(row)
	if err != nil {
		return nil, false
	}
	return rec, true
}

func (s *store) list() []*serverRecord {
	rows, err := s.db.Query(
		`SELECT id, name, grp, tags_json, status, cert_serial, created_at, last_seen, agent_version, heartbeat_json
		 FROM servers ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []*serverRecord
	for rows.Next() {
		rec, err := scanServer(rows)
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// rowScanner abstracts over *sql.Row and *sql.Rows, which share Scan but no
// common interface in database/sql.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanServer(row rowScanner) (*serverRecord, error) {
	var rec serverRecord
	var tagsJSON string
	var lastSeen, heartbeatJSON sql.NullString
	var createdAt string

	if err := row.Scan(&rec.ID, &rec.Name, &rec.Group, &tagsJSON, &rec.Status, &rec.CertSerial,
		&createdAt, &lastSeen, &rec.AgentVer, &heartbeatJSON); err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(tagsJSON), &rec.Tags)
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	if lastSeen.Valid {
		rec.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen.String)
	}
	if heartbeatJSON.Valid && heartbeatJSON.String != "" {
		var hb heartbeatSnapshot
		if json.Unmarshal([]byte(heartbeatJSON.String), &hb) == nil {
			rec.LastHeartbeat = &hb
		}
	}
	return &rec, nil
}

// maxKnownCertSerial scans every serial this control plane has ever issued
// or revoked and returns the highest one seen (0 if none), so a freshly
// loaded CA's serial counter can be seeded above it — see
// loadOrCreateAgentCA.
func (s *store) maxKnownCertSerial() int64 {
	var max int64
	rows, err := s.db.Query(`SELECT cert_serial FROM servers WHERE cert_serial != '' UNION SELECT serial FROM revoked_certs`)
	if err != nil {
		return 0
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if rows.Scan(&s) != nil {
			continue
		}
		var n int64
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n > max {
			max = n
		}
	}
	return max
}

func (s *store) auditLog() []auditEntry {
	rows, err := s.db.Query(`SELECT seq, at, server_id, actor, action, detail FROM audit_log ORDER BY seq DESC LIMIT 500`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []auditEntry
	for rows.Next() {
		var e auditEntry
		var at string
		if err := rows.Scan(&e.Seq, &at, &e.ServerID, &e.Actor, &e.Action, &e.Detail); err != nil {
			continue
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, e)
	}
	return out
}

type siteRecord struct {
	ID         string
	ServerID   string
	Domain     string
	SystemUser string
	Docroot    string
	AppType    string
	PHPVersion string
	Status     string
	CreatedAt  time.Time
}

func (s *store) listSites(serverID string) []*siteRecord {
	rows, err := s.db.Query(
		`SELECT id, server_id, domain, system_user, docroot, app_type, php_version, status, created_at
		 FROM sites WHERE server_id = ? ORDER BY created_at DESC`, serverID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []*siteRecord
	for rows.Next() {
		var rec siteRecord
		var createdAt string
		if err := rows.Scan(&rec.ID, &rec.ServerID, &rec.Domain, &rec.SystemUser, &rec.Docroot,
			&rec.AppType, &rec.PHPVersion, &rec.Status, &createdAt); err != nil {
			continue
		}
		rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		out = append(out, &rec)
	}
	return out
}

func (s *store) createSite(serverID, domain, systemUser, docroot, appType, phpVersion string) (*siteRecord, error) {
	rec := &siteRecord{
		ID: randID("site"), ServerID: serverID, Domain: domain, SystemUser: systemUser,
		Docroot: docroot, AppType: appType, PHPVersion: phpVersion, Status: "active", CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.Exec(
		`INSERT INTO sites (id, server_id, domain, system_user, docroot, app_type, php_version, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.ServerID, rec.Domain, rec.SystemUser, rec.Docroot, rec.AppType, rec.PHPVersion, rec.Status,
		rec.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// getSite looks up one site scoped to serverID, so a caller can never
// address a site belonging to a server it didn't ask about (e.g. a
// backup/restore request for site X on server A can't be redirected at
// site X's docroot if X actually belongs to server B).
func (s *store) getSite(serverID, siteID string) (*siteRecord, bool) {
	row := s.db.QueryRow(
		`SELECT id, server_id, domain, system_user, docroot, app_type, php_version, status, created_at
		 FROM sites WHERE id = ? AND server_id = ?`, siteID, serverID)
	var rec siteRecord
	var createdAt string
	if err := row.Scan(&rec.ID, &rec.ServerID, &rec.Domain, &rec.SystemUser, &rec.Docroot,
		&rec.AppType, &rec.PHPVersion, &rec.Status, &createdAt); err != nil {
		return nil, false
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return &rec, true
}

type backupRecord struct {
	ID        string
	ServerID  string
	SiteID    string
	Scope     string
	Path      string
	DBName    string
	SizeBytes int64
	SHA256    string
	Status    string
	CreatedAt time.Time
}

// createBackup persists a backup record. This is only ever called after
// backup.run has already succeeded on the agent (see backups.go
// handleCreateBackup) — the backups table records completed, verified
// backups, never in-flight or attempted ones.
func (s *store) createBackup(serverID, siteID, scope, path, dbName string, sizeBytes int64, sha256sum string) (*backupRecord, error) {
	rec := &backupRecord{
		ID: randID("backup"), ServerID: serverID, SiteID: siteID, Scope: scope, Path: path,
		DBName: dbName, SizeBytes: sizeBytes, SHA256: sha256sum, Status: "complete", CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.Exec(
		`INSERT INTO backups (id, server_id, site_id, scope, path, db_name, size_bytes, sha256, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.ServerID, rec.SiteID, rec.Scope, rec.Path, rec.DBName, rec.SizeBytes, rec.SHA256, rec.Status,
		rec.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// listBackups returns backups for one site, newest first. siteID must be
// non-empty: every backup this control plane creates is created through the
// per-site endpoint (see backups.go), so there is always a site to scope
// the list to.
func (s *store) listBackups(serverID, siteID string) []*backupRecord {
	rows, err := s.db.Query(
		`SELECT id, server_id, site_id, scope, path, db_name, size_bytes, sha256, status, created_at
		 FROM backups WHERE server_id = ? AND site_id = ? ORDER BY created_at DESC`, serverID, siteID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []*backupRecord
	for rows.Next() {
		rec, err := scanBackup(rows)
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// getBackup looks up one backup scoped to serverID, for the same
// cross-tenant-addressing reason getSite is scoped to serverID.
func (s *store) getBackup(serverID, backupID string) (*backupRecord, bool) {
	row := s.db.QueryRow(
		`SELECT id, server_id, site_id, scope, path, db_name, size_bytes, sha256, status, created_at
		 FROM backups WHERE id = ? AND server_id = ?`, backupID, serverID)
	rec, err := scanBackup(row)
	if err != nil {
		return nil, false
	}
	return rec, true
}

type databaseRecord struct {
	ID        string
	ServerID  string
	SiteID    string
	Name      string
	OwnerUser string
	Engine    string
	Status    string
	CreatedAt time.Time
}

// createDatabase persists a database record. Like createBackup, this is
// only ever called after db.create has already succeeded on the agent (see
// databases.go handleCreateDatabase) — the databases table records
// databases that actually exist on the server, never attempted ones. The
// owner user's password is deliberately not a field here: it is generated
// per-request, handed to the agent to set, returned to the caller exactly
// once in the API response, and never persisted anywhere in this store —
// the same "shown once" treatment createServer gives bootstrap tokens.
func (s *store) createDatabase(serverID, siteID, name, ownerUser, engine string) (*databaseRecord, error) {
	rec := &databaseRecord{
		ID: randID("db"), ServerID: serverID, SiteID: siteID, Name: name, OwnerUser: ownerUser,
		Engine: engine, Status: "active", CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.Exec(
		`INSERT INTO databases (id, server_id, site_id, name, owner_user, engine, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.ServerID, rec.SiteID, rec.Name, rec.OwnerUser, rec.Engine, rec.Status,
		rec.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// listDatabases returns every database record for one server, newest first.
func (s *store) listDatabases(serverID string) []*databaseRecord {
	rows, err := s.db.Query(
		`SELECT id, server_id, site_id, name, owner_user, engine, status, created_at
		 FROM databases WHERE server_id = ? ORDER BY created_at DESC`, serverID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []*databaseRecord
	for rows.Next() {
		rec, err := scanDatabase(rows)
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// getDatabase looks up one database scoped to serverID, for the same
// cross-tenant-addressing reason getSite/getBackup are scoped to serverID.
func (s *store) getDatabase(serverID, databaseID string) (*databaseRecord, bool) {
	row := s.db.QueryRow(
		`SELECT id, server_id, site_id, name, owner_user, engine, status, created_at
		 FROM databases WHERE id = ? AND server_id = ?`, databaseID, serverID)
	rec, err := scanDatabase(row)
	if err != nil {
		return nil, false
	}
	return rec, true
}

// deleteDatabaseRecord removes a database's control-plane record. Only ever
// called after db.delete has already succeeded on the agent (see
// databases.go handleDeleteDatabase) — a record here means the database
// actually exists on the server; deleting it here means it no longer does.
func (s *store) deleteDatabaseRecord(serverID, databaseID string) error {
	res, err := s.db.Exec(`DELETE FROM databases WHERE id = ? AND server_id = ?`, databaseID, serverID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("database not found")
	}
	return nil
}

func scanDatabase(row rowScanner) (*databaseRecord, error) {
	var rec databaseRecord
	var createdAt string
	if err := row.Scan(&rec.ID, &rec.ServerID, &rec.SiteID, &rec.Name, &rec.OwnerUser, &rec.Engine, &rec.Status, &createdAt); err != nil {
		return nil, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return &rec, nil
}

func scanBackup(row rowScanner) (*backupRecord, error) {
	var rec backupRecord
	var createdAt string
	if err := row.Scan(&rec.ID, &rec.ServerID, &rec.SiteID, &rec.Scope, &rec.Path, &rec.DBName,
		&rec.SizeBytes, &rec.SHA256, &rec.Status, &createdAt); err != nil {
		return nil, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return &rec, nil
}

func randID(prefix string) string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return fmt.Sprintf("%s_%x", prefix, n)
}
