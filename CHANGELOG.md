# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-19 — Database control-plane persistence + dashboard UI, real MariaDB test coverage

- **Closed DB-005** (`docs/SERVERAVATAR_PARITY.md`): databases created via `db.create` are
  now persisted as first-class `databases` rows (`apps/controlplane/db.go` schema,
  `store.go` `createDatabaseRecord`/`listDatabases`/`getDatabaseRecord`/
  `deleteDatabaseRecord`, all scoped by server ID the same way sites/backups are) instead
  of existing only as an ephemeral task result — the same dispatch-then-persist-on-success
  pattern `handleCreateSite`/`handleCreateBackup` already use. New endpoints:
  `GET`/`POST /api/v1/servers/{id}/sites/{siteId}/databases`,
  `DELETE /api/v1/servers/{id}/databases/{databaseId}`.
- The control plane now generates the database owner's password itself
  (`crypto/rand`, 24 bytes) instead of expecting the caller to supply one, and returns it
  exactly once in the create response — the same "shown once, never persisted" pattern
  already used for bootstrap install tokens. The `databases` table stores the owner
  *username* only, never a password or password hash.
- Added a "Databases" panel to the site-detail dashboard view (create modal with
  one-time password display, list table, delete with a destructive-action confirmation).
- `packages/capabilities/db.go`'s `db.create`/`db.delete` now return structured JSON
  (`dbResult{name, owner_user}`) instead of a human-readable string, matching
  `backupResult`/the site-create result shape, so the control plane can parse them.
- **Installed a real MariaDB instance in this session's environment** (previously absent,
  which is why DB-001/BAK-001/BAK-002's db-scope paths were only manually verified in a
  prior session) and added `packages/capabilities/db_test.go`: 4 new tests, including a
  real create → connect-as-owner → verify least-privilege isolation (owner user can use
  its own database but is rejected from an unrelated one) → delete round trip against a
  live server — the first automated test coverage `db.go` has ever had. Tests skip
  cleanly (not fail) when no MariaDB is reachable, matching the existing
  `ensureTestSystemUser`/`newTestSiteRoot` environment-skip pattern.
- Added 2 new control-plane tests (`TestDatabaseCreateListGetDeleteRoundTrip` in
  `store_test.go`, `TestDatabaseEndpointsValidateBeforeDispatch` in `http_test.go`,
  covering not-found/validation/dispatch-ordering boundaries the same way the backup
  endpoint tests do).
- **Found and fixed a real bug in `backup.run`/`backup.restore`'s db/full-scope path**
  (`packages/capabilities/backup.go`), caught by writing the first-ever real-MariaDB
  round-trip test against it (`TestHandleBackupRunAndRestoreDBScopeRoundTrip`,
  `TestHandleBackupRunFullScopeArchivesBothDBAndFiles`): `handleBackupRun` was archiving
  the `mysqldump` output at its absolute temp-file path (e.g.
  `/tmp/sp-backup-XXXXXX/dbname.sql`), so the resulting tar entry was nested under that
  *specific* randomly-generated temp directory name. `handleBackupRestore` looks for the
  dump at `<its own fresh temp dir>/dbname.sql` — since `os.MkdirTemp` generates a new
  random name on every call, backup-time and restore-time temp dirs never match, so the
  dump could never actually be found and every db/full-scope restore would have failed
  with "archive does not contain a database dump". This was invisible until now because
  no environment with a real `mysqldump`/`mysql` to exercise it was available in any
  prior session (tracked honestly as `BLOCKED_EXTERNAL`/manually-verified-only in
  `SERVERAVATAR_PARITY.md`) — files-scope restore worked and was real-tested, masking
  that db-scope was not. Fixed by taring the dump with `tar -C workDir dbname.sql`
  (a flat, reproducible entry name) instead of its absolute path; files-scope is
  unaffected (its path is a fixed, known value at both backup and restore time, unlike
  the throwaway dump temp dir). Both new tests pass against a real MariaDB instance.
- Full suite: 69 test functions, `go build`/`go vet`/`gofmt -l`/`go test ./...` clean.
- Updated `docs/SERVERAVATAR_PARITY.md` (DB-001, DB-005, BAK-001, BAK-002 now
  `COMPLETE`) and `docs/SYSTEM.md`.

## 2026-08-17 — Backup restore, ServerAvatar parity tracking

- **Implemented `backup.restore`** (`packages/capabilities/backup.go`), closing the
  single largest functional gap flagged in the previous entry. Restores a
  `backup.run` archive with, in order: archive-location validation (must resolve to a
  file directly inside the agent's backup directory, never an arbitrary path),
  optional checksum verification against the value `backup.run` originally returned,
  safe extraction via Go's `archive/tar` directly (not a shelled-out `tar`) into a
  private temp directory — rejecting any entry with an absolute path or one that would
  traverse outside it, and skipping anything that isn't a plain file or directory — a
  pre-restore checkpoint backup of the live state taken via `backup.run` itself
  (returned in the result, so a bad restore is always recoverable), then the database
  restore (`mysql` import, streamed from disk, never buffered as a string or passed as
  an argv value) and/or an atomic-as-possible directory swap for files, with ownership
  restored to the site's own system user afterward.
- Wired `backup.restore` (and, previously dispatch-only, `backup.run`) into the control
  plane end-to-end: new `backups` store methods (`createBackup`/`listBackups`/
  `getBackup`, each scoped by server ID the same way `getSite` now is), three new
  endpoints (`GET`/`POST /api/v1/servers/{id}/sites/{siteId}/backups`,
  `POST /api/v1/servers/{id}/backups/{backupId}/restore`), an idempotent
  `db_name` column migration for the pre-existing `backups` table, and a "Backups"
  panel per site in the dashboard (create-backup modal with scope selection, a backups
  table, and a restore button with a destructive-action confirmation dialog).
- Added 9 new capability-layer tests (archive-location/checksum/path-traversal
  rejection, a real files backup→corrupt→restore round trip against a real throwaway
  system user, and `archive/tar` extraction-safety unit tests for path traversal,
  absolute paths, and a decompression-size limit) and 4 new control-plane tests
  (backup CRUD round trip, cross-server scoping for both `getSite` and `getBackup`,
  and HTTP boundary/validation tests for the new endpoints). Full suite: 61 test
  functions, `go vet`/`gofmt` clean.
- Updated `SYSTEM.md`, `API.md`, `OPERATIONS.md`, and `TESTING.md` to reflect restore
  as implemented (same-server only — cross-server restore remains a Phase 2 gap,
  tracked alongside cross-server migration).
- Added `docs/SERVERAVATAR_PARITY.md` and `docs/SERVERAVATAR_DOC_INVENTORY.md`,
  establishing the ongoing feature-parity tracking process against ServerAvatar's
  public product documentation (capability reference only — no ServerAvatar code,
  copy, or design assets used).

## 2026-08-14 — Automated test suite, doc restructuring

- Added `go test` coverage across `apps/controlplane` and `packages/capabilities`
  (48 test functions): session/auth lifecycle, TOTP round-trip and clock-skew
  handling, bootstrap-token single-use/expiry semantics, server create/revoke/
  heartbeat/audit flows, 4 full HTTP integration tests through the real `routes()`
  mux, the `service.control` allow-list boundary (including an explicit shell-
  injection-attempt test), the file manager's path-traversal/symlink-escape defenses,
  log redaction, and domain/system-user validation. All tests run against real SQLite
  and real filesystem operations, not mocks. No defects were found by this pass — see
  `docs/TESTING.md` for what remains manually-verified-only vs. automated.
- Restructured documentation into the project's required doc set: added
  `docs/SYSTEM.md` (comprehensive system reference), `docs/API.md`, `docs/TESTING.md`,
  `docs/OPERATIONS.md`, `docs/INSTALLATION.md`, and this changelog. Renamed
  `docs/architecture.md` → `docs/ARCHITECTURE.md` and
  `docs/security-trust-model.md` → `docs/SECURITY.md`, annotating each section with
  its actual implementation status (several sections, e.g. commit-confirm SSH/
  firewall changes and agent self-update, describe Phase 2 design intent that has no
  code yet — now explicitly labeled rather than left ambiguous). Folded
  `docs/implementation-status.md`'s content into `SYSTEM.md`/`TESTING.md` and removed
  the standalone file to avoid two documents drifting out of sync.
- Documented, rather than silently left implicit, the most significant functional gap
  found while writing this pass: **there is no backup-restore capability yet** (only
  `backup.run`) — flagged in `SYSTEM.md` §19/§21 and `OPERATIONS.md` §3 as the
  recommended next implementation priority.

## 2026-08-14 — Phase 1 build-out: auth/2FA, persistent CA/storage, hosting-stack and site-management capabilities, working dashboard

- Control plane: bcrypt + TOTP (RFC 6238, stdlib-only) authentication, session
  cookies, SQLite-backed persistent storage for users/servers/tokens/audit records,
  an internal agent CA persisted to disk (fixing a bug where the CA regenerated in
  memory on every restart, silently invalidating all registered agents), server
  CRUD, bootstrap-token issuance/redemption/revocation, task dispatch, an
  append-only audit log, and a site-creation endpoint.
- Agent: bootstrap-token registration, persistent reconnecting mTLS session, real
  heartbeats (uptime, load average, memory%, disk%), and the Phase 1 capability set —
  `stack.install` (LEMP profile), `site.create`/`site.set_status`,
  `app.wordpress_install`, `ssl.issue_letsencrypt`/`ssl.install_custom`,
  `db.create/delete/list`, `file.list/read/write/delete`, `backup.run`, `logs.tail`.
- Dashboard: a single self-contained embedded HTML page — login/signup, 2FA
  enrollment, server list with search/filter, server detail with live heartbeat
  stats, site list/create, audit log view.
- Found and fixed during real integration testing against an Ubuntu 24.04 container:
  missing IP SANs on the gateway TLS cert, premature "connected" logging, the CA
  persistence bug above, UFW's incorrect `OpenSSH` app-profile assumption, Composer's
  root-warning-as-version bug, MariaDB's `?`-placeholder limitation inside
  `CREATE USER`, IPv6-related `nginx -t` failures (both in generated vhosts and the
  stock default site), `server_names_hash_bucket_size` sizing, `site.create`
  succeeding without being persisted, and agent version/heartbeat data not being
  saved onto the server record.

## 2026-08-14 — Phase 1 scaffold: control plane and agent (mTLS, allow-listed capabilities)

- Initial Go module scaffold: `apps/controlplane` (public API + agent gateway),
  `apps/agent`, `packages/capabilities` (fixed capability registry, no shell-exec
  entry point), `packages/proto` (shared wire types).
- mTLS agent registration/connection model: bootstrap-token-for-certificate exchange,
  an internal ECDSA CA, a certificate-authenticated gateway listener separate from
  the public API.

## 2026-08-14 — Pre-implementation plan

- Added `docs/product-plan.md`, `docs/architecture.md` (now `ARCHITECTURE.md`), and
  `docs/security-trust-model.md` (now `SECURITY.md`): the architecture comparison
  (centralized control plane vs. per-server local panel), trust model, infra cost
  estimate, data-retention plan, phase/milestone estimates, MVP cost estimate,
  security risk register, and postponed-features list that this project has been
  built against.
