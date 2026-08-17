# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-17 — Backup restore capability and control-plane persistence

- Added the `backup.restore` agent capability (`packages/capabilities/backup.go`),
  closing the single largest functional gap flagged in the previous session's
  documentation pass (`SYSTEM.md` §19/§21): restore was previously not implemented at
  all, only `backup.run`. Restore verifies the archive's SHA-256 against the checksum
  recorded at backup time before touching anything, takes a fresh pre-restore
  checkpoint backup of current live state first (aborting untouched if that checkpoint
  fails), extracts to a scratch directory and validates it can locate the expected
  dump/site content, then restores the database (`mysql <db_name> < dump.sql`) and/or
  files (`cp -a` over the live site directory, re-applying ownership). Backup-archive
  creation was refactored into a shared `performBackup` helper used by both
  `backup.run` and the restore checkpoint, so there is exactly one code path that
  writes an archive.
- Wired the control plane to actually use the `backups` table that already existed in
  the schema but had no store methods, no API route, and nothing writing to it:
  `store.createBackup/listBackups/getBackup` (`apps/controlplane/store.go`), and three
  new endpoints (`apps/controlplane/backups.go`) — `POST`/`GET
  /api/v1/servers/{id}/backups` and `POST /api/v1/servers/{id}/backups/{backupId}/
  restore`. Restore's `expected_sha256`/`backup_path` are read from the control
  plane's own database, never accepted from the request body, so the checksum check
  can't be bypassed by a caller supplying its own value.
- Added an additive, idempotent schema-migration mechanism (`migrateSchema` in
  `apps/controlplane/db.go`, using `PRAGMA table_info` to check for a column before
  `ALTER TABLE ADD COLUMN`) for the new `backups.db_name` column, since `CREATE TABLE
  IF NOT EXISTS` alone doesn't add a column to a database file created before that
  column existed. Covered by a test that recreates the pre-migration table shape and
  confirms `openDB` migrates it in place.
- Added 16 new test functions: `packages/capabilities/backup_test.go` (validation,
  checksum-mismatch rejection, path-traversal/backupBaseDir-escape rejection, and a
  real end-to-end files-scope backup→mutate→restore→verify round trip against actual
  `tar`/`cp`/`chown`) and additions to `apps/controlplane/store_test.go`/`http_test.go`
  (backup persistence round trip, the schema-migration test above, and HTTP-level
  request validation for the new endpoints, including confirming a failed dispatch
  never leaves an orphan `backups` row). `db`/`full` scope (which need a real
  `mysqldump`/`mysql`) remain manually-verified-only, same limitation `db.create/
  delete/list` already had — no MariaDB instance is available in this environment; see
  `TESTING.md` §2.
- Updated `docs/SYSTEM.md`, `docs/API.md`, `docs/ARCHITECTURE.md`,
  `docs/OPERATIONS.md`, and `docs/TESTING.md` to reflect the new capability, endpoints,
  test counts, and the restore implementation's documented limitations (same-server
  only; file restore is create/overwrite, not delete-then-replace, to avoid ever
  recursive-deleting a live site directory as a side effect; no dashboard UI yet).

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
