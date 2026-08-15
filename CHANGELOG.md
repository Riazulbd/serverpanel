# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-15 — Backup restore, SSL auto-renewal, and the backups API/UI

- **Added `backup.restore`**, the capability the previous pass flagged as the single
  largest functional gap (`packages/capabilities/backup.go`). Safety model: it always
  takes a fresh pre-restore checkpoint of the live state before changing anything and
  aborts cleanly if that checkpoint fails; a files/full restore moves the current site
  directory aside (same-filesystem rename) rather than deleting it, rolling back
  automatically if the restored copy can't be put in place; a db restore streams the
  archived dump into `mysql <dbname>` via `cmd.Stdin` (no shell). The archive path is
  validated against path traversal and symlink escape the same way the file manager's
  `resolveScopedPath` already does (`resolveBackupPath`).
- **Control plane**: new `backups` store methods (`createBackup`/`listBackups`/
  `getBackup`/`getSite`) and three new endpoints —
  `POST /api/v1/servers/{id}/sites/{siteId}/backups` (dispatches `backup.run`,
  persists a row only on success, mirroring `handleCreateSite`'s pattern),
  `GET /api/v1/servers/{id}/backups`, and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` (dispatches `backup.restore`
  using the archive path/scope/db name **recorded on the backup**, never anything the
  caller supplies — this is what keeps restore from reaching an arbitrary path or
  database). Added a `db_name` column to the `backups` table via a best-effort
  `ALTER TABLE` run on every `openDB` (there's still no real migration tool — see
  `docs/OPERATIONS.md` §5).
- **Dashboard**: a new Backups panel on the server-detail view — a "Back up" button
  per site (scope + optional DB name modal) and a backups table with size/scope/
  status and a "Restore" button (with a confirmation prompt and the resulting
  checkpoint path shown on completion).
- **SSL auto-renewal**: `stack.install` now explicitly enables `certbot.timer` (it
  isn't always on by default depending on the base image), closing the other gap the
  previous pass's `SYSTEM.md` flagged as missing.
- **Tests**: 9 new test functions. `packages/capabilities/backup_test.go` proves the
  restore path for real — not just parameter validation — with an end-to-end
  files-scope round trip (back up a site, corrupt the live copy, restore, assert it's
  back to exactly the backed-up state and that files added after the backup are gone)
  plus a "restoring site A's archive into site B's root fails and leaves B untouched"
  safety test. `apps/controlplane/store_test.go` and `http_test.go` cover the new
  store methods and the backup API's auth-gating, 404s, and — the important one — that
  a backup can't be restored through a different server's ID. The db-scope restore
  path (`mysql` import) is validated for parameter handling only, since this sandbox
  has no MariaDB installed; see `docs/TESTING.md` for what that leaves for a real-host
  pass.
- Updated `docs/SYSTEM.md`, `docs/API.md`, `docs/OPERATIONS.md`, `docs/ARCHITECTURE.md`,
  and `docs/TESTING.md` to reflect all of the above — restore is no longer listed as
  ⬜, and the remaining real gap is restoring to a *different* server, not restoring at
  all.

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
