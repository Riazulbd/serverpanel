# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-17 — Backup restore: `backup.restore` capability, dedicated backup API, dashboard UI

Closes the single largest functional gap flagged by the previous session (`SYSTEM.md`
§19/§21, `OPERATIONS.md` §3): backups could be created but never restored.

- **Agent**: new `backup.restore` capability
  (`packages/capabilities/backup.go`). Verifies the target archive's SHA-256 against
  the value recorded at backup time before touching anything (refuses a
  corrupted/tampered archive); always takes a fresh checkpoint backup of the restore
  destination's *current* state first, so a bad restore is itself recoverable; then
  restores the database (`mysql` import) and/or files (`cp -a` after clearing the
  target directory, then `chown` back to the site's system user). Also refactored
  `backup.run`'s archive format to a stable, scope-independent layout
  (`manifest.json` + `db.sql` + `files/` at fixed relative paths) so restore never has
  to guess where the dump/files live inside an archive — the previous format tarred
  the DB dump from a randomly-named temp path, which restore couldn't reliably locate.
  New capability constant `CapBackupRestore`, registered in `Default()`.
- **Control plane**: new `apps/controlplane/backups.go` with
  `POST/GET /api/v1/servers/{id}/sites/{siteId}/backups` (dispatch `backup.run`,
  persist the result — same "dispatch, then persist only on success" pattern as
  `handleCreateSite`) and `POST /api/v1/servers/{id}/backups/{backupId}/restore`
  (dispatch `backup.restore` using the stored record's own path/checksum/scope — no
  restore-target parameters accepted from the caller — and persist the agent's
  pre-restore checkpoint as its own first-class, restorable backup row). Added
  `store.getSite`, `store.createBackup`, `store.getBackup`, `store.listBackups`, and a
  `backups.db_name` column with a guarded `ALTER TABLE` migration for databases
  created before this column existed (`migrateAddColumnIfMissing` in `db.go`).
- **Dashboard**: a "Backups" panel per site (button on each site's row) — create a
  backup (scope + optional database name), list existing backups and checkpoints with
  size/timestamp/status, and restore any of them with a confirmation dialog explaining
  that a pre-restore checkpoint will be taken first.
- **Tests**: a real files-scope `backup.run` → `backup.restore` round trip (backs up a
  real directory tree, corrupts/deletes files, restores, verifies exact content is
  back) plus archive-path traversal rejection, checksum-mismatch rejection (verifying
  the target is left untouched), and scope/system-user validation
  (`packages/capabilities/backup_test.go`, 8 tests); store-level backup CRUD and the
  `db_name` column migration against a simulated pre-migration database
  (`apps/controlplane/store_test.go`); HTTP-level request validation for both new
  endpoints, including that a backup belonging to a different server 404s on restore
  rather than being restorable by ID-guessing (`apps/controlplane/http_test.go`). Total
  suite: 60 test functions (was 48), all passing, `go vet`/`gofmt` clean. The db-scope
  backup/restore path still needs a live MariaDB to exercise for real — same category
  as `db.create/delete/list`, see `docs/TESTING.md` §2/§5.
- Updated `docs/API.md`, `docs/SYSTEM.md`, `docs/OPERATIONS.md`, and `docs/TESTING.md`
  to describe the new endpoints/capability and remove the now-stale "restore not
  implemented" gap notes.

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
