# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-16 — Backup restore capability, wired end-to-end

Closes the single largest functional gap flagged in the prior entry below: there was
no way to restore a backup, only create one.

- **Agent**: added the `backup.restore` capability
  (`packages/capabilities/backup.go`). It confines `backup_path` to the agent's own
  backup directory, verifies the archive's SHA-256 against the checksum recorded at
  backup time before touching anything, takes a fresh pre-restore checkpoint backup of
  the current state by default, then restores files (staged via `cp -a` and swapped
  into place with same-directory renames — the previous directory is moved aside, not
  deleted, with a best-effort rollback if the final swap fails) and/or a database
  (extracted `.sql` dump piped into `mysql <db_name>` on stdin). Refactored the shared
  dump/tar/checksum logic out of `handleBackupRun` into `createBackupArchive` so both
  the regular backup path and the restore path's checkpoint step use the same,
  already-tested code.
- **Control plane**: added `POST /api/v1/servers/{id}/backups` (dispatches
  `backup.run`, persists a `backups` row only on success — same pattern as
  `handleCreateSite`), `GET /api/v1/servers/{id}/backups`, and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` (dispatches `backup.restore`
  using the exact site/database/checksum recorded for that backup — never a
  caller-supplied override, so a restore can't be pointed at the wrong database or a
  tampered archive). Added a `db_name` column to the `backups` table via a new
  best-effort `applyMigrations` step in `db.go` (no migration tool exists yet — see
  `docs/SYSTEM.md` §8), since the column postdates the table's original
  `CREATE TABLE IF NOT EXISTS`.
- **Dashboard**: added a "Backups" panel to the server-detail view — start a
  files/db/full backup against a site, see recorded backups with size and checksum,
  and restore one with a confirmation prompt.
- **Tests**: 8 new test functions, all against real filesystem/SQLite operations, no
  mocks — including a full end-to-end round trip in
  `packages/capabilities/backup_test.go` that backs up a real site directory, mutates
  it (simulating a bad deploy), restores it, and confirms both that the original
  content came back *and* that the pre-restore checkpoint captured the mutated state,
  not the restored one. `go test ./...` is now 56 test functions (was 48), all
  passing; `go build ./...`, `go vet ./...`, and `gofmt -l .` all clean.
- **Known limitation this doesn't close**: restore only works on the same server a
  backup was taken on — cross-server restore needs either transferring the archive
  between agents or remote (S3-compatible) storage, neither of which exist yet. The
  `db`/`full` scope of both `backup.run` and `backup.restore` also still has no
  automated test coverage, since this environment has no MariaDB installed to restore
  into — see `docs/TESTING.md` §5 for the recommended next step (a scripted real-VPS/
  container integration pass).
- Updated `docs/SYSTEM.md`, `docs/API.md`, `docs/OPERATIONS.md`,
  `docs/ARCHITECTURE.md`, and `docs/TESTING.md` to reflect all of the above.

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
