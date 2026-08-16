# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-16 — Backup restore: the capability, control-plane wiring, and dashboard UI

Implements the single largest documented gap in the Phase 1 feature set (flagged
repeatedly across `SYSTEM.md`, `OPERATIONS.md`, and `TESTING.md`): there was a
`backup.run` capability but no way to restore from it. This entry closes that gap
end-to-end — agent capability, control-plane persistence/API, and dashboard UI — not
just the capability in isolation.

- **Agent capability**: added `backup.restore` (`packages/capabilities/backup.go`,
  registered as `CapBackupRestore`). It re-verifies the archive's SHA-256 (if supplied)
  before extracting anything; takes a best-effort pre-restore checkpoint of whatever
  currently occupies the restore target (reusing `backup.run` internally), skipped only
  when the target is genuinely empty (a fresh restore) or `skip_checkpoint` is set;
  restores the database (`mysql <dump.sql`, via a new `runWithStdinFile` exec helper)
  and/or files (`tar` extract → `cp -a` into the target → `chown` to the named system
  user). The restore target (`restore_site_root`/`restore_system_user`/
  `restore_db_name`) is always supplied explicitly rather than inferred from the
  archive, which is what makes restoring to a different site, server, or database name
  the same code path as restoring in place — a deliberate design decision, recorded in
  `SYSTEM.md` §28.
- **Control plane**: the `backups` table (schema already existed, but nothing wrote to
  it) is now actually populated. Added `store.createBackup`/`listBackups`/`getBackup`
  and three endpoints (`apps/controlplane/backups.go`): `POST` and `GET
  /api/v1/servers/{id}/backups` (dispatch `backup.run` and persist only on success, or
  list), and `POST /api/v1/servers/{id}/backups/{backupId}/restore`, which resolves
  `backupId` to its recorded path/checksum server-side — a caller never supplies a raw
  filesystem path, and a backup is only reachable through the server it was recorded
  against (enforced by scoping `getBackup`'s query to `server_id`, tested).
- **Dashboard**: a "Backups" section on the server-detail page (list with scope/size/
  checksum, a "Run backup" modal, and a "Restore..." modal per backup with restore-
  target fields and a "skip pre-restore checkpoint" opt-out), following the same plain
  HTML/`fetch()`/no-build-step pattern as the existing Sites section.
- **Tests**: 14 new test functions. `packages/capabilities/backup_test.go` exercises
  the full capability for real — not mocked — including a files-scope backup→restore
  round trip into a *different* site root and a real system user (created via a real
  `useradd`/`userdel` in the test, matching what `site.create` does in production),
  automatic-checkpoint vs. skipped-when-empty vs. explicit-skip, checksum-mismatch
  rejection (and that nothing is written to the target when it fires), and the
  archive-path/site-root/db-name validation boundaries (traversal, outside the backup
  base directory, non-`/home/sites/` targets, non-identifier DB names). Database-scope
  restore's `mysqldump`/`mysql` invocations are not exercised for real in this
  environment (no MariaDB installed here) — same documented limitation as the rest of
  this project's DB capabilities; see `TESTING.md` §2. `apps/controlplane/store_test.go`
  and `http_test.go` gained coverage for the backup store methods and the parts of the
  backups API reachable without a live agent connection (list, restore-404).
  `go test ./... -race` passes (62 total test functions, up from 48).
- **Verification beyond `go test`**: built the real `controlplane` binary and ran it
  against a temp SQLite DB and a temp CA directory, then drove the real HTTP API with
  `curl` through signup → login → server creation → `GET .../backups` (confirmed
  empty) → `POST .../backups/{unknown}/restore` (confirmed `404`, proving a restore
  request never reaches `gateway.dispatch` for a backup ID this control plane doesn't
  know about) → `POST .../backups` with no agent connected (confirmed `502`, proving
  the dispatch path is reached and fails at the expected point, not earlier). Also
  extracted and syntax-checked the dashboard's embedded JavaScript (`node --check`).
- **Docs updated**: `SYSTEM.md` (§2 feature tables, §12 capability list, §19 backup/
  restore model, §21 known limitations, §28 assumptions, §3 phase status),
  `OPERATIONS.md` §3, `API.md` (new endpoints + request/response shapes), `TESTING.md`
  (§1 coverage tables and counts, §2 what's/isn't covered, §4 this session's
  verification, §5 re-prioritized — real-VPS/container integration testing is now the
  top remaining item, since it's the only way to automatically verify the
  database-restore path and everything else in `TESTING.md` §2 against a real
  MariaDB/systemd instead of a prior session's manual pass).

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
