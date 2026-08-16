# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-16 — Backup restore capability, closing Phase 1's largest gap

- Added the `backup.restore` agent capability (`packages/capabilities/backup.go`):
  restores a `backup.run` archive's database and/or files. Safety properties: the
  archive path is confined to `backupBaseDir` (symlink-resolved before the
  containment check); an optional expected SHA-256 is verified before anything is
  touched; a same-scope **pre-restore checkpoint** backup is always taken first, and
  the restore aborts with nothing changed if that checkpoint itself fails; every
  subsequent error names the checkpoint path so a failed restore is recoverable.
- Refactored `backup.run`'s archive layout to be stable and restorable: a database
  dump is now always written to `db.sql` and a files backup to a `files/` directory,
  both at the archive root, instead of tar-ing the caller's original absolute paths
  (which put the DB dump under a random per-run temp-directory name a later restore
  had no way to rediscover). Safe to change now, before any restore capability existed
  to depend on the old layout and before any real backup had been taken against it.
- Control plane: `backups` table gained a `db_name` column; new store methods
  (`createBackup`, `listBackups`, `getBackup`, `getSite`); new endpoints
  `POST /api/v1/servers/{id}/backups` (dispatch `backup.run`, persist only on real
  success — same "dispatch then persist" shape as `handleCreateSite`),
  `GET /api/v1/servers/{id}/backups`, and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` (dispatches
  `backup.restore` using the archive path/checksum/scope from the *stored* record
  only, never from request input).
- Dashboard: a Backups section on the server-detail page — create a backup (scope +
  site/db picker), list recorded backups with size and target, and a one-click
  Restore button (with a confirmation dialog explaining the automatic checkpoint).
- Tests: `packages/capabilities/backup_test.go` — a real end-to-end `backup.run` →
  mutate → `backup.restore` round trip for the "files" scope (tar/cp against a real
  filesystem, no mocks) plus validation coverage (bad scope/db_name/site_root,
  checksum mismatch, archive path traversal/outside `backupBaseDir`, missing
  archive). `apps/controlplane/store_test.go` and `http_test.go` cover the new store
  methods and every endpoint validation path short of an actual agent dispatch (no
  live agent in this test environment). 9 new test functions; suite total 48 → 57,
  all passing under `go test ./... -race`, `go vet` clean, `gofmt -l` clean.
- Known gap this doesn't close: the `db`/`full` restore path (`mysql <db> < db.sql`)
  has not yet been run against a live MariaDB instance (this sandbox has neither
  `mysql` nor `mysqldump` installed) — flagged in `TESTING.md` §5 as the next
  verification priority, same as `backup.run`'s DB scope already was. Restoring a
  backup onto a *different* server than the one it was taken on remains unimplemented
  (Phase 2).
- Docs updated: `docs/SYSTEM.md` (§2 feature table, §3 phase status, §12 allow-list,
  §19 backup/restore model, §21 known limitations, §28 assumptions), `docs/API.md`
  (new endpoints), `docs/ARCHITECTURE.md` (capability table), `docs/OPERATIONS.md`
  (§3 rewritten), `docs/TESTING.md` (coverage tables, known gaps).

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
