# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-16 — Backup restore capability, closing the largest Phase 1 gap

- Added `backup.restore` (`packages/capabilities/backup.go`), the capability flagged
  in the previous entry as "the single largest functional gap" relative to the product
  plan. It verifies the archive's SHA-256, takes a pre-restore checkpoint (a fresh
  backup of exactly what's about to be overwritten, aborting before touching data if
  that step fails), restores the database via `mysql <db> < dump.sql`, and/or overlays
  files back onto the site directory via `cp -a` — never a delete-then-restore,
  consistent with this codebase's "no unrestricted recursive delete" rule.
- Wired backup dispatch through to persistence end to end: `POST
  /api/v1/servers/{id}/backups` dispatches `backup.run` and, only on agent-confirmed
  success, writes a `backups` row (the same dispatch-then-persist pattern as
  `site.create`); `POST /api/v1/servers/{id}/backups/{backupId}/restore` dispatches
  `backup.restore` using the archive path/checksum from that stored row — the request
  body can never point the agent at an arbitrary filesystem path. Added a `db_name`
  column to the `backups` table via an additive, idempotent migration (`ensureColumn`
  in `db.go`), and a Backups section (list, "+ New backup", "Restore") to the
  server-detail view in the dashboard.
- Found and fixed a real bug via the new end-to-end restore test
  (`TestBackupRunThenRestoreFilesRoundTrip`,
  `packages/capabilities/backup_test.go`): backup filenames were built from a
  second-precision timestamp, so a pre-restore checkpoint of the same site/scope taken
  within the same second as the backup being restored from could collide on disk and
  silently overwrite the archive the restore was reading from, corrupting it with the
  current (about-to-be-replaced) state instead. Fixed by appending a random suffix to
  every backup filename. This is exactly the class of bug a mocked/validation-only
  test suite would not have caught — it only surfaced because the test drove real
  `tar`/`cp` calls against real files with real timestamps.
- Added 10 new capability-level tests (validation, path-traversal/outside-basedir
  rejection, checksum-mismatch rejection, missing-DB-dump rejection, and the full
  files-scope round trip) and 3 new store-level tests (`getSite` and backup
  create/list/get, all scoped-to-server). Database-scope restore
  (`mysql <db> < dump.sql`) is implemented but not exercised against a real MariaDB in
  this session's sandbox — see `TESTING.md` §5 for what remains to verify.
- Updated `SYSTEM.md`, `API.md`, `OPERATIONS.md`, `TESTING.md`, and `ARCHITECTURE.md`
  to reflect all of the above and remove now-stale "not implemented" language.

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
