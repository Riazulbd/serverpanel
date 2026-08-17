# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-17 — Backup restore capability + persisted backup records

- Added the `backup.restore` agent capability (`packages/capabilities/backup.go`),
  closing the single largest gap called out in the prior session's own documentation
  (`docs/SYSTEM.md` §19/§28: "`backup.run` shipped before any restore capability").
  It re-verifies the archive's SHA-256 before touching anything, resolves the archive
  path through the same symlink-safe containment check the file manager uses
  (`resolveBackupArchivePath`), locates the DB dump inside the extracted archive by
  filename regardless of the random per-run temp path `backup.run` embeds it under
  (`findFileByName`), and — for a files/full restore — takes its own checksummed
  pre-restore checkpoint of the site's current state before any existing file is
  removed, aborting the whole restore if that checkpoint step itself fails.
- Wired backups into the control plane end to end: a `backups` table row is now
  actually persisted (`store.createBackup`/`listBackups`/`getBackup` — the schema
  existed since Phase 1 but nothing wrote to it), via three new API endpoints —
  `POST /api/v1/servers/{id}/sites/{siteId}/backups` (dispatch `backup.run`, persist
  on success), `GET /api/v1/servers/{id}/backups` (list), and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` (dispatch `backup.restore`
  using the *stored* checksum, never one from the request body; a resulting
  pre-restore checkpoint is persisted as its own backup record so it's immediately
  restorable itself).
- Added 8 new capability-level tests (real filesystem/tar operations: backup→corrupt→
  restore round trip, checksum-mismatch rejection, invalid-scope/missing-checksum/
  unmanaged-site-root/out-of-bounds-path/missing-archive rejection, nested-dump
  lookup) and 2 new control-plane tests (backup CRUD against real SQLite, and an HTTP
  integration test proving every validation error on the new endpoints is rejected
  *before* any agent dispatch is attempted). `go test ./...` now covers 58 test
  functions (up from 48), all passing; `go vet`/`gofmt` clean.
- Updated `docs/SYSTEM.md`, `docs/API.md`, `docs/OPERATIONS.md`, and `docs/TESTING.md`
  to reflect restore as implemented rather than a documented gap, and to state its
  remaining honest limitations plainly: restore is synchronous (bounded by a 10-minute
  context timeout, no background-job progress model yet), same-server only (no
  cross-server restore), and its db-scope path is untested against a real MariaDB
  instance in this environment (same constraint `db.go`'s tests already documented).

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
