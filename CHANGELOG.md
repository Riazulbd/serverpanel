# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-15 — Backup restore: capability, persistence, dashboard UI

- Implemented `backup.restore` (`packages/capabilities/backup.go`), closing the
  largest functional gap flagged in the previous pass. Safety properties: the archive
  path must resolve inside the managed backup directory (`resolveBackupArchivePath`,
  symlink-safe, same pattern as the file manager's `resolveScopedPath`); its SHA-256
  must match a caller-supplied `expected_sha256` or the restore is refused outright;
  every member path inside the archive is listed and validated against the declared
  restore scope *before* anything is extracted (`validateBackupArchiveMembers`),
  rejecting a corrupted or mismatched-scope archive rather than extracting it; a
  best-effort pre-restore checkpoint of current state is taken before any mutation
  (`createBackupArchive`, factored out of `backup.run` so both share it); database
  restore imports a `.sql` dump via `mysql`; file restore extracts back to the
  archive's original absolute path and restores ownership to the site's isolated
  system user (`siteSystemUserFromPath`).
- **Found and fixed a real bug while testing the above**: backup archive filenames
  used a second-granularity timestamp only, so `backup.restore`'s own pre-restore
  checkpoint — running seconds (or less) after the backup it's restoring from — could
  collide with and silently overwrite the original archive with a fresh snapshot of
  already-corrupted state, which extraction then read back from post-overwrite. Caught
  by `TestBackupRunAndRestoreFilesRoundTrip` on its first run; fixed with a random
  filename suffix (see `docs/TESTING.md` §4 for the full writeup).
- Wired backup persistence and restore into the control plane: `store.go` gained
  `createBackup`/`listBackups`/`getBackup`/`getSite`; new `apps/controlplane/backups.go`
  dispatches `backup.run`/`backup.restore` and only persists/acts on agent-confirmed
  success (same pattern `handleCreateSite` already used for sites); new routes
  `GET/POST /api/v1/servers/{id}/backups` and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` — restore always dispatches
  the archive path/checksum from the control plane's own stored record, never a
  client-supplied one.
- Added a "Backups" section to the dashboard (`apps/controlplane/web/index.html`):
  list backups per server with scope/size/checksum, a "+ New backup" modal (scope
  selector with site/db-name fields that show/hide per scope), and a one-click
  "Restore" action with a confirmation prompt. Manually verified with a real running
  control-plane binary (curl through the full create/list/validate/404/502 flow) and a
  headless-Chromium (Playwright) pass through login → server detail → new-backup modal
  → scope toggling, no console errors.
- Added 16 new automated tests (11 in `packages/capabilities`, 4 store-level + 1 HTTP
  route test in `apps/controlplane`; 64 total, up from 48), including a real
  end-to-end files-scope backup→drift→restore round trip against real files, a real
  system user, and real `tar` — not mocked. `db`/`full`-scope paths remain untested by
  `go test` (no MariaDB in this sandbox — see `docs/TESTING.md` §2/§5).
- Updated `docs/SYSTEM.md` §2/§3/§19/§21, `docs/API.md`, `docs/OPERATIONS.md` §3, and
  `docs/TESTING.md` to reflect all of the above.

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
