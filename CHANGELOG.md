# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-15 — Backup restore, backup lifecycle wired into the API/dashboard, mobile responsiveness fixes

- **`backup.restore` capability** (`packages/capabilities/backup.go`): the single
  largest documented functional gap from the prior pass. Verifies the archive's SHA-256
  checksum, takes a fresh `backup.run` pre-restore checkpoint of the current files state
  before overwriting anything (aborting the restore if the checkpoint itself fails),
  extracts the archive, and restores the database dump (via `mysql`) and/or files (via
  `cp -a`, after clearing the target directory's contents). `backup_path` is validated
  against the fixed `backupBaseDir` with the same symlink-escape-resistant approach
  `resolveScopedPath` uses for site roots (`validateBackupPath`).
- **Backup lifecycle wired end-to-end**, previously only a bare, unreachable-from-the-UI
  agent capability: new `apps/controlplane/backups.go` with
  `POST /api/v1/servers/{id}/backups` (dispatch `backup.run`, persist a `backups` row
  only on confirmed success — the same pattern `handleCreateSite` uses),
  `GET /api/v1/servers/{id}/backups` (list), and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` (dispatch `backup.restore`
  using the recorded backup's path/scope/checksum). New `store` methods `getSite`,
  `createBackup`, `listBackups`, `getBackup`. New dashboard UI: a "Backups" section on
  the server-detail page with a "Run backup" modal (scope/site/DB-name fields that
  toggle based on scope) and a "Restore…" button per backup.
- **Real bug found and fixed**: `backup.run`'s output filename used only
  second-granularity timestamps, so two backups of the same site/scope started within
  the same second could collide and silently overwrite each other — caught by
  `TestBackupRunRestoreFilesRoundTrip` failing on its first run (restored content came
  back as the post-mutation state, because the restore's own pre-restore checkpoint had
  overwritten the archive being restored). Fixed with a random 4-byte hex filename
  suffix (`randSuffix()`).
- **Dashboard mobile responsiveness**: verified with real headless-Chromium (Playwright)
  automation at 320/375/390/414/768/1024px across every view — the first pass found and
  this pass fixed real overflow (topbar not wrapping, a hard-coded 360px auth-card
  width, tables overflowing the page instead of scrolling within their own box). See
  `docs/TESTING.md` §4 for the full before/after.
- Tests: `packages/capabilities/backup_test.go` (new — `validateBackupPath`'s
  traversal/symlink-escape defenses, scope validation, checksum-mismatch rejection, and
  a real `backup.run` → mutate → `backup.restore` → verify round trip for the `files`
  scope), plus new `apps/controlplane` store/HTTP tests for the backup endpoints.
  62 test functions total (was 48), all passing under `go test ./...` and
  `go test ./... -race`.
- Docs: updated `SYSTEM.md`, `API.md`, `OPERATIONS.md`, and `TESTING.md` to reflect
  restore now being implemented and tested, and mobile responsiveness now being
  verified rather than an open gap.

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
