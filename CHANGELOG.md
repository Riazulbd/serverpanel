# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-16 — Backup restore, backups persistence + dashboard UI, mobile-responsiveness fix

- **Added the `backup.restore` agent capability**
  (`packages/capabilities/backup.go`), closing the single largest functional gap
  called out repeatedly in the prior session's documentation pass (`SYSTEM.md` §19/
  §21, `OPERATIONS.md` §3): until now `backup.run` existed with no way to restore from
  it. `backup.restore` verifies the archive's SHA-256 against an expected checksum
  before touching anything, confirms the archive's actual contents match the claimed
  scope, takes a fresh pre-restore checkpoint backup of the current state (aborting
  before any change if that checkpoint itself fails), then extracts and re-imports the
  DB dump (`mysql` client) and/or copies files back into place.
- **Found and fixed a real backup-filename-collision bug** while writing the first
  real (non-mocked) round-trip test for the new capability: `backup.run`'s output
  filename only had second-resolution timestamp granularity, so a restore's own
  pre-restore checkpoint could silently overwrite the very archive being restored
  from if both happened within the same second — corrupting the restore instead of
  fixing it. Fixed by adding a random filename suffix, which closes the whole
  "two backups of the same thing, same second" collision class.
- **Wired up the previously-unused `backups` database table**: added
  `store.createBackup`/`listBackups`/`getBackup`/`getSite` (`apps/controlplane/
  store.go`) and three new endpoints (`apps/controlplane/backups.go`) —
  `POST`/`GET /api/v1/servers/{id}/backups` and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` — following the same
  "dispatch → parse the agent's result → persist a row only on success" pattern
  `handleCreateSite` already used for sites. A restore always uses the archive
  path/checksum recorded in the `backups` table, never a value an API caller could
  supply directly, and its pre-restore checkpoint is itself persisted as a new row
  (`status: "checkpoint"`) so undoing a bad restore is just another restore.
- **Added a Backups section to the dashboard** (`apps/controlplane/web/index.html`):
  list backups per server (creation time, linked site, scope, size, status), a
  "+ New backup" modal, and a Restore action per row with a confirmation dialog.
- **Verified dashboard mobile responsiveness with real browser automation**
  (Playwright/Chromium) at 320/375/390/414/768/1280px across every view — something
  the prior session's docs explicitly flagged as unverified. Found and fixed one real
  bug in the process: the top navigation bar had no `flex-wrap`, so on narrow
  viewports the session info overflowed the page instead of wrapping to a second
  line. Also added a shared `.table-scroll` container around every table (server
  list, sites, backups, audit log) so wide tables scroll within their own card
  instead of the page scrolling horizontally.
- Added 10 new automated tests (`packages/capabilities/backup_test.go`,
  `apps/controlplane/store_test.go`, `apps/controlplane/http_test.go`) — validation
  coverage for `backup.restore` (bad scope, archive-path confinement including a
  `..`-traversal attempt, missing/mismatched checksum, unmanaged site root, scope/
  content mismatch) plus a real, non-mocked `backup.run` → mutate → `backup.restore`
  round trip for the `files` scope that also verifies the pre-restore checkpoint
  archive is itself valid. `go test ./...` and `go test ./... -race` both pass
  (58 test functions total, up from 48); `go vet`/`gofmt -l` clean.
- Updated `docs/SYSTEM.md`, `docs/API.md`, `docs/OPERATIONS.md`, `docs/SECURITY.md`,
  and `docs/TESTING.md` to reflect all of the above — backup/restore is no longer
  documented as the biggest gap, and mobile responsiveness is no longer documented as
  unverified.

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
