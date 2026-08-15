# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-15 — Backup restore capability, backup persistence, dashboard backup UI

- Added the `backup.restore` agent capability (`packages/capabilities/backup.go`):
  restores a database (`mysql dbName < dump.sql`) and/or a site's files
  (`cp -a` + re-`chown`) from a `backup.run` archive. Never accepts an arbitrary
  filesystem path — the archive must resolve under the fixed `backupBaseDir`
  (following symlinks), and a files/full restore target must resolve under
  `/home/sites/`, the same boundary the file manager and `site.create` already
  enforce. Verifies the archive's SHA-256 against a caller-supplied checksum before
  touching anything, and — before making any change — takes a fresh "pre-restore
  checkpoint" backup of whatever is currently live, aborting the restore before any
  destructive step if that checkpoint itself fails.
- Wired `backup.run`'s and the new `backup.restore`'s dispatch through actual
  persistence for the first time: `apps/controlplane/backups.go`
  (`handleCreateBackup`/`handleListBackups`/`handleRestoreBackup`) plus new `store`
  methods and a `backups.db_name` schema column (added via a new minimal
  `applyMigrations` step in `db.go`, since the table may already exist on disk). A
  files/full backup or restore's target is always derived from the request's
  `site_id` against the already-recorded `sites` table — never trusted directly from
  the request body — so a caller can't point either operation at an arbitrary path.
  A restore's pre-restore checkpoint is itself persisted as a new backup row, so it's
  visible in the dashboard and can itself be restored from.
- Added three new endpoints (`GET`/`POST /api/v1/servers/{id}/backups`,
  `POST .../backups/{backupId}/restore`) and a "Backups" section to the dashboard's
  server-detail view: a table of recorded backups with a Restore button, and a modal
  to start a new db/files/full backup.
- New tests: a real end-to-end `backup.run` → corrupt live data → `backup.restore` →
  verify original content came back round trip (using a real tar archive and a real
  `useradd`-created system user, not mocks), checksum-mismatch/invalid-scope/path-
  escape rejection tests, backup/site store-layer CRUD and cross-server-scoping tests,
  and an HTTP-layer test for the new endpoints' input validation. 56 test functions
  total now (was 48), all passing; `go vet`/`gofmt` clean.
- Found and fixed two defects while writing this pass (see `TESTING.md` §4 for
  detail): `backup.run`'s output filename had only second-resolution uniqueness, so
  two backups of the same target within the same second could silently collide and
  overwrite each other — caught by the new restore round-trip test taking a
  checkpoint moments after the backup it was restoring from; fixed with a random
  4-byte hex filename suffix. Also found (and fixed in the test, not production code)
  that calling a capability handler directly with a `nil` `Progress` — bypassing
  `Registry.Dispatch`'s nil-guard — panics if the handler reaches a `progress(...)`
  call before any early-return validation.
- Updated `SYSTEM.md`, `API.md`, `OPERATIONS.md`, and `TESTING.md` to reflect that
  backup restore is now implemented and tested rather than the previously-documented
  single largest functional gap; database-scope restore's `mysqldump`/`mysql` path
  remains unverified against a real MariaDB instance (none available in this
  sandboxed environment), documented as the next real-VPS verification item.

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
