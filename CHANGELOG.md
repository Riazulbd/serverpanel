# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-15 — Backup restore, backup persistence, mobile responsiveness fixes

- **Implemented `backup.restore`**, closing the single largest functional gap flagged in
  the prior session's documentation pass (`docs/SYSTEM.md` §19/§21). It verifies the
  target archive's SHA-256 against the value recorded at backup time before touching
  anything; takes a best-effort pre-restore checkpoint (a fresh `backup.run` of the
  current state) so a bad restore can itself be rolled back; restores the database scope
  via `mysql <db_name> < dump.sql` and the files scope via `cp -a` (merge/overwrite,
  never a wipe — consistent with this codebase's "no unrestricted recursive deletion
  capability" rule); and never reads an archive outside `/var/backups/serverpanel`.
- **Wired `backup.run` dispatch through to persistence**: `POST /api/v1/servers/{id}/backups`
  now records a `backups` row on success (this was previously a known gap — the
  capability worked but nothing wrote to the table). Added
  `GET /api/v1/servers/{id}/backups` and `POST /api/v1/servers/{id}/backups/{backupId}/restore`;
  restore takes no request body — every parameter is derived server-side from the stored
  backup/site records, not the caller, so it can't be turned into an arbitrary-write
  primitive. Added a `backups.db_name` column via a small additive-migration mechanism
  (`applyMigrations` in `db.go`, this project's first schema migration).
- **Dashboard**: added a Backups section to the server-detail view — "Back up files" per
  site, a "Back up a database..." action, and a list of recorded backups each with a
  confirming "Restore" button.
- **Found and fixed a real bug** while writing the backup.restore round-trip test:
  `backup.run`'s filename only had second-resolution timestamps, so a pre-restore
  checkpoint created within the same second as the archive being restored from could
  collide on filename and silently overwrite it with corrupted contents mid-restore.
  Fixed with a random hex suffix on every backup filename, which also makes concurrent
  `backup.run` calls collision-safe in general.
- **Verified and fixed dashboard mobile responsiveness** with real Playwright browser
  automation (not a visual guess) at 320/375/390/414/768/1280px against the login
  screen, server list, server detail, and audit log — checking actual DOM overflow, not
  eyeballing screenshots. Found and fixed two real bugs: the topbar didn't wrap at
  narrow widths (email + sign-out ran off-screen, forcing page-level horizontal scroll),
  and the login card's fixed 360px width exceeded a 320px viewport. Also wrapped the
  sites/backups tables (nested inside the larger server-detail card) in their own
  scroll containers so a wide table scrolls internally instead of blowing out the page.
- Added 10 new automated tests (58 total, up from 48): `backup.restore` validation
  (path confinement, checksum mismatch, invalid scope, missing archive) plus a real
  end-to-end files-scope round trip through actual `tar`/`cp`; store-level and HTTP-level
  coverage for the new backup endpoints and `getSite`.
- Updated `docs/SYSTEM.md`, `docs/API.md`, `docs/OPERATIONS.md`, and `docs/TESTING.md`
  to reflect all of the above — restore is no longer documented as a gap, and the mobile
  fix and its residual coverage limits (Security tab and modals not yet screenshotted)
  are recorded rather than left implicit.

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
