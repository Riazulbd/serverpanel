# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-17 — Backup restore, and backups wired into the dashboard/API

- Added `backup.restore` (`packages/capabilities/backup.go`), closing the gap flagged
  as the single largest functional shortfall in the prior pass (see 2026-08-14 below
  and `SYSTEM.md` §19/§21). It extracts a `backup.run` archive and, for `files`/`full`
  scope, replaces the target `site_root`'s contents with the archive's (clearing what's
  there first, then `cp -a`, then a best-effort ownership fix), and for `db`/`full`
  scope, pipes the archive's dump into `mysql <db_name>`. Unless `checkpoint: false` is
  passed, it takes a fresh `backup.run` of whatever's about to be overwritten *first*
  and aborts the entire restore before touching anything if that step fails — a
  pre-restore safety net, not a note in a doc.
- Refactored `backup.run`'s archive layout so restoring is possible at all: instead of
  embedding the caller's actual paths (which baked in the original temp-dir name for
  DB dumps and the original site directory name for files), the archive now always
  uses fixed top-level entry names (`db/<name>.sql`, `files/...`) built via `tar -h -C`
  against a staging directory. This is also what makes restoring a backup onto a
  *different* site or server's `site_root`/`db_name` possible in principle, ahead of
  the product plan's cross-server-restore requirement — the dashboard/API restore flow
  itself still only targets the server the backup was listed under (see `SYSTEM.md`
  §19/§21 for that remaining gap).
- Added `resolveBackupPath` (mirrors `file.go`'s `resolveScopedPath` symlink-safe
  containment check, applied to `/var/backups/serverpanel` instead of a site root) so
  `backup.restore` can't be handed a path outside the managed backup directory.
- Wired backups into the control plane end-to-end, previously entirely missing despite
  the `backups` table existing in schema since the first Phase 1 pass: new
  `POST`/`GET /api/v1/servers/{id}/backups` and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` endpoints
  (`apps/controlplane/backups.go`), new `store` methods (`createBackup`, `listBackups`
  with an optional site filter, `getBackup`), and a `backups` dashboard section per
  server (back up now, list with size/scope/kind, one-click restore with a
  confirmation dialog that explains the automatic checkpoint).
- Added `sites.home_dir` (and `siteResult.HomeDir`/`site.go`'s `home` value) so the
  control plane has the site's actual home directory on hand for backup/restore
  requests, instead of fragilely re-deriving it from `docroot`'s parent.
- Added `migrateSchema` (`apps/controlplane/db.go`) — best-effort, idempotent
  `ALTER TABLE ... ADD COLUMN` statements for the two new `backups` columns
  (`kind`, `params_json`) and the new `sites.home_dir` column, so an existing
  development database doesn't need to be deleted to pick up the new columns. Not a
  real migration framework — documented as a known limitation in `SYSTEM.md` §21.
- Tests: 13 new test functions (48 → 61 total, see `TESTING.md`) covering
  `backup.run`/`backup.restore`'s scope validation, `resolveBackupPath`'s
  containment/traversal/directory-rejection defenses, a full files-scope
  backup→mutate→restore round trip against a real filesystem (including that files
  added after the backup don't survive restore and nested subdirectories do), a
  checkpoint-then-restore-the-checkpoint scenario proving the safety net actually
  recovers the pre-restore state, the new `store` methods, and the new HTTP endpoints
  failing cleanly (400/404/502) with no agent connected. `go build`, `go vet`,
  `gofmt -l`, `go test ./...`, and `go test ./... -race` all clean.

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
