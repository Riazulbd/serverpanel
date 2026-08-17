# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-17 — Backup restore

Closed the largest functional gap flagged in the 2026-08-14 pass: there was a
`backup.run` capability but no way to restore from what it produced.

- Added the `backup.restore` capability (`packages/capabilities/backup.go`):
  confines restores to archives under the agent's own `backupBaseDir`, re-verifies
  the archive's SHA-256 against a caller-supplied checksum before touching anything,
  always takes a fresh checkpoint backup of the current live state before restoring
  (refusing the restore outright if the checkpoint itself fails), then restores the
  database via `mysql`'s stdin (no shell) and/or atomically swaps the site's files
  directory into place (rename, falling back to `cp -a` across filesystems).
  Refactored `backup.run`'s archive-creation logic into a shared
  `createBackupArchive` helper used by both the on-demand backup path and the
  automatic pre-restore checkpoint, so they stay identical in validation and layout.
- Wired it into the control plane: `apps/controlplane/backups.go` adds
  `POST /api/v1/servers/{id}/backups` (dispatch `backup.run`, persist a `backups` row
  only once the agent confirms success — same pattern as site creation) and
  `POST /api/v1/servers/{id}/backups/{backupID}/restore` (reads the archive path,
  checksum, scope, and target from the control plane's own stored record — never
  from the request — dispatches `backup.restore`, and persists the agent's
  pre-restore checkpoint as its own `backups` row so it's visible and itself
  restorable). Added `apps/controlplane/store.go` CRUD for the `backups` table and a
  small additive-migration helper (`migrateSchema` in `db.go`) for the new
  `site_root`/`db_name`/`kind`/`restored_at` columns, since the table already existed
  from the prior session with a narrower schema.
- Added a Backups section to the dashboard (`apps/controlplane/web/index.html`):
  run a backup with a scope picker, list backups/checkpoints with size and restored
  status, and a confirm-gated Restore button per backup.
- Tests: `packages/capabilities/backup_test.go` covers scope/site_root/db_name
  validation, the archive-outside-`backupBaseDir` and path-traversal rejections, the
  checksum-mismatch rejection, and a real `backup.run` → mutate the live files →
  `backup.restore` → confirm original content restored, unrelated new files removed,
  and a distinct pre-restore checkpoint recorded — all against a real filesystem and
  a real tar/gzip round trip (no MariaDB in this environment, so the `db`/`full`
  scopes are validated but not exercised against a live database — see
  `docs/TESTING.md` §5). `apps/controlplane/store_test.go` covers backup create/
  list/get/mark-restored and that a backup is only retrievable under the server it
  was created for. `go test ./... -race`, `go vet ./...`, and `gofmt -l .` all clean.
- Docs: updated `SYSTEM.md` (§2, §3, §8, §12, §19, §21), `API.md`, `OPERATIONS.md`
  §3, `TESTING.md` (§1, §2, §3, §5), and `SECURITY.md` (new §4a) to describe restore
  as implemented rather than the flagged gap, and to be explicit about what's still
  only self-restore-in-place (no cross-server restore yet — depends on Phase 2
  migration) and what's still only reviewed rather than live-database-tested.

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
