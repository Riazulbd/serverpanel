# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-18 — Database management: control-plane persistence and dashboard UI

- **Closed DB-005** (`docs/SERVERAVATAR_PARITY.md`), the top-priority documented
  database-management gap: `db.create`/`db.delete`/`db.list`
  (`packages/capabilities/db.go`) already worked against a real MariaDB, but their
  results only ever existed as a plain human-readable string, and nothing on the
  control-plane side recorded that a database now existed — there was no `databases`
  table, no dedicated API, and no dashboard UI (the exact same shape of gap `backup.run`
  had before `backup.restore` closed it in the 2026-08-17 entry above).
- `db.create`/`db.delete`/`db.list` now return structured JSON (`dbCreateResult`/
  `dbDeleteResult`/`dbListResult`) instead of a formatted string, so the control plane
  can parse and persist the outcome instead of scraping text.
- New `databases` table (`apps/controlplane/db.go`) and store methods
  (`createDatabase`/`listDatabases`/`getDatabase`/`databaseNameExists`/
  `markDatabaseDeleted`, `apps/controlplane/store.go`), following the same
  dispatch-then-persist-on-success pattern as sites and backups. Deletion is a soft
  delete (`status = 'deleted'`, filtered out of listings) rather than a row delete, so
  the id and audit trail stay resolvable.
- New endpoints (`apps/controlplane/databases.go`): `POST`/`GET
  /api/v1/servers/{id}/databases`, `DELETE /api/v1/servers/{id}/databases/{dbId}`.
  `POST` generates the owner password server-side with `crypto/rand` (never accepted
  from the client) and returns it exactly once in the response — the same one-time-
  reveal pattern a bootstrap install token already used — and rejects a database-name
  collision with `409` *before* dispatching, since `CREATE DATABASE IF NOT EXISTS`
  would otherwise silently let a second site's request reuse (and, via its own
  `GRANT`, gain access to) a database another site already owns.
- New "Databases" panel per server in the dashboard (`apps/controlplane/web/index.html`):
  a table of recorded databases, a "+ New database" modal (name, owner username,
  optional site association), a one-time password-reveal box on creation, and a
  per-row delete with a destructive-action confirmation dialog.
- Added 9 new tests: 6 capability-layer validation tests
  (`packages/capabilities/db_test.go` — invalid name/owner/password rejected before any
  MariaDB connection is attempted, plus the `identifierRe` accept/reject boundary at
  its exact length limit) and 3 control-plane tests (`TestDatabaseCreateListGetRoundTrip`,
  `TestDatabaseNameExists` in `store_test.go`; `TestDatabaseEndpoints` in `http_test.go`
  — missing-field validation, nonexistent-site 404, name-collision 409 before dispatch,
  no-agent-connected 502, list, delete-nonexistent 404, all proven to happen in the
  right order relative to dispatch). `go build ./...`, `go vet ./...`, `gofmt -l .`, and
  `go test ./...` all clean (70 test functions total, up from 61).
- Updated `docs/SYSTEM.md` (new "Database management" table, `databases` schema row,
  API endpoint summary), `docs/API.md` (new endpoint docs, `db.create`/`db.delete`/
  `db.list` capability reference), `docs/TESTING.md` (coverage counts), and
  `docs/SERVERAVATAR_PARITY.md` (DB-001 moved from "no control-plane persistence yet" to
  reflecting what DB-005 now provides; DB-005 itself moved `NOT_STARTED` → `COMPLETE`
  with a full detail block; MongoDB support (DB-002), DB admin UI (DB-003), and
  process/query monitoring (DB-004) remain the tracked remaining gaps in this category).
- The real agent-side `db.create`/`db.delete` MariaDB calls this new layer dispatches to
  remain `BLOCKED_EXTERNAL` for end-to-end verification in this environment (no MariaDB
  here) — same documented limitation as DB-001/BAK-001 before it; everything above them
  (persistence, API, UI, and their validation/authorization boundaries) is implemented
  and tested.

## 2026-08-17 — Backup restore, ServerAvatar parity tracking

- **Implemented `backup.restore`** (`packages/capabilities/backup.go`), closing the
  single largest functional gap flagged in the previous entry. Restores a
  `backup.run` archive with, in order: archive-location validation (must resolve to a
  file directly inside the agent's backup directory, never an arbitrary path),
  optional checksum verification against the value `backup.run` originally returned,
  safe extraction via Go's `archive/tar` directly (not a shelled-out `tar`) into a
  private temp directory — rejecting any entry with an absolute path or one that would
  traverse outside it, and skipping anything that isn't a plain file or directory — a
  pre-restore checkpoint backup of the live state taken via `backup.run` itself
  (returned in the result, so a bad restore is always recoverable), then the database
  restore (`mysql` import, streamed from disk, never buffered as a string or passed as
  an argv value) and/or an atomic-as-possible directory swap for files, with ownership
  restored to the site's own system user afterward.
- Wired `backup.restore` (and, previously dispatch-only, `backup.run`) into the control
  plane end-to-end: new `backups` store methods (`createBackup`/`listBackups`/
  `getBackup`, each scoped by server ID the same way `getSite` now is), three new
  endpoints (`GET`/`POST /api/v1/servers/{id}/sites/{siteId}/backups`,
  `POST /api/v1/servers/{id}/backups/{backupId}/restore`), an idempotent
  `db_name` column migration for the pre-existing `backups` table, and a "Backups"
  panel per site in the dashboard (create-backup modal with scope selection, a backups
  table, and a restore button with a destructive-action confirmation dialog).
- Added 9 new capability-layer tests (archive-location/checksum/path-traversal
  rejection, a real files backup→corrupt→restore round trip against a real throwaway
  system user, and `archive/tar` extraction-safety unit tests for path traversal,
  absolute paths, and a decompression-size limit) and 4 new control-plane tests
  (backup CRUD round trip, cross-server scoping for both `getSite` and `getBackup`,
  and HTTP boundary/validation tests for the new endpoints). Full suite: 61 test
  functions, `go vet`/`gofmt` clean.
- Updated `SYSTEM.md`, `API.md`, `OPERATIONS.md`, and `TESTING.md` to reflect restore
  as implemented (same-server only — cross-server restore remains a Phase 2 gap,
  tracked alongside cross-server migration).
- Added `docs/SERVERAVATAR_PARITY.md` and `docs/SERVERAVATAR_DOC_INVENTORY.md`,
  establishing the ongoing feature-parity tracking process against ServerAvatar's
  public product documentation (capability reference only — no ServerAvatar code,
  copy, or design assets used).

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
