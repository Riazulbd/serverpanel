# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-17 — Backup restore

Closes the single largest functional gap flagged in the prior session's documentation
pass (`SYSTEM.md` §19/§21): there was a `backup.run` capability but no way to actually
restore from one.

- **Agent**: added `backup.restore` (`packages/capabilities/backup.go`). Safety
  properties: the archive path is confined to `backupBaseDir` with the same
  symlink-escape defense the file manager uses (`resolveBackupPath`); a SHA-256
  checksum is mandatory and re-verified before extraction, refusing a corrupted or
  tampered archive outright; before overwriting anything, the current database (if it
  exists) is checkpointed via a fresh dump and the current site directory is renamed
  aside rather than deleted; restoring into a different target database/site than the
  backup was taken from is supported. `backup.run` now writes a `manifest.json` into
  every archive (which member is the DB dump vs. the files payload) so restore never
  has to guess an archive's internal layout. See `docs/SECURITY.md` §7 for the full
  checklist.
- **Control plane**: `backup.run`/`backup.restore` dispatch was previously only
  reachable through the generic task-dispatch endpoint, and successful backups were
  never persisted (the `backups` table existed in the schema but nothing wrote to it).
  Added dedicated endpoints — `POST/GET /api/v1/servers/{id}/backups` and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` — that dispatch and, only on
  confirmed agent success, persist/read backup records, mirroring the existing
  `handleCreateSite` pattern. A restore call reads its archive path/checksum from the
  stored record, never from request input; the request only supplies the *restore
  target* (`db_name`/`site_id`), which may differ from the backup's origin.
- **Dashboard**: added a Backups section to the server-detail view — list existing
  backups (scope, size, created-at), create a new one (scope + target
  database/site picker), and restore an existing one with an explicit confirmation
  step, matching the existing Sites section's UI conventions (`apps/controlplane/web/index.html`).
- **Tests**: 21 new test functions (69 total, up from 48) — `go vet`/`gofmt` clean,
  `go test ./... -race` clean. Notably a real end-to-end `backup.run` → mutate →
  `backup.restore` round trip against a real filesystem and a real (test-created)
  system user, verifying restored content matches the pre-mutation backup and that a
  pre-restore checkpoint was preserved; a real checksum-mismatch rejection against a
  deliberately invalid on-disk archive; `resolveBackupPath`'s traversal/symlink-escape/
  directory-rejection defenses; and full endpoint-validation coverage for both new
  control-plane routes. Database-scope restore logic is covered at the
  validation/unit level only — this environment has no MariaDB installed, matching the
  existing `db.create/delete/list` testing tier (see `docs/TESTING.md` §2).
- **Docs**: updated `SYSTEM.md`, `API.md`, `SECURITY.md` (new §7), `OPERATIONS.md`,
  `TESTING.md`, `INSTALLATION.md`, `ARCHITECTURE.md`, and `README.md` to reflect the
  new capability and its current verification tier, and to flag what's still out of
  scope (automatic cross-server backup transfer, backup deletion/retention).

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
