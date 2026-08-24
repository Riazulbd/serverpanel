# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-24 — Cron job management, `system_user` path-traversal hardening

- **Implemented cron job management** end-to-end (agent capability, control plane
  persistence/API, dashboard UI) — the next-highest-priority `NOT_STARTED` item in
  `SERVERAVATAR_PARITY.md`'s server-management category (SRV-005). New agent
  capabilities `cron.create`/`cron.list`/`cron.delete`/`cron.set_enabled`
  (`packages/capabilities/cron.go`): one `/etc/cron.d/serverpanel-<system_user>` file
  per site, fully owned and rewritten by this package (never hand-edited), each entry
  a `# sp-cron:<id> enabled|disabled` marker line followed by the real cron.d line —
  disabling comments the line out in place rather than deleting it, so re-enabling
  doesn't need the schedule/command resupplied. Jobs run as the site's own unprivileged
  system user, matching the isolation model `site.create`/`db.create` already
  establish; `cron`'s inotify watch on `/etc/cron.d/` picks up changes automatically,
  no service restart required.
- Schedule validation restricts each of the 5 fields to `[0-9*/,-]` (day/month names
  not supported — deliberately, to keep every accepted character safe to write
  directly into a single cron.d line); command validation rejects newlines outright
  (the one character that could inject a second, uncontrolled line into the file).
- Wired into the control plane: new `crons` table + store methods (`createCron`/
  `listCrons`/`getCron`/`deleteCron`/`setCronEnabled`, each scoped by server ID the
  same way `getSite`/`getBackup` are), four new endpoints (`GET`/
  `POST /api/v1/servers/{id}/sites/{siteId}/crons`,
  `POST /api/v1/servers/{id}/crons/{cronId}/toggle`,
  `DELETE /api/v1/servers/{id}/crons/{cronId}`), and a "Cron Jobs" panel per site in
  the dashboard (hourly/daily/weekly/monthly presets plus a raw-expression field,
  enable/disable/delete actions).
- **Security fix found during this pass, not scoped to cron**: `system_user` validation
  across `app.go`/`logs.go`/`site.go` (and the new `cron.go`) checked only a `"site_"`
  *prefix* before building a filesystem path from the value — a crafted string like
  `site_/../../../etc/passwd` would pass that check and reach `filepath.Join`. Replaced
  all five call sites with a shared `validateSiteSystemUser` (`exec_helpers.go`): a
  full-charset regex matching exactly what `systemUserForDomain` ever generates,
  bringing `system_user` up to the same strict-charset standard already used for
  database/domain identifiers (`identifierRe`/`domainRe`). Bounded by the existing
  trust model (only an authenticated dashboard session can dispatch a capability at
  all), so this is defense-in-depth hardening, not a closed remote-exploit path — see
  `SECURITY.md` §4 and `SERVERAVATAR_PARITY.md` SRV-005 for the full writeup.
- Added 13 new capability-layer tests (schedule/command validation including the
  newline-injection case, create/list round trip, duplicate-ID rejection,
  enable/disable persistence, delete removing only the targeted entry, last-entry
  deletion removing the file rather than leaving it empty, unknown-ID rejection, and
  the `validateSiteSystemUser` path-traversal regression test) and 5 new control-plane
  tests (cron store round trip + cross-server scoping, endpoint not-found boundaries,
  field-validation-before-dispatch). Full suite: 75 test functions (was 61),
  `go vet`/`gofmt` clean.
- Updated `SYSTEM.md`, `API.md`, `OPERATIONS.md`, `SECURITY.md`, `TESTING.md`, and
  `SERVERAVATAR_PARITY.md` to reflect cron management as implemented (SRV-005 now
  `COMPLETE`; live-`cron`/inotify pickup itself remains `BLOCKED_EXTERNAL` — not
  exercisable without a real running `crond` to observe).

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
