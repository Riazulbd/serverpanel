# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-17 — Cron job management (SRV-005)

- **Implemented `cron.sync`** (`packages/capabilities/cron.go`), closing the top
  `NOT_STARTED` Server Management gap in `SERVERAVATAR_PARITY.md`. Declarative, not
  incremental: one capability call replaces a site's own system user's *entire*
  crontab with exactly the job set given, so create/edit/delete/enable/disable are all,
  agent-side, the same "recompute desired state, sync the whole thing" operation
  `site.create` already uses for nginx vhosts — no add-one-line/remove-one-line
  capability, keeping the allow-list small and every sync idempotent/safe to retry.
  Jobs are not a free-text shell string: each is `{binary, args}`, `binary` drawn from
  an allow-listed, already-vetted set (`php`, `wp`, `composer`, `curl`) resolved to an
  absolute path at sync time rather than left to cron's own often-minimal `PATH`, and
  every argument is checked against a character allow-list containing no shell
  metacharacter — so no argument can terminate the intended command or smuggle a second
  one, even though the resulting crontab line is ultimately parsed by cron's own
  `/bin/sh`. `run_as_user` is independently re-validated agent-side (must be a
  `site_`-prefixed, actually-existing system user — never root, never trusted just
  because the control plane sent it) and each job's stdout/stderr is redirected, by the
  agent rather than the caller, to a per-job log file under a directory `chown`ed to
  that site's own user.
- Wired `cron.sync` into the control plane end-to-end: a new `cron_jobs` table (source
  of truth for job definitions — the agent's crontab is a derived, resynced view of
  it), `createCronJob`/`listCronJobs`/`getCronJob`/`updateCronJob`/`deleteCronJob` store
  methods (each scoped by server ID like `getSite`/`getBackup`), five new endpoints
  (`GET`/`POST /api/v1/servers/{id}/sites/{siteId}/cron`,
  `PUT`/`DELETE .../cron/{jobId}`, `POST .../cron/sync` as an explicit retry path), and
  a "Cron jobs" panel per site in the dashboard (new-job modal, jobs table with
  enable/disable and delete). A job is persisted before the sync is attempted, so a
  sync failure (agent briefly disconnected) never loses the job's definition — it's
  retried by the next mutation or an explicit sync call.
- Added 11 new capability-layer tests, including — against a real `crontab` binary
  installed in this session specifically to exercise it, and a real throwaway system
  user on this session's real Ubuntu 24.04.4 LTS container — a full write→verify (via
  an independent `crontab -l` shell-out, not the handler's own return value)→clear
  round trip, plus schedule/binary/argument/user validation and injection-rejection
  tests. Added 1 new store test (full CRUD round trip + cross-server-scoping rejection)
  and 2 new HTTP tests (not-found boundaries; validation-before-dispatch, and that a job
  is persisted/removed even when the sync to a disconnected agent fails). Full suite:
  75 test functions, `go vet`/`gofmt`/`-race` clean.
- **Security self-review caught and fixed one real defect before commit**: schedule
  validation checked each of a schedule's 5 fields but wrote the caller's *original*
  string (not the validated/normalized form) into the generated crontab line — a
  schedule containing an embedded newline could still tokenize into 5 valid-looking
  fields (since `strings.Fields` splits on any whitespace) and would have injected a
  second, attacker-controlled crontab entry. Fixed by having `validateCronSchedule`
  return the re-joined, normalized field string and requiring every caller to use it;
  pinned by two regression tests, one of which round-trips through a real `crontab -l`
  to confirm exactly one job line results. See `TESTING.md` §4 for the full writeup.
- Updated `SYSTEM.md`, `ARCHITECTURE.md` (the pre-implementation `cron.upsert` sketch
  is superseded by the as-built `cron.sync` design), `API.md`, `TESTING.md`, and
  `SERVERAVATAR_PARITY.md` (SRV-005 moved from the not-started summary table to a full
  `COMPLETE` detail block) to reflect cron job management as implemented.

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
