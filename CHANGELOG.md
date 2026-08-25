# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-25 — Cron job management (SRV-005)

- **Implemented cron job management end-to-end**: `cron.list`/`cron.create`/
  `cron.update`/`cron.delete`/`cron.set_enabled` (`packages/capabilities/cron.go`) edit
  a site's real system user's crontab via `crontab -u <user> -l` / `crontab -u <user> -`
  — no separate scheduler daemon, no new database table; the crontab itself is the
  single source of truth, listed live from the agent on every request. Every entry this
  control plane writes carries a machine-readable marker comment
  (`# serverpanel-cron id=... enabled=... label=...`) on the line above it; disabling an
  entry comments out just its schedule/command line (cron never runs it) rather than
  deleting it, so re-enabling is lossless, and any other content already present in that
  crontab — added by hand or by anything else — round-trips byte-for-byte, never
  touched. Common frequencies (every minute/hourly/daily/weekly/monthly) are offered as
  presets that resolve to a standard 5-field expression; a custom expression goes
  through the identical field-by-field range validator.
- Closed the two adversarial gaps called out for this feature: (1) **ownership** — the
  crontab "owner" ever sent to the agent is always the resolved site's own
  `system_user`, read server-side from the stored site row for the exact server+site the
  URL names; a client-supplied `system_user` is never accepted or forwarded, so a caller
  can only ever touch a crontab for a site their own request already resolved to. (2)
  **crontab-line injection** — the `command`/`label` fields reject embedded
  newlines/carriage-returns/NUL bytes and an unescaped `%`, the specific ways a
  caller-supplied string could otherwise break out of its single crontab line and
  smuggle in an entirely separate, arbitrarily-scheduled entry (or forge a marker line)
  — deliberately *not* a shell-metacharacter blocklist, since a cron command is handed
  to the user's shell by cron itself and `;`/`|`/`&&`/backticks are ordinary, expected
  cron usage.
- Wired the capability into the agent's existing allow-list (`packages/capabilities.
  Default()` — the agent binary picks it up automatically, no separate agent-side
  change needed) and into the control plane: six new endpoints under
  `/api/v1/servers/{id}/sites/{siteId}/cron[...]` (`apps/controlplane/cron.go`), each
  enforcing the existing session/auth model and writing an audit-log entry
  (`cron.created`/`cron.updated`/`cron.deleted`/`cron.enabled`/`cron.disabled`), and a
  new "Cron Jobs" panel in the site-detail dashboard view (job table, add/edit modal
  with schedule presets + a custom-expression field, per-row enable/disable/delete).
- Added 15 new capability-layer tests (`packages/capabilities/cron_test.go`) — schedule
  validation (valid presets/expressions and 13 invalid-garbage cases), command/label
  validation including 5 explicit crontab-injection attempts (newline, CRLF, forged
  marker line, NUL byte, unescaped `%`) all rejected and an escaped `%` accepted,
  parse/render round-trip fidelity (foreign crontab lines preserved verbatim and
  interleaved between managed entries, a command's internal whitespace preserved
  exactly), a full create→disable→re-enable→update→delete round trip, not-found
  handling, and a real-`crontab`-binary end-to-end test that self-skips in this
  development environment (no `cron` package installed here, matching the existing
  MariaDB/wp-cli gaps) — and 6 new control-plane HTTP tests
  (`apps/controlplane/cron_test.go`): unauthenticated requests rejected on every new
  route, nonexistent server/site 404s, invalid/missing fields rejected with 400 before
  any agent dispatch, a well-formed request against a disconnected agent failing as a
  502 (proving validation order), and a regression test proving a client-supplied
  `system_user` field is never forwarded. Full suite: 82 test functions (1
  environment-gated skip), `go vet`/`gofmt` clean.
- Updated `SYSTEM.md` (§2 Server management table, §3 phase status, §12 capability
  list), `API.md` (new endpoint table rows + detail sections, `cron.*` capability
  reference), and `SERVERAVATAR_PARITY.md` (SRV-005 promoted from the `NOT_STARTED`
  summary table to a full `COMPLETE` detail block, including the known-differences this
  pass deliberately left for later: no per-org/per-user resource ownership yet — see
  ORG-001 — so cron's "session without access" boundary is today's single-user auth
  model, same as every other endpoint; cron entries aren't persisted locally, so the job
  list is unavailable while an agent is offline; no per-job execution history/output
  log; day-of-week accepts numeric values only, not three-letter names).

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
