# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-17 — Real host facts (IP/CPU/memory/disk) end-to-end; overview/gauge redesign

Prompted by a design reference showing overview cards and circular usage gauges
(original branding, not a copied competitor asset — see the prior entry's redesign
for that distinction). Implemented for real rather than approximated with placeholder
numbers:

- Wire protocol (`packages/proto`): `Hello` now carries `public_ip`, `cpu_cores`,
  `mem_total_mb`, `disk_total_mb` — sent once per connection, since these essentially
  never change mid-session, keeping steady-state heartbeat traffic unchanged.
  `Heartbeat` gained `mem_used_mb`, `disk_used_mb`, `swap_total_mb`, `swap_used_mb`
  alongside the existing percentages.
- Agent (`apps/agent/metrics.go`): `readMemInfo`/`readDiskInfo` now return absolute
  values (not just percentages) from the same `/proc/meminfo`/`statfs` reads already
  being done — no new syscalls per field. `cpuCores` via `runtime.NumCPU()`.
  `primaryIP` determines the outbound-facing IP via a UDP dial trick (resolves a
  route and reads the local bound address — no packet ever sent, no third-party
  IP-lookup API, keeping the core platform free of paid/external dependencies).
- Control plane: `servers` table gained `public_ip`/`cpu_cores`/`mem_total_mb`/
  `disk_total_mb` columns, populated by a new `setAgentFacts` (replacing
  `setAgentVersion`) called from the gateway's `Hello` handler.
- Dashboard: server-detail page restructured into Overview (public IP, group, tags,
  registered date) and Configuration (OS, CPU cores, memory, disk, agent version, last
  seen) cards, plus a resource-usage row with real circular gauges for memory/disk
  (and swap, only when the host actually has any configured) showing both percentage
  and actual GB used/free, alongside numeric load-average and uptime tiles.
- Verified end-to-end against a real running agent (not just unit tests): started the
  control plane and a real agent locally, registered it, waited for a live heartbeat,
  and screenshotted the populated dashboard at desktop and 375px — 0px horizontal
  overflow, all figures cross-checked against the container's actual `/proc` values.
- Still deliberately not shown: a "Stack" card (web server/database/provider) — those
  facts are only true after `stack.install` succeeds, and that isn't persisted to the
  control plane yet (only written to a report file on the agent's own disk), so
  showing it before verifying would risk misrepresenting a server's real state. A
  load-history chart remains unimplemented for the same reason as before: no heartbeat
  history is stored yet, only the latest snapshot.

## 2026-08-17 — WordPress deployment actually installs; dashboard redesign

- **Bug fix: selecting "WordPress" as a site type never installed WordPress.** The
  dashboard's New Site flow only ever dispatched `site.create` (system user, PHP-FPM
  pool, nginx vhost); `app.wordpress_install` existed as a capability but nothing ever
  called it, and `site.create` writes no placeholder for `app_type=wordpress` (unlike
  `static`/`php`) — so choosing WordPress produced a working vhost serving an empty
  document root. `handleCreateSite` now chains `site.create` → `db.create` →
  `app.wordpress_install` for WordPress sites, generating a least-privilege database
  and a random admin password, and returns the credentials once in the response (never
  persisted — there is no databases table yet). A failure in a chained step is reported
  as `wordpress_error` alongside the created site rather than as an HTTP error, since
  the site itself already exists at that point and there is no automatic rollback.
  WordPress core still comes from wordpress.org via `wp-cli`, Composer from
  getcomposer.org (SHA-384 verified), and WP-CLI from its official GitHub release
  (SHA-512 verified) — nothing is mirrored or re-hosted by this panel.
- Dashboard redesign: sidebar navigation (off-canvas drawer under 880px with an
  explicit close button), page headers, a restructured server-detail page with a
  configuration card and real SVG usage gauges driven by actual heartbeat data,
  sites/backups count tiles, tables that reflow into stacked cards under 720px,
  bottom-sheet modals on phones, copy-to-clipboard for the install command and
  generated WordPress credentials, focus rings, `aria-label`s on icon-only buttons,
  Escape-to-close on modals, and 40px+ touch targets. No ServerAvatar/Webuzo assets,
  markup, or branding were copied — only generic dashboard patterns common to the
  category.
- Verified with real browser automation (Playwright/Chromium) at 320/375/414/768px and
  desktop: **0px horizontal overflow at every breakpoint**, no console or page errors,
  screenshots reviewed for each. Two real CSS bugs were found and fixed this way: the
  sidebar close button leaked onto desktop (`button.icon-btn`'s `display:inline-flex`
  out-specified a bare `.sidebar-close { display:none }`), and the "Resource usage"
  card rendered as an empty grey box before the first heartbeat.
- Known gap deliberately not faked: the server-detail page has no load/usage *history*
  chart, because only the latest heartbeat is stored — a time-series chart would need
  heartbeat history persisted first, so none is drawn rather than showing invented data.

## 2026-08-17 — Backup restore, backup persistence, and dashboard Backups UI

Closes the single largest functional gap flagged in the prior session's documentation
pass (`docs/SYSTEM.md` §19/§21, `docs/OPERATIONS.md` §3, `docs/TESTING.md` §5 item 1):
there was no way to restore a backup.

- Agent: new `backup.restore` capability
  (`packages/capabilities/backup.go`/`capabilities.go`). Validates `backup_path` stays
  under the agent's managed `backupBaseDir` (rejecting a `../` traversal attempt, not
  just a prefix string match — resolved via `filepath.EvalSymlinks` + `filepath.Clean`
  the same way `resolveScopedPath` does for the file manager), re-verifies the
  archive's SHA-256 if one is supplied, takes a **pre-restore checkpoint** (a fresh
  `backup.run` of the current live state) before touching anything and aborts the
  whole restore if that checkpoint itself fails, then extracts the archive and either
  pipes a SQL dump into `mysql <db>` (new `runWithStdin` helper in
  `exec_helpers.go` — the one place besides `run()` that shells out, still a fixed
  argv, untrusted content only ever flows through stdin) or clears the live site
  directory and copies the restored files back into place.
- Control plane: `backups` table gained `site_root`/`db_name` columns (recorded at
  backup time, so a restore always operates on the exact source a given archive came
  from rather than a caller-resupplied value); new `store.createBackup`/`listBackups`/
  `getBackup` methods; new `POST /api/v1/servers/{id}/backups` (dispatch `backup.run`,
  persist on success — the same dispatch → parse → insert pattern `handleCreateSite`
  already uses), `GET /api/v1/servers/{id}/backups`, and
  `POST /api/v1/servers/{id}/backups/{backupId}/restore` (dispatches `backup.restore`
  using the recorded backup's own params, never caller-supplied ones).
- Dashboard: a "Backups" section on the server-detail page — list, "+ New backup"
  (scope/site-root/db-name form), and a "Restore" button per backup with a
  confirmation dialog explaining the automatic pre-restore checkpoint.
- Testing: capability-level input-validation tests for every rejection path in
  `backup.restore` (invalid scope, `backup_path` outside the managed directory
  including a traversal attempt, missing archive, invalid `site_root`/`db_name`,
  checksum mismatch), plus a **real backup → mutate → restore round trip**
  (`TestBackupRunRestoreFilesRoundTrip`, `packages/capabilities/backup_test.go`)
  against the actual filesystem and real `tar`/`cp` binaries — no mocks. Store-level
  and HTTP-integration tests for the new endpoints, following the same patterns
  `store_test.go`/`http_test.go` already use for sites. `go test ./...` (61 functions,
  up from 48), `go vet`, `gofmt -l`, and `-race` all clean.
- **Bug found and fixed by the new round-trip test** (kept as evidence the testing is
  real, matching this project's existing practice — see `docs/TESTING.md` §4):
  `backup.run`'s output filename only had second-precision timestamp granularity, so
  two backups of the same site+scope within the same second silently overwrote each
  other — exactly what `backup.restore`'s own pre-restore checkpoint does. The round
  trip caught this immediately (the checkpoint clobbered the very archive being
  restored from). Fixed by adding a random 8-hex-char suffix to every backup filename.
- Docs: `SYSTEM.md`, `API.md`, `OPERATIONS.md`, `TESTING.md`, and `README.md` updated
  to reflect that backup restore is implemented and tested, not planned.

Known gap this pass didn't close: restoring to a *different* server is not yet a
one-click flow (the archive/capability don't prevent it, but nothing automates copying
the archive to another agent's backup directory and recording it there — see
`OPERATIONS.md` §3); and `backup.restore`'s `db`/`full` scope has only been
validated for input handling, never against a real MariaDB, since no MariaDB is
available in this session's environment (same limitation `backup.run`/`db.create`
already had — see `TESTING.md` §2).

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
