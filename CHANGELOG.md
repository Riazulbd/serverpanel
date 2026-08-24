# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-24 — Agent certificate auto-renewal (SRV-012)

- **Implemented automatic agent certificate renewal**, closing the highest-severity
  latent defect in the system: agent certificates are issued with a 30-day TTL and
  there was no renewal path, so every deployed agent would have gone permanently
  offline 30 days after enrollment and needed a manual re-install to recover.
- Renewal is a new `cert_renew_request`/`cert_renew_response` message pair carried
  **over the agent's existing mTLS session**, not a new HTTP endpoint. The request
  carries only a CSR; the certificate is issued for the identity derived from that
  connection's verified peer certificate, so an authenticated agent can renew its own
  identity and nothing else, renewal needs no bootstrap token, and no new
  unauthenticated surface is added. Each renewal generates a **fresh private key** —
  a real credential rotation, not an expiry-date extension.
- **Revocation now covers every certificate ever issued to a server**, via a new
  `issued_certs` table. This is a prerequisite, not a nicety: renewal deliberately
  leaves the superseded certificate valid for the rest of its own TTL (so an agent
  that fails to persist the new one is retryable rather than permanently locked out),
  which means revoking only `servers.cert_serial` would have left a still-usable
  certificate behind.
- `handleCertRenew` re-checks the server's status, so a revoked server cannot mint
  itself a fresh certificate on a connection opened before the revocation landed —
  the handshake-time check has already passed for that session.
- Agent-side, the renewed pair is written under fresh filenames and committed with a
  single atomic rename of `identity.json` (which now names the authoritative pair).
  There is no window in which the certificate and key on disk belong to different
  keypairs, and a crash before the rename leaves the previous identity fully usable.
  Identities written before this change have no pointer fields and fall back to the
  original filenames, so an already-installed agent keeps working across an upgrade.
- **Fixed an unsynchronized-write bug found while touching this code**: heartbeats,
  progress events from concurrently-running tasks, and now renewal requests all share
  one connection, and `json.Encoder` is not safe for concurrent use — interleaved
  partial writes could desynchronize the gateway's decoder for the rest of a session.
  All agent writes now go through a mutex-guarded `connWriter`.
- **A real end-to-end run found a renew/reconnect loop that every unit and integration
  test had passed.** Run against real control-plane and agent processes with the TTL
  and check interval compressed (only those two constants differed from production),
  it produced **18,588 renewals in 100 seconds**: a successful renewal drops the
  connection so the new certificate takes effect at once, and a certificate that still
  reads as near-expiry turns that into a flood against the gateway — reachable in
  production via a badly skewed system clock or a shortened TTL. Fixed with
  `renewalGate`, a process-wide rate limit that logs loudly when it holds an attempt
  back; the identical scenario then produced 2 renewals in the same window, with the
  agent reconnecting and staying connected on each new certificate. Full write-up in
  `TESTING.md` §4a.
- Added 10 tests: 4 in a new `apps/controlplane/gateway_test.go` — the **first tests in
  this codebase to stand up the real mTLS listener** and connect a CA-issued client
  certificate to it — and 6 in a new `apps/agent/renew_test.go` (the agent package had
  no tests at all before this). Full suite: 74 test functions, `-race` clean,
  `go vet`/`gofmt` clean.
- Updated `SYSTEM.md`, `SECURITY.md` (§2 rewritten from "not yet implemented" to the
  implemented design, including why the superseded certificate is intentionally left
  valid), `API.md` (renewal message pair documented in the wire protocol), `TESTING.md`
  (new §4a), and `SERVERAVATAR_PARITY.md` (new SRV-012 entry, `COMPLETE`).

## 2026-08-24 — Database management wired end-to-end (DB-005)

- **Databases are now a first-class, per-site resource in the control plane**, closing
  the gap flagged in `SERVERAVATAR_PARITY.md` DB-001: the `db.create`/`db.delete`
  capabilities existed agent-side but were only reachable through generic task dispatch,
  with nothing recorded and no dashboard surface. Added a `databases` table
  (`server_id`, `site_id`, `name`, `owner_user`, `status`, `created_at`), store methods
  (`createDatabase`/`listDatabases`/`getDatabase`/`deleteDatabase`, each scoped by
  server ID the same way `getSite`/`getBackup` are), and three endpoints:
  `GET`/`POST /api/v1/servers/{id}/sites/{siteId}/databases` and
  `POST /api/v1/servers/{id}/databases/{dbId}/delete`.
- **The owner password is generated server-side and never stored.** It is not accepted
  from the caller (so it can't be weak or reused), is returned exactly once in the
  creation response the way a bootstrap token is, and has no column in the `databases`
  table — a compromise of the control plane's SQLite file yields no usable database
  credential. Delete reads `name`/`owner_user` from the stored row rather than from
  client input, so a caller can only ever drop a database this control plane recorded.
- The identifier allow-list (`^[a-z][a-z0-9_]{0,30}$`) is now enforced twice
  independently — control plane before dispatch, agent before the statement — matching
  the defense-in-depth pattern `stack.install`'s OS/resource preflight checks use.
- Dashboard: site-detail "Databases" panel (create modal showing the generated
  credentials once, databases table, per-row delete behind a destructive-action
  confirmation). The backup modal's database field is now a select populated from the
  site's recorded databases instead of free text, falling back to a text input when
  none are recorded yet.
- A failed `db.delete` dispatch deliberately leaves the record in place rather than
  removing it: dropping the row on a transport failure would orphan a real database the
  control plane no longer knows about. Covered by its own regression test.
- Added 3 tests (1 store CRUD/scoping round trip, 2 HTTP integration tests covering
  not-found boundaries, six malformed-identifier rejections, and both
  persist-nothing-on-failed-create and keep-record-on-failed-delete). Full suite: 64
  test functions, `go vet`/`gofmt` clean.
- Updated `SYSTEM.md`, `API.md`, `TESTING.md`, and `SERVERAVATAR_PARITY.md` (DB-005
  `NOT_STARTED` → `COMPLETE`; DB-001's remaining gaps narrowed to MongoDB,
  phpMyAdmin integration, query monitoring, multi-user-per-database, and remote-host
  access rules).

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
