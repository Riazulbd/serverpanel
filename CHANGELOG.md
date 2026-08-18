# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-18 — Agent certificate auto-renewal

- **Implemented agent certificate auto-renewal**, closing the security/correctness gap
  flagged in `SECURITY.md` §2 and `SYSTEM.md`'s known limitations: agent mTLS client
  certificates were issued with a fixed 30-day TTL and no rotation path, so an agent
  left running past that window would silently become unable to reconnect and require
  a fresh bootstrap token to recover — a real availability risk for any fleet left
  unattended for a month.
- New `renew_request`/`renew_response` message pair in the existing gateway wire
  protocol (`packages/proto/proto.go`), sent over the agent's already-open,
  already-authenticated mTLS session — deliberately not a new HTTP endpoint or
  credential type. `apps/agent/renew.go` checks the agent's own certificate's real
  `NotAfter` (parsed from the certificate itself, not a trusted side value) every 6
  hours and requests renewal once within 7 days of expiry, giving several retries'
  worth of margin before a genuinely missed window forces manual re-registration.
  `gateway.handleRenew` (`apps/controlplane/gateway.go`) signs the replacement using
  `serverID` already derived from the connection's verified peer certificate — never
  from the renewal request's CSR — so renewal can't be used to claim a different
  server's identity, matching how `handleRegister` already works.
- Renewal deliberately does **not** revoke the certificate it replaces
  (`store.renewCert`, new and distinct from `store.revokeServer`): revoking
  immediately would risk a permanent lockout if the agent's disk write of the new
  cert/key ever fails (full disk, killed process) after the old one is invalidated.
  The superseded certificate now just expires on its own original schedule instead —
  a small overlap-validity window traded for "a failed renewal is always recoverable
  on the next 6-hour check," consistent with this project's existing
  recoverable-over-irreversible bias (see the pre-restore-checkpoint design in the
  previous entry).
- New `agentCertTTL` constant (`apps/controlplane/ca.go`) shared by both the
  registration and renewal signing paths, replacing a magic `30*24*time.Hour` literal
  that only registration used to see. `signAgentCSR` now returns the certificate's
  actual `NotAfter` instead of callers re-deriving it. Added a `cert_not_after` column
  (idempotent migration, same pattern as the prior `backups.db_name` migration) so the
  control plane — and now the dashboard's server-detail view — can see when a given
  agent's identity actually expires, not just its serial.
- The agent persists a renewed certificate/key with a temp-file-then-rename write for
  each file (`persistRenewedIdentity`/`atomicWriteFile`), then intentionally closes its
  connection to force a prompt reconnect on the new certificate — proving the new
  identity actually works end-to-end rather than leaving it unused for however long the
  current session happens to stay open.
- Refactored `gateway.listenAndServe` into `newTLSListener` + `serve` so tests can bind
  an ephemeral port and drive the real accept loop directly instead of mocking the
  gateway; this also fixed a latent bug where a closed listener made the accept loop
  spin in a tight error-logging loop forever instead of returning.
- Added 2 store-layer tests, 2 new end-to-end `gateway_test.go` tests that dial the
  real mTLS listener and exercise the actual `renew_request`/`renew_response` wire
  messages (including one that submits a CSR claiming a different server's identity, to
  confirm the gateway ignores it), and `apps/agent`'s first test file
  (`renew_test.go`, 4 tests covering expiry parsing and atomic-write correctness). Full
  suite: 68 test functions, `go vet`/`gofmt` clean, `go test -race ./...` clean.
- Updated `SYSTEM.md`, `SECURITY.md`, `API.md`, and `SERVERAVATAR_PARITY.md` (SRV-001)
  to reflect renewal as implemented and tested.

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
