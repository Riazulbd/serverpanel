# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-23 — Agent certificate auto-renewal, two latent bugs fixed

- **Implemented agent client-certificate auto-renewal**, closing SRV-001's one
  remaining documented gap (`SECURITY.md` §2 had described this design since the
  security-model doc was written, but no code implemented it — client certs were
  issued with a fixed 30-day TTL and, without this, every connected agent in the fleet
  would have silently lost connectivity 30 days after registration with no automated
  recovery path). New wire messages `renew_request`/`renew_response`
  (`packages/proto/proto.go`); the agent (`apps/agent/renew.go`) checks its current
  certificate's expiry every hour and, once within 7 days of `NotAfter`, sends a fresh
  CSR over the *already-authenticated* mTLS session — no bootstrap token, no new
  registration. The gateway (`gateway.handleRenew`, `apps/controlplane/gateway.go`)
  signs the replacement bound to the session's already-verified `server_id` (never
  anything the request itself claims, same invariant the initial registration path
  already enforced), records the new serial via a new `store.updateCertSerial` (kept
  deliberately separate from `markIssuedCert`, which also forces status to "offline" —
  correct at registration, wrong mid-session), and replies. The agent persists the new
  identity atomically (`writeFileAtomic`, shared with a refactored `register.go`) and
  closes the connection so the very next reconnect — which now reloads identity from
  disk before each redial (`main.go`) — picks up the new cert immediately, instead of
  it sitting unused until some unrelated reconnect. A failed/rejected/timed-out
  renewal never tears down the still-valid live session; it just retries on the next
  hourly check.
- Extracted CSR/keypair generation (`generateKeyAndCSR`) and atomic file writes
  (`writeFileAtomic`) out of `register.go` into a shared `apps/agent/csr.go`, used by
  both the registration and renewal paths, so the two issuance flows can't drift apart.
- **Fixed a latent goroutine leak**: `heartbeatLoop` (and now the renewal loop) were
  scoped to the reconnect loop's long-lived outer `context.Context` rather than to the
  individual connection attempt, so every reconnect left the previous connection's own
  background goroutines running forever, silently failing writes against an
  already-closed socket, for the life of the process. Fixed by deriving a
  per-connection `context.WithCancel` in `runConnection` and tying both loops to it.
- **Fixed a busy-spin bug** in the gateway's mTLS accept loop: any `Accept()` error
  (e.g. the listener being closed) looped forever with no backoff or exit condition —
  caught immediately while writing the new end-to-end test below, since closing the
  test's listener triggered it. `gateway.go`'s `listenAndServe` is now split into
  `listenAndServe` (binds the real address) and `serve` (runs the accept loop against
  an already-bound `net.Listener`, also letting tests bind an OS-assigned port and
  discover the real address); `serve` now returns the error instead of looping,
  matching `net/http`'s `Server.Serve` convention and what `main.go` already expected
  (`log.Fatalf` on a non-nil return).
- Added 7 new tests: 3 in `apps/controlplane/gateway_test.go` (same-`server_id`/
  fresh-serial/later-expiry renewal invariants, that renewal never clobbers a live
  connection's status the way registration's `markIssuedCert` deliberately does,
  invalid-CSR rejection, and — the only test in the suite exercising the actual wire
  protocol rather than calling a handler directly — a real end-to-end mTLS round trip
  through Hello→Ack→RenewRequest→RenewResponse against a live `gateway.serve`
  listener) and 4 in a new `apps/agent` test package (`certExpiringSoon`'s
  renewal-window decision against real self-signed certificates, `generateKeyAndCSR`,
  `writeFileAtomic`) — `apps/agent` previously had zero automated test coverage.
  `go test ./... -race` and `go vet ./...` both clean.
- Docs updated: `SECURITY.md` §2 (implemented, no longer "not yet"), `API.md` §3 (new
  message types + the renewal flow), `SYSTEM.md` (§2 feature table, §11, §21),
  `SERVERAVATAR_PARITY.md` (SRV-001), `TESTING.md` (§1 coverage table, §4 bug list).

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
