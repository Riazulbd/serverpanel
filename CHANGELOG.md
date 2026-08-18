# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-18 — Agent certificate auto-renewal

- **Implemented agent client-certificate auto-renewal**, closing the security gap
  `SECURITY.md` §2 had flagged as not-yet-built since the initial trust-model design:
  an agent's 30-day mTLS client certificate previously had no rotation path short of
  a human manually re-running the install command with a fresh bootstrap token once it
  expired. `apps/agent/connect.go`'s new `renewalLoop` checks hourly and, once fewer
  than 7 days of validity remain, sends a `renew_csr` message over the agent's
  *existing* authenticated connection — no shared long-lived secret is ever reused.
  `apps/controlplane/gateway.go`'s new `renewAgentCert` signs the replacement bound to
  the server ID it already derived from that live session's peer certificate at
  handshake time (the CSR's own requested Subject is ignored outright, so a connected
  agent can only ever renew its own identity), and replies with `renew_cert`. The
  previous certificate is deliberately left un-revoked — an overlap window until its
  own natural expiry, not an instantaneous swap — so an agent crash or dropped
  connection between receiving the new certificate and durably persisting it to disk
  can never strand the machine requiring manual re-registration for no operational
  reason. The agent persists the renewed identity via an atomic temp-file-then-rename
  write and updates its in-memory identity in place, so the very next reconnect (for
  any reason — network blip, control-plane restart) picks it up automatically.
- Added two new wire message types (`renew_csr`/`renew_cert`, `packages/proto/proto.go`)
  and a shared `agentCertTTL` constant (`apps/controlplane/gateway.go`) now used by both
  first registration and renewal, replacing a duplicated magic-number TTL.
- **Fixed a latent goroutine-leak bug** found while wiring the renewal loop in:
  `heartbeatLoop` was launched against the agent process's top-level context, not one
  scoped to the individual connection — so every reconnect (a normal, expected event
  over a long agent uptime) leaked one ticker goroutine forever, retrying failed writes
  to an already-closed connection. Both `heartbeatLoop` and the new `renewalLoop` are
  now scoped to a per-connection `context.WithCancel`, cancelled when `runConnection`
  returns.
- **Fixed a latent concurrent-write race** on the agent's connection encoder: task
  results (`handleTask`, one goroutine per in-flight task) and heartbeats were both
  calling `enc.Encode` on the same unsynchronized `*json.Encoder` concurrently, which
  could interleave two JSON messages into one corrupted line on the wire under `-race`
  detection. Introduced `safeEncoder`, a small mutex-guarded wrapper now shared by
  `heartbeatLoop`, `handleTask`, and `renewalLoop`.
- **Fixed the same class of race on `identity`'s certificate fields**: renewal
  updates `CertPEM`/`KeyPEM` from a background goroutine that can outlive a single
  `runConnection` call, and the next reconnect's `tls.X509KeyPair` read had no
  synchronization against a still-in-flight renewal write. Made both fields
  private, reachable only through mutex-guarded `certKeyPEM()`/`setCertKeyPEM()`
  accessors — the full suite (including `apps/agent`, which had no test file
  before this change) now passes under `go test -race`.
- Added `apps/controlplane/renewal_test.go` (4 tests: renewal binds to the
  already-authenticated server ID regardless of what the CSR requests, the store
  updates to the new serial while the previous serial is confirmed *not* revoked — the
  overlap window — an unknown server ID is rejected, and successive renewals chain
  correctly) and `apps/agent/register_test.go` (9 tests: this is `apps/agent`'s first
  test file — CSR/keypair generation and PEM round-tripping, the renewal-threshold
  decision function, atomic file persistence, and that a renewed identity survives a
  simulated process restart via `loadIdentity`). Full suite: 74 test functions across
  three packages (was 61 across two), `go vet`/`gofmt` clean, `-race` clean.
- Updated `SECURITY.md` §2 from "partially implemented" to "implemented", `API.md` §3
  with the new wire messages, `SYSTEM.md` (§2 feature table, §11, §21 known
  limitations), `TESTING.md`, and `docs/SERVERAVATAR_PARITY.md` (new AGT-002 entry) to
  match — including an explicit, undisguised note that the actual `renew_csr`/
  `renew_cert` exchange over a live TCP socket is *not* covered by the automated suite
  (a structural limit: `apps/agent` and `apps/controlplane` are both `package main`, so
  one Go test binary can't import both to drive a real connection between them), the
  same honest gap the pre-existing agent connect/reconnect loop already had before this
  change.

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
