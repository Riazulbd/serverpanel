# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-23 — Agent certificate auto-renewal

- **Closed the last open item in `docs/SECURITY.md` §2**: client certificates now
  auto-renew before their 30-day expiry, exactly as that section's trust-model design
  already described but the code hadn't implemented yet. An agent whose certificate is
  within 7 days of expiring sends a `renew_cert` request over its already-open,
  already-authenticated mTLS session; the gateway signs a fresh certificate bound to the
  identity it independently derived from that connection's own peer certificate (never
  anything the request claims) and replies with `renew_cert_result`. No bootstrap token,
  no new connection, no shared long-lived secret reused for renewal.
- New wire protocol messages (`packages/proto/proto.go`): `MsgRenewCert`/
  `MsgRenewCertResult`, `RenewCert{CSRPEM}`, `RenewCertResult{CertPEM, Error}`.
- `apps/controlplane/gateway.go`: `handleRenewCert` signs the CSR via the existing
  `ca.signAgentCSR` (same `agentCertTTL` constant — now shared, previously duplicated
  as a literal `30*24*time.Hour` in `http.go` — between initial registration and
  renewal) and replies over the same session; a malformed CSR gets an error result, not
  a closed connection. `listenAndServe` was split into `listen`/`serve` so tests can
  bind an ephemeral port and dial in with a real client certificate.
- `apps/agent/renew.go` (new): `certRenewer` tracks one in-flight renewal (guarded by a
  mutex that also protects `identity.CertPEM`/`KeyPEM` against the genuine
  cross-goroutine race this feature introduces — see below), checks expiry via
  `certExpiry`, builds a CSR via `buildCSR`, and on success persists the new cert/key to
  the agent's data directory and updates the in-memory identity for the connection's
  *next* dial — deliberately without forcing the current, still-valid session to
  reconnect early.
- **Two real bugs found and fixed while building this** (see `docs/TESTING.md` §4 for
  the full writeup): (1) `heartbeatLoop` — and, unfixed, the new `renewalLoop` — was
  scoped to the agent process's lifetime context rather than one connection's, so every
  dropped connection leaked that goroutine running forever against a dead socket; fixed
  with a per-connection `context.WithCancel` in `runConnection`. (2) Reusing
  `markIssuedCert` to record a renewed certificate's serial would have reset a live,
  connected server's dashboard status to "offline" on every renewal (that function
  unconditionally sets status alongside the serial, correct only at initial
  registration before any connection exists); fixed with a dedicated
  `updateCertSerial` store method that touches only the serial column.
- Added 10 new tests: `apps/controlplane/gateway_test.go` (2 tests, dialing a real
  `gateway.listen`/`serve` instance with a genuine client certificate — renewal issues a
  correctly-bound fresh certificate while leaving a live session's connected status
  untouched, and a malformed CSR is rejected without closing the session) and
  `apps/agent/renew_test.go` (8 tests — this package's first test file — covering
  expiry parsing, the renewal-threshold/no-double-send decision logic, and all three
  outcomes of handling a renewal result, including a real `tls.X509KeyPair` check that
  a persisted renewal's key actually pairs with its certificate). `go test ./...` now
  covers 78 test functions (was 68) across three packages (was two), all passing under
  `-race`; `go vet`/`gofmt -l` clean.
- Updated `docs/SECURITY.md` (§2 now "mostly implemented" instead of "partially"),
  `docs/SYSTEM.md` (§2 core-platform table, §7 agent lifecycle, §21 known limitations),
  `docs/API.md` (§3 wire protocol), `docs/TESTING.md` (counts, coverage, bug list), and
  `docs/SERVERAVATAR_PARITY.md` (SRV-001's "Known differences" closed out).

## 2026-08-23 — Database management: control-plane persistence + dashboard UI

- **Closed the DB-005 parity gap** flagged in the previous entry's tracker
  (`docs/SERVERAVATAR_PARITY.md`, DB-001 "Known differences"): databases created via
  `db.create` are now durable, listed, and deletable through the dashboard, following
  the same dispatch-then-persist-on-success pattern `handleCreateSite`/
  `handleCreateBackup` already established.
- `packages/capabilities/db.go`: `handleDBCreate` now returns a JSON `dbResult`
  (`{name, owner_user}`) instead of a plain sentence, so the control plane can parse and
  persist it — the same shape change `site.create`'s `siteResult` introduced.
- New `databases` table (`server_id`, `site_id`, `name`, `owner_user`, `status`,
  `created_at` — no password column, ever) and `store` methods `createDatabase`/
  `listDatabases`/`getDatabase`/`deleteDatabase`, each scoped by server ID the same way
  `getSite`/`getBackup` are.
- Three new endpoints (`apps/controlplane/databases.go`): `GET`/
  `POST /api/v1/servers/{id}/sites/{siteId}/databases`,
  `DELETE /api/v1/servers/{id}/databases/{databaseId}`. The owner password is generated
  server-side (`generateDBPassword`, `crypto/rand`, 24 random bytes/base64url) — never
  accepted from the caller, never stored after the one-time response that returns it.
  `name`/`owner_user` are validated against the same identifier allow-list the agent
  uses, at the control-plane layer, before a task is ever dispatched.
- A "Databases" panel landed on the site-detail dashboard view (`web/index.html`): list
  table, "+ New database" modal, and a delete action with a destructive-action confirm.
- Added 7 new tests: `packages/capabilities/db_test.go` (identifier-allow-list and
  password-length validation for `db.create`/`db.delete`, the layer that runs before
  any MariaDB connection is attempted), `apps/controlplane/store_test.go`
  (`TestDatabaseCreateListGetDeleteRoundTrip`), and `apps/controlplane/http_test.go`
  (`TestDatabaseEndpointsRequireARealSite`, `TestCreateDatabaseRejectsInvalidIdentifiers`).
  `go test ./...` now covers 68 test functions (was 61), all passing;
  `go vet`/`gofmt -l` clean.
- Updated `docs/SYSTEM.md` (§8 schema, §12 capability list), `docs/API.md` (three new
  endpoint entries), `docs/TESTING.md` (updated counts/coverage description), and
  `docs/SERVERAVATAR_PARITY.md` (DB-005 promoted to a detailed `COMPLETE` entry; DB-001
  "Known differences" narrowed to MongoDB/DB-admin-UI only).
- **Known remaining gap, unchanged by this pass**: the real agent-side
  `CREATE DATABASE`/`CREATE USER`/`GRANT` round trip still requires a live MariaDB
  instance to verify end-to-end — this environment has none, so that path remains
  manually-verified-in-a-prior-session, the same documented limitation `backup.run`'s
  db/full scope already carries.

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
