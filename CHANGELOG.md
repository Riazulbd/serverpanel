# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-22 — Agent certificate auto-renewal

- **Closed the highest-priority security-critical known gap flagged in `SYSTEM.md`**:
  agent client certificates (30-day TTL, `agentCertTTL` in `apps/controlplane/ca.go`)
  previously had no renewal path at all — an agent whose cert expired would be
  permanently locked out (no bootstrap token to fall back on) and require a manual
  operator re-registration on every single server, every 30 days, forever.
- Added a new protocol exchange over the *existing* mTLS session rather than a new
  endpoint: `proto.MsgRenewRequest`/`MsgRenewResponse`. The agent generates a fresh
  keypair + CSR and sends it; the gateway signs a new cert bound to the `server_id` it
  already derived from the connection's peer certificate (`gateway.go`
  `handleRenewRequest`) — never from anything the request itself claims — and updates
  `store.recordRenewedCert`, which tracks the new serial without disturbing connection
  status. The superseded serial is deliberately left un-revoked (it simply expires on
  its original schedule), so a renewal whose response the agent fails to persist can
  never strand it without any valid certificate.
- Agent side (`apps/agent/connect.go` `certRenewalLoop`): checks hourly, renews once
  under 10 days remain (~240 retry attempts before actual expiry), and persists the
  new cert/key atomically (temp-file-then-rename, `persistRenewedIdentity`) before
  adopting it in memory — so a crash mid-renewal always leaves either the complete old
  identity or the complete new one on disk, never a mismatched pair.
- Fixed a latent, pre-existing concurrency bug surfaced while adding a third
  concurrent writer to the agent's connection: `heartbeatLoop` and every in-flight
  task's `TaskEvent` were both calling `json.Encoder.Encode` on the same connection
  without any synchronization, which can interleave partial writes into invalid JSON
  on the wire under concurrent load. Introduced a small mutex-guarded `encoder`
  wrapper shared by all three writers.
- Refactored `gateway.listenAndServe` into `tlsListener` + `serve` so tests can bind an
  ephemeral port and drive a real mTLS session end-to-end, rather than only exercising
  the gateway indirectly through HTTP handlers.
- Tests: 2 new full mTLS integration tests (`apps/controlplane/gateway_test.go` —
  successful renewal issues a new serial/cert bound to the right identity and updates
  the store, and a malformed-CSR renewal is rejected without mutating server state), 1
  new store test (`recordRenewedCert` updates the serial without touching connection
  status and leaves the old serial unrevoked), and 5 new agent-side unit tests
  (`apps/agent/register_test.go` — CSR generation/verification, cert-expiry parsing,
  and atomic identity persistence including a failure path). Full suite (68 test
  functions total) passes under both `go test` and `go test -race`.
- Updated `SYSTEM.md` (§7 agent lifecycle, §11 agent auth summary, known limitations —
  removed the closed gap, added a narrower one: no distinguishable alert yet if
  renewal keeps failing all the way to actual expiry) and `SECURITY.md` §2 (mTLS
  renewal is now marked implemented, with the design rationale inline).

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
