# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-19 — Agent certificate rotation

- **Implemented automatic agent certificate renewal**, closing the last of the three
  gaps `SYSTEM.md` had flagged as blocking Phase 1. Agent certificates are issued for
  30 days and, until now, had no renewal path at all: every connected server would
  have silently dropped out of the fleet 30 days after enrollment, recoverable only by
  manually re-registering each one.
- Renewal rides the **already-authenticated mTLS session** rather than a new endpoint
  (`renew_request`/`renew_response`/`renew_ack` in `packages/proto`). Possession of a
  currently valid, non-revoked certificate is precisely the right authorization to be
  issued its successor, and the gateway already knows the peer's identity without
  trusting anything asserted in-band.
- Ordering is built so an interruption can never strand a server: the gateway signs and
  sends the successor but changes *nothing* until the agent confirms it is durably on
  disk; the agent writes each file write-temp → fsync → rename, and only then
  acknowledges; the acknowledgement is what atomically adopts the new serial and
  revokes the old one (`store.commitCertRenewal`, one transaction — the half-applied
  states both being bad is exactly why). An agent that dies at any point still holds a
  valid certificate and retries on its next reconnect, with ~10 days of headroom.
- Each renewal generates a **new keypair** rather than re-certifying the existing one:
  rotating the certificate while keeping the key leaves the thing most worth stealing
  unchanged. The successor's identity is set by the gateway from the handshake, never
  from the CSR, so an agent cannot renew into another server's identity. A revoked
  certificate cannot be renewed (re-checked at renewal time, since a session can
  outlive the revocation that happened during it), and one renewal per session bounds
  serial-number churn from a misbehaving agent.
- **Fixed a pre-existing data race**: the agent wrote to a shared `json.Encoder` from
  the heartbeat goroutine and every task goroutine with no synchronization. Two
  interleaved encodes emit a corrupt frame that desynchronizes the connection for the
  rest of the session. Writes now go through a mutex-guarded `sender`.
- `gateway.listenAndServe` split into `listen`/`serve` so the listener's bound address
  is knowable before serving (needed to test against an ephemeral port). The accept
  loop now returns its error to `main`'s existing `log.Fatalf` instead of `continue`ing
  forever, which on a closed listener was an unlogged busy-spin.
- Added 10 tests, including 4 rotation integration tests against a real mTLS listener,
  real CA, and real database — enrolling an agent through the actual `/agents/register`
  endpoint and driving the real protocol — plus the first tests in `apps/agent`. Full
  suite: 79 test functions across three packages, `go vet`/`gofmt` clean, passes with
  `-race`.
- Updated `SECURITY.md` §2 (`partially implemented` → `implemented`), `API.md` (wire
  protocol + a renewal section), `SYSTEM.md` (§2 feature table, §3 phase status, §7
  agent lifecycle, §11 agent auth, and removed the now-closed known limitation),
  `TESTING.md`, and `SERVERAVATAR_PARITY.md` (SRV-001).

## 2026-08-19 — Database management end-to-end

- **Wired database management through the full stack**, closing the highest-priority
  remaining gap in the parity matrix (DB-005): the `db.create`/`db.delete`/`db.list`
  agent capabilities already existed but were only reachable through generic task
  dispatch, with no persistence and no UI. They now have dedicated control-plane
  endpoints (`GET`/`POST /api/v1/servers/{id}/databases`,
  `DELETE /api/v1/servers/{id}/databases/{databaseId}`), a `databases` table, and a
  "Databases" panel on each server-detail page.
- The owner password is now **generated server-side** (24 characters from `crypto/rand`
  over a shell/URL-safe alphabet), returned to the caller exactly once, and never
  persisted or logged — the same "shown once" handling the bootstrap-token install
  command already used. Previously a caller had to supply it themselves through generic
  dispatch, which put a plaintext credential in the request body for no benefit.
- `db.create` now returns structured JSON (`{"name", "owner_user"}`) instead of a prose
  string, so the control plane can parse its result to persist a record — the same
  dispatch-then-persist-on-success pattern `site.create` and `backup.run` use. Delete
  reads the target's name/owner from the stored row rather than client input, so a
  caller can only ever drop a database this control plane actually recorded.
- Exported `capabilities.ValidIdentifier` so the control plane validates database names
  with the *exact* pattern the agent enforces, rather than a second copy of the regex
  that could silently drift out of sync with what actually gets executed.
- Added 8 tests (control-plane store CRUD + cross-server ID scoping, two HTTP boundary/
  validation tests proving validation runs before dispatch, and capability-layer
  validation-rejection tests plus `ValidIdentifier` boundary cases). Full suite: 69 test
  functions, `go vet`/`gofmt` clean.
- Updated `SYSTEM.md` (new §19 Databases, schema table, feature list), `API.md`,
  `TESTING.md`, and `SERVERAVATAR_PARITY.md` (DB-001 `PARTIAL` → `COMPLETE`, DB-005
  `NOT_STARTED` → `COMPLETE`, new DB-006 for the multiple-users-per-database gap this
  surfaced). The live-MariaDB SQL round trip remains `BLOCKED_EXTERNAL` in this
  environment, as it already was for the backup db/full scopes.

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
