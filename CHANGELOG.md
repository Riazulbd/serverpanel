# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-23 — Agent certificate auto-rotation

- **Implemented proactive agent certificate renewal**, closing the top-priority
  security gap flagged in `SECURITY.md` §2 and `SERVERAVATAR_PARITY.md` SRV-001:
  agent client certificates were issued with a fixed 30-day TTL and had no renewal
  path at all — an agent whose cert expired required manual re-registration with a
  fresh bootstrap token, with no automated recovery in between.
- Added two new wire-protocol messages (`packages/proto`): `renew_request` (agent →
  gateway, a freshly generated CSR) and `renew_response` (gateway → agent, the newly
  issued certificate). Sent over the connection already authenticated by the agent's
  *current* still-valid certificate — no shared long-lived secret is ever reused for
  renewal, matching the same trust model as the original bootstrap-token exchange.
- `apps/agent/renew.go`: `renewalLoop` checks every 6 hours whether the connection's
  current certificate is within 10 days of expiry (a third of the 30-day TTL, leaving
  multiple retry windows) and, if so, generates a new keypair/CSR and sends
  `renew_request`. On `renew_response`, the new certificate is persisted to disk
  (temp-file-then-rename, so a crash mid-write can never leave a half-written
  cert/key), and the connection is deliberately closed and redialed — a live TLS
  session can't have its client certificate swapped in place — with `main.go`
  reloading the identity from disk before the next dial.
- `apps/controlplane/gateway.go`: `handleRenewRequest` signs the CSR and binds the new
  certificate to the identity from the **connection's already-verified peer
  certificate** — never anything the CSR itself claims — and records the new serial
  via a new `store.updateCertSerial` (deliberately separate from `markIssuedCert`,
  which also flips status to `offline`; a renewal happens over a connection that is,
  by definition, already `connected`, and must not make it look otherwise).
- Fixed a related latent issue while touching the agent's reconnect loop
  (`apps/agent/main.go`): per-connection background goroutines (heartbeat, and now
  renewal) previously ran on the process-lifetime context instead of one scoped to
  their own connection, meaning a dead connection's heartbeat loop kept retrying
  writes to a closed socket forever; and reconnect backoff never reset after a long
  healthy connection, so a fleet running long enough would have every future
  reconnect — including transient blips — start at the 30s cap. Both fixed: each
  `runConnection` call now gets its own cancelable context, and backoff resets to 1s
  after any connection that stayed up more than 30s.
- Added 4 new control-plane tests (`apps/controlplane/gateway_test.go`, exercising
  `handleRenewRequest` over an in-memory `net.Pipe`: identity binding ignores a CSR
  requesting a different identity, renewal never flips a connected server's status to
  offline, an invalid CSR is rejected without touching the stored serial, a nil/empty
  request is a no-op) and 3 new agent tests (`apps/agent/renew_test.go`: `certExpiry`
  parsing, and `applyRenewal`'s atomic persist-then-`loadIdentity` round trip). Full
  suite: 68 test functions across three packages, `go vet`/`gofmt`/`-race` clean.
- Updated `SECURITY.md` §2, `API.md` §3 (wire protocol), `SYSTEM.md` (§2 table, §11,
  §21, §23, Phase 1 summary), `TESTING.md`, and `SERVERAVATAR_PARITY.md` SRV-001 to
  reflect renewal as implemented. Remaining, explicitly documented gap: no automated
  alert/fallback if the renewal window is missed entirely (agent offline past its
  cert's actual expiry) — that's a monitoring/alerting feature, not a renewal-protocol
  gap, and is tracked separately.

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
