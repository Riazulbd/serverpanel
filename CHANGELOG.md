# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-18 — Product scope decision: narrow notifications/backups, drop white-label/reseller/billing

Product-owner decision, recorded here and reflected across the planning docs (no code
changes — none of the affected features had been built yet):

- **Notification channels**: scope narrowed to **Email, Telegram, and a generic
  outbound Webhook only**. Slack, Discord, and Pushover are intentionally out of scope,
  not deferred.
- **Remote backup storage**: scope narrowed to **Amazon S3 only** — not a pluggable
  multi-provider adapter. R2/B2/Spaces/Wasabi/Google Drive/Dropbox are intentionally
  out of scope, not deferred.
- **White-label and reseller/self-hosted panel**: removed from the roadmap entirely.
  Not a later phase — this product will not have branding/custom-domain white-labeling,
  an admin/reseller panel, or a customer-facing scoped control panel.
- **Billing/wallet/subscriptions**: removed from the roadmap entirely. No wallet
  ledger, plans/entitlements, payment-provider adapters, or invoicing.
- Updated `product-plan.md` (§6 Phase 2/3 milestone tables, §9 postponed-features list,
  §10 resolves the pricing/packaging and self-hosted-panel open questions as N/A),
  `SERVERAVATAR_PARITY.md` (INT-003/INT-004 scoped down; BILL-001..004 and
  WL-001/002/RS-001..003 moved to `INTENTIONALLY_NOT_APPLICABLE` with the decision
  recorded as their reason, progress-summary counts updated), `SYSTEM.md`, and
  `README.md` to match.

## 2026-08-18 — Agent certificate auto-renewal

- **Implemented in-session agent certificate auto-renewal**, closing the top item in
  the known-limitations list (`SYSTEM.md` §21) and the pre-planned-but-unbuilt design
  in `SECURITY.md` §2: agent client certs were issued with a fixed 30-day TTL and no
  renewal path existed, so every agent would silently lose connectivity roughly a
  month after enrollment, requiring a human to generate a fresh bootstrap token and
  manually re-register it — a real production correctness/availability defect, not a
  cosmetic gap.
- Added a `renew`/`renewed` message pair to the agent↔gateway wire protocol
  (`packages/proto/proto.go`), riding the *existing* mTLS session rather than adding a
  new endpoint: the gateway (`apps/controlplane/gateway.go` `handleRenew`) re-derives
  `server_id` from the connection's already-verified peer certificate — never from the
  agent-supplied CSR's subject — and signs a fresh 30-day cert under that same
  `server_id` (`store.markRenewedCert`). The agent (`apps/agent/renew.go`) checks its
  current cert's expiry once an hour (plus once on connect) and requests renewal once
  within 7 days of expiring, then durably persists the response via a temp-file+rename
  before swapping its in-memory identity over, so a crash mid-renewal can never leave a
  half-written cert/key pair or lose the agent's only working identity.
- **Deliberate design choice**: the previous certificate is left un-revoked after
  renewal rather than proactively revoked, so a lost renewal response or a crash before
  the agent durably persists the new cert can never permanently brick its connectivity
  — the accepted cost is a bounded (≤30-day) window where two certs for the same
  `server_id` are simultaneously valid, not an open-ended one.
- Added `apps/controlplane/gateway_test.go`, the first automated test to dial a real,
  live `gateway.listenAndServe` mTLS listener directly (not `httptest`, since the
  gateway is a raw TLS socket, not HTTP): connects as an agent with a CA-issued cert,
  completes the handshake/ack, requests renewal, and asserts the new cert's CN/serial/
  expiry, the store's updated `cert_serial`, that the old serial was **not** revoked,
  and that the still-open old-cert-authenticated connection keeps working afterward.
  Added `apps/agent/renew_test.go` (expiry parsing, atomic file replacement,
  in-memory identity consistency) — the first tests for `apps/agent`, previously
  untested. Full suite: 66 test functions across three packages, `go vet`/`gofmt`/
  `go test -race` all clean.
- Updated `SECURITY.md` §2, `API.md` §3, `SYSTEM.md`, `TESTING.md`, and
  `SERVERAVATAR_PARITY.md` (SRV-001) to reflect renewal as implemented and tested.

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
