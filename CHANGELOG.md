# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-18 — SSL: wire up the dashboard, fix custom-cert install

- **Closed a real correctness gap in `ssl.install_custom`**: it previously wrote the
  certificate/key to disk and stopped — nothing ever pointed nginx at them, so a
  "successful" custom SSL install left the site serving plain HTTP with no error to
  say so. It now verifies the certificate and key actually match
  (`crypto/tls.X509KeyPair`) and cover the requested domain
  (`x509.Certificate.VerifyHostname`), rejects an already-expired certificate, and —
  only once all of that passes — wires the cert into the site's existing nginx vhost
  (`injectHTTPSListen`, a pure text transform that adds the `listen ... ssl` and
  `ssl_certificate*` directives on first install and updates them in place on a
  re-install/renewal, so a retry never produces a duplicate-directive `nginx -t`
  failure), verifies `nginx -t`, and reverts to the last-known-good vhost if it fails
  rather than leaving nginx broken.
- **Added `ssl.status`**, a new capability that reports what certificate is actually
  installed for a domain (source, expiry, issuer) by reading the certificate file
  itself — never trusted from a handler's own report of what it did. Both
  `ssl.issue_letsencrypt` and `ssl.install_custom` now call this internally and return
  it as their result, so what the control plane records is always a live read of the
  agent's filesystem.
- **Wired SSL into the control plane end-to-end** — previously the capabilities existed
  agent-side with no way to reach them except a raw generic-task-dispatch call and no
  UI at all. Added three endpoints (`POST /api/v1/servers/{id}/sites/{siteId}/ssl/
  {letsencrypt,custom,status}`), a `sites.ssl_status`/`ssl_expires_at`/`ssl_checked_at`
  migration, and a dashboard "SSL certificate" panel per site (status line with an
  expiry countdown that turns into a warning under 14 days, "Issue Let's Encrypt
  certificate", "Install custom certificate" modal, "Check status").
- Added 14 new tests: `packages/capabilities/ssl_test.go` (cert/key-mismatch,
  wrong-hostname, expired-cert, and invalid-domain rejection; the vhost text-transform's
  add/idempotent-update/leave-unrecognized-files-alone behavior), `apps/controlplane/
  http_test.go` (site-scoping and validate-before-dispatch boundary tests), and
  `apps/controlplane/store_test.go` (`setSiteSSL` persistence and cross-server
  scoping). Full suite: 75 test functions, `go vet`/`gofmt` clean. Manually verified in
  a live-server + headless-browser smoke test (login → open site detail → SSL status
  line renders installed/expiring/none states correctly → custom-cert modal opens and
  closes) since no real agent-connected server was available in this environment to
  exercise the actual `certbot`/`nginx` round trip end-to-end — that remains
  `BLOCKED_EXTERNAL` per `SERVERAVATAR_PARITY.md` APP-015/APP-016.
- Updated `SYSTEM.md`, `API.md`, and `SERVERAVATAR_PARITY.md` (APP-015/APP-016 promoted
  from summary-table rows to full detail blocks, both `PARTIAL`).

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
