# Changelog

All notable changes to this project are recorded here, newest first. Dates are UTC.

## 2026-08-25 — SSL status, custom SSL dashboard UI, automatic Let's Encrypt renewal

- **Closed the top gap `SYSTEM.md` had flagged since the last entry**: SSL certificates
  could be issued (`ssl.issue_letsencrypt`) or custom-installed (`ssl.install_custom`)
  agent-side, but neither had any dashboard wiring, there was no way to see a
  certificate's expiry, and nothing renewed a Let's Encrypt certificate before it
  expired.
- Added two agent capabilities (`packages/capabilities/ssl.go`): `ssl.status`
  (read-only — locates whichever known certificate path exists for a domain and reads
  its real expiry via `openssl x509 -enddate`, never a caller-claimed value) and
  `ssl.renew` (`certbot renew --cert-name <domain>`, itself renewal-window-aware, so the
  control plane never has to duplicate certbot's own due-date decision). Refactored
  `ssl.issue_letsencrypt`/`ssl.install_custom` to return the same structured
  `{status, issuer, expires_at, days_remaining}` JSON on success, via a shared
  `certExpiry` helper — one round trip to learn a certificate's real state, not two.
- Added a `sites.ssl_issuer`/`ssl_expires_at`/`ssl_checked_at` migration and three new
  control-plane endpoints (`POST /api/v1/servers/{id}/sites/{siteId}/ssl/{issue,custom,refresh}`),
  following the same dispatch-then-persist-on-success pattern as backups/sites — a raw
  agent success never gets recorded without also updating the site's stored SSL state.
- Added a control-plane-side renewal scheduler (`apps/controlplane/ssl_renewal.go`,
  `-ssl-renew-interval` flag, default `12h`): a plain `time.Ticker` goroutine that
  sweeps every site with a recorded `letsencrypt` issuer and dispatches `ssl.renew`
  unconditionally, relying on certbot's own renewal-window logic rather than
  reimplementing it. A disconnected server is skipped for that tick (logged, not
  treated as a failure or persisted to the audit log) and retried on the next one; a
  failed dispatch never overwrites a site's last-known-good SSL state.
- Added the dashboard's first SSL UI: a per-site "SSL certificate" panel showing
  issuer/expiry/days-remaining, "Issue Let's Encrypt cert", "Upload custom cert", and
  "Refresh status" actions.
- Added 17 new tests (61 → 78 total, `go vet`/`gofmt` clean): `certExpiry` against real
  openssl-generated self-signed certificates under both the Let's Encrypt and custom
  on-disk layouts (including "no certificate" and "both exist, Let's Encrypt wins"),
  every `ssl.*` handler's input validation and its clean-failure behavior when
  certbot/nginx aren't installed (both real conditions in this environment, not
  mocked), `updateSiteSSL`'s round trip and cross-server-scoping rejection,
  `listSitesWithIssuer`'s cross-server aggregation, the renewal scheduler's two safety
  properties (a disconnected server is a no-op, a `custom`-issuer site is never
  touched), and HTTP boundary tests for all three new endpoints.
- Updated `SYSTEM.md`, `API.md`, `OPERATIONS.md`, `TESTING.md`, and
  `SERVERAVATAR_PARITY.md` (promoted APP-015/APP-016 from `PARTIAL` summary rows to
  full `COMPLETE` detailed entries — the real certbot/nginx network-dependent success
  paths are marked `BLOCKED_EXTERNAL`, not claimed as verified).
- Manually smoke-tested end-to-end against a locally built binary (signup → login →
  server/site creation → all three SSL endpoints' validation and no-agent-connected
  error paths → confirmed the new `ssl_issuer`/`ssl_expires_at`/`ssl_checked_at` fields
  round-trip through the sites list API and render in the dashboard's embedded JS).
  Real certbot/nginx network calls remain `BLOCKED_EXTERNAL` in this environment — see
  `SERVERAVATAR_PARITY.md` §4.

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
