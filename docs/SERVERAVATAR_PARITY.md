# ServerAvatar Feature Parity Matrix

Authoritative feature-parity tracker for this project against the functional
capabilities documented at
[serveravatar.com/docs/intro](https://serveravatar.com/docs/intro/) (inventoried in
`SERVERAVATAR_DOC_INVENTORY.md`).

## Ground rules

ServerAvatar's documentation is used here **only** as a functional specification — what
a capability does and the workflow it supports. Nothing below is, or was derived from,
ServerAvatar source code, proprietary API responses, UI layouts, copy, branding, logos,
icons, or screenshots. Every "Our implementation" cell describes this project's own,
independently designed architecture (Go control plane + Go agent, mTLS, SQLite,
allow-listed capabilities — see `SYSTEM.md`).

## Status legend

`NOT_STARTED` · `DISCOVERED` · `DESIGNING` · `IMPLEMENTING` · `PARTIAL` ·
`TESTING` · `BLOCKED_EXTERNAL` · `COMPLETE` · `INTENTIONALLY_NOT_APPLICABLE`

`COMPLETE` is used only where the capability is implemented **and** has automated test
coverage (see `TESTING.md`) — matching an item to SYSTEM.md's ✅ marker, not its 🚧.
Items marked 🚧 in `SYSTEM.md` are `PARTIAL` here.

## How to read this file

Fully implemented or partially implemented features get a full detail block (every
field the tracking process requires). Not-yet-started features are listed in compact
summary tables grouped by category, to keep this file's size proportional to what
actually exists — expand a row into a full block the moment work on it begins
(`DESIGNING`/`IMPLEMENTING`), per the workflow in §7.

---

## 1. Detailed entries — implemented or partially implemented capabilities

### SRV-001 — Server registration and agent enrollment
- **Category**: Server Management
- **Documentation page**: Server Management → "Installation (Direct Method)"
- **Short description**: Connect a VPS to the control plane via a one-time install command.
- **Expected behavior** (per ServerAvatar's documented workflow): operator creates a server record, gets an install command, runs it on a clean VPS, server appears connected.
- **Our implementation**: bootstrap-token → mTLS client-certificate exchange (`POST /agents/register`); agent connects outbound to the gateway, no inbound port required.
- **Frontend**: `web/index.html` "+ New server" modal, server list/detail views.
- **Backend service**: `apiServer.handleCreateServer`, `agentCA`, `gateway`.
- **API endpoint(s)**: `POST /api/v1/servers`, `POST /agents/register`.
- **Agent command**: n/a (registration precedes capability dispatch).
- **DB tables**: `servers`, `bootstrap_tokens`, `revoked_certs`.
- **Required permission**: authenticated session (single-user model today — see ORG-001).
- **Security considerations**: single-use/short-lived hashed bootstrap tokens; certificate identity independently derived from the mTLS handshake, never trusted from agent-asserted data; revocation checked every handshake.
- **Test coverage**: `apps/controlplane/http_test.go` (`TestServerCreateListRevokeFlow`, `TestRegisterEndpointRejectsBadToken`), `apps/controlplane/store_test.go`.
- **Current status**: `COMPLETE`
- **Completion date**: 2026-08-14
- **Known differences**: no agent certificate auto-renewal before 30-day expiry yet.
- **Reason**: scoped out of the initial secure-foundation pass; tracked in `SYSTEM.md` §21.

### SRV-002 — Hosting stack installation (LEMP)
- **Category**: Server Management
- **Documentation page**: Server Management (stack/software install)
- **Short description**: One-click install of nginx/PHP/database/supporting tools.
- **Expected behavior**: select a stack profile, it installs idempotently, retryably.
- **Our implementation**: `stack.install` capability — nginx, PHP 8.3-FPM, MariaDB, Redis, Git, Composer, WP-CLI, Certbot, UFW, Fail2Ban, all idempotent (checked via `dpkg-query` before each install step).
- **Frontend**: server-detail "Install Phase 1 stack" action button.
- **Backend service**: `gateway.dispatch` → `packages/capabilities.handleStackInstall`.
- **API endpoint(s)**: `POST /api/v1/servers/{id}/tasks` with `capability: stack.install`.
- **Agent command**: `stack.install`.
- **DB tables**: none directly (task result only; server's `heartbeat_json`/status reflect connectivity).
- **Required permission**: authenticated session.
- **Security considerations**: OS/version/resource preflight checks (defense in depth, re-checked agent-side even though `install.sh` checks too); allow-listed package set only.
- **Test coverage**: manually verified against a real Ubuntu 24.04 host in a prior session (see `TESTING.md` §2); not covered by `go test` (requires real apt/systemd).
- **Current status**: `PARTIAL`
- **Completion date**: n/a
- **Known differences**: only PHP 8.3 is actually installed by `stack.install` today, even though per-site PHP-version selection is already parameterized; Apache/OpenLiteSpeed stack adapters don't exist yet.
- **Reason**: Phase 1 deliberately ships one stack profile; additional stacks are Phase 3 (`product-plan.md` §9).

### APP-001 — Application (site) lifecycle: create, enable/disable
- **Category**: Application Management
- **Documentation page**: Application Management → "Deploy Custom PHP"
- **Short description**: Create an isolated web application (system user, docroot, vhost).
- **Our implementation**: `site.create` provisions an isolated Linux system user, php-fpm pool (`open_basedir`, disabled dangerous functions), nginx vhost, and a temporary `*.sslip.io` test domain; `site.set_status` enables/disables.
- **Frontend**: server-detail "+ New site" modal, sites table.
- **Backend service**: `apiServer.handleCreateSite` (dispatch-then-persist pattern).
- **API endpoint(s)**: `POST /api/v1/servers/{id}/sites`, `GET /api/v1/servers/{id}/sites`.
- **Agent command**: `site.create`, `site.set_status`, `site.set_php_version`.
- **DB tables**: `sites`.
- **Required permission**: authenticated session.
- **Security considerations**: per-application OS-level isolation is the core security property here (system user + php-fpm pool + `open_basedir` + scoped DB grants), not just a UI-level distinction.
- **Test coverage**: `apps/controlplane/store_test.go` (`TestCreateAndListSites`, `TestGetSiteIsScopedToServerID`); `site.create`'s deterministic path builders unit-tested in `packages/capabilities/site_test.go`.
- **Current status**: `PARTIAL`
- **Completion date**: n/a
- **Known differences**: no per-application environment variables, maintenance mode, or basic-auth protection yet; app types limited to WordPress/custom-PHP/static (no Laravel/Node.js/n8n/Mautic installers yet).
- **Reason**: those are explicitly Phase 2/3 items (`product-plan.md` §9).

### APP-002 — WordPress deployment
- **Category**: Application Management → WordPress
- **Documentation page**: Deploy Apps → WordPress
- **Short description**: One-click WordPress install with its own DB and admin account.
- **Our implementation**: `app.wordpress_install` — real `wp-cli core download`/`config create`/`core install`, run as the site's own isolated system user (`runuser`), idempotent (checks for existing `wp-config.php`/install state before each step).
- **Frontend**: site-creation app-type selector (`wordpress`).
- **Backend service**: `gateway.dispatch` → `packages/capabilities.handleWordPressInstall`.
- **API endpoint(s)**: `POST /api/v1/servers/{id}/tasks` (`capability: app.wordpress_install`) — not yet folded into the dedicated `handleCreateSite` flow the way `site.create` itself is.
- **Agent command**: `app.wordpress_install`.
- **DB tables**: none beyond `sites` (WordPress's own DB name/credentials are not currently persisted on the `sites` row — see Known differences).
- **Required permission**: authenticated session.
- **Security considerations**: runs entirely as the unprivileged site user, never root; admin password is caller-supplied, not agent-generated (see ACC-004/WP-AUTOLOGIN below for the auto-login gap this creates).
- **Test coverage**: manually verified in a prior session (real `wp-cli`, real DB tables) — see `TESTING.md` §2; not covered by `go test` (requires a running MariaDB).
- **Current status**: `PARTIAL`
- **Completion date**: n/a
- **Known differences**: no WordPress-specific toolkit yet (plugin/theme management, auto-login, blueprints, search-replace) — see the `INTENTIONALLY_NOT_APPLICABLE`/`NOT_STARTED` table under WordPress Toolkit.
- **Reason**: initial pass only covers install; toolkit is Phase 2/3 scope.

### DB-001 — Database create/delete/list with scoped users
- **Category**: Database Management
- **Documentation page**: Database Management → "Understanding Database Management"
- **Short description**: Create a MySQL/MariaDB database with a least-privilege owner user.
- **Our implementation**: `db.create`/`db.delete`/`db.list` — identifier allow-list regex, `CREATE USER`/`GRANT` scoped to exactly one database (never global), Unix-socket root auth (no stored MySQL root password on disk for this path).
- **Frontend**: not yet surfaced as its own dashboard panel (capability exists and is dispatchable via generic task dispatch; no dedicated "Databases" tab yet).
- **Backend service**: `gateway.dispatch` → `packages/capabilities.handleDBCreate/Delete/List`.
- **API endpoint(s)**: `POST /api/v1/servers/{id}/tasks`.
- **Agent command**: `db.create`, `db.delete`, `db.list`.
- **DB tables**: none on the control-plane side yet (no `databases` table — see Known differences).
- **Required permission**: authenticated session.
- **Security considerations**: identifier allow-list (`^[a-z][a-z0-9_]{0,30}$`) prevents SQL-identifier injection where placeholders can't be used; grants are always single-database-scoped.
- **Test coverage**: manually verified in a prior session against a real MariaDB; not covered by `go test` (requires a running MariaDB — this environment has none).
- **Current status**: `PARTIAL`
- **Completion date**: n/a
- **Known differences**: MongoDB support, a dedicated dashboard UI, and control-plane persistence of database records (so they show up per-site the way backups now do) don't exist yet.
- **Reason**: capability-layer work landed before the control-plane persistence/UI layer that backups just got (see BAK-001) — same pattern, not yet applied here. Good candidate for the next iteration.

### BAK-001 — On-demand backup (files/db/full)
- **Category**: Backups
- **Documentation page**: Backups → "Getting Started"
- **Short description**: Take a checksummed backup of an application's files and/or database.
- **Our implementation**: `backup.run` (agent) — tars the site's files and/or `mysqldump`s the database into a checksummed local `tar.gz`; control plane dispatches it per-site and persists a durable `backups` row only after the agent confirms success.
- **Frontend**: site-detail "Backups" panel — "Create backup" modal (scope selector, optional `db_name`), backups table.
- **Backend service**: `apiServer.handleCreateBackup` (`apps/controlplane/backups.go`).
- **API endpoint(s)**: `POST /api/v1/servers/{id}/sites/{siteId}/backups`, `GET /api/v1/servers/{id}/sites/{siteId}/backups`.
- **Agent command**: `backup.run`.
- **DB tables**: `backups` (`server_id`, `site_id`, `scope`, `path`, `db_name`, `size_bytes`, `sha256`, `status`, `created_at`).
- **Required permission**: authenticated session.
- **Security considerations**: backup archives are written only under a fixed system directory (`/var/backups/serverpanel`); SHA-256 is computed and recorded at creation time so a later restore can verify integrity before trusting the file.
- **Test coverage**: `packages/capabilities/backup_test.go` (`TestHandleBackupRunRejectsBadScope`, `TestHandleBackupRunFilesRoundTripsAndChecksums`); `apps/controlplane/store_test.go` (`TestBackupCreateListGetRoundTrip`); `apps/controlplane/http_test.go` (`TestCreateBackupRejectsInvalidScope`, `TestBackupEndpointsRequireARealSite`). Files scope tested against a real filesystem; db/full scope (real `mysqldump`) not exercised by `go test` in this environment (no MariaDB here) — manually verified in a prior session.
- **Current status**: `COMPLETE` (files scope, fully automated); `PARTIAL` overall (db/full scope automated-tested only at the validation layer, not a real `mysqldump` round trip in this environment)
- **Completion date**: 2026-08-17 (files scope); db/full scope's real-MariaDB verification remains `BLOCKED_EXTERNAL` in this environment.
- **Known differences**: no scheduling/retention policy (on-demand only); no remote storage adapters (S3/R2/B2/Spaces/Wasabi — local disk only); backups are not encrypted at rest (rely on host filesystem permissions).
- **Reason**: scheduling/retention/remote-storage/encryption are explicitly Phase 2 (`product-plan.md` §9); this pass's scope was closing the restore gap first (see BAK-002), which was the higher-priority documented blocker.

### BAK-002 — Backup restore
- **Category**: Backups
- **Documentation page**: Backups (restore workflow)
- **Short description**: Restore an application's files and/or database from a prior backup.
- **Our implementation**: `backup.restore` (agent) — validates the archive is one this agent's own `backup.run` created (path confined to the backup directory, optional checksum re-verification), extracts safely via Go's `archive/tar` (rejecting path-traversal/absolute-path/non-regular entries — never a shelled-out `tar`), takes a pre-restore checkpoint of the *current* live state before touching anything, then restores the database (streamed `mysql` import) and/or files (atomic-as-possible directory swap, ownership restored to the site's own system user).
- **Frontend**: site-detail "Backups" panel — "Restore" button per backup row, with a destructive-action confirmation dialog.
- **Backend service**: `apiServer.handleRestoreBackup` (`apps/controlplane/backups.go`).
- **API endpoint(s)**: `POST /api/v1/servers/{id}/backups/{backupId}/restore`.
- **Agent command**: `backup.restore`.
- **DB tables**: reads `backups` (no new table — a restore doesn't itself create a `backups` row, though the pre-restore checkpoint it takes does).
- **Required permission**: authenticated session; restore parameters (`archive_path`, `scope`, `db_name`, `expected_sha256`) are read server-side from the stored `backups` row, never accepted as free-form client input, so a caller can only ever restore a backup that was actually created and recorded.
- **Security considerations**: this is the highest-blast-radius capability in the registry (it can overwrite a live database and an entire site's files), so it gets defense in depth beyond the file-manager pattern: archive-location confinement, checksum verification, a from-scratch safe tar extractor (not the `tar` binary), a mandatory pre-restore checkpoint that can't be skipped, and streamed (not argv-passed) SQL import.
- **Test coverage**: `packages/capabilities/backup_test.go` — 7 tests covering archive-location rejection, path-traversal-in-archive-path rejection, checksum-mismatch rejection, a full files backup→corrupt→restore round trip against a real throwaway system user (verifying both restored content and checkpoint creation), and three `extractTarGzSafely` unit tests (path traversal, absolute path, size-limit enforcement). `apps/controlplane` HTTP/store tests cover the endpoint's not-found/validation boundaries. Real `mysql`-import round trip not exercised in this environment (no MariaDB) — `BLOCKED_EXTERNAL`.
- **Current status**: `COMPLETE` (files scope; db/full scope's SQL-import step is `BLOCKED_EXTERNAL` for real-MariaDB verification, same as BAK-001)
- **Completion date**: 2026-08-17
- **Known differences**: same-server restore only — there is no capability to restore a backup onto a *different* server (that needs a transfer step first).
- **Reason**: cross-server restore is coupled to cross-server migration/cloning, both explicitly Phase 2 (`product-plan.md` §9); tracked as a follow-up, not silently dropped.

### APP-016 — Let's Encrypt SSL, issuance + status
- **Category**: Application Management → SSL
- **Documentation page**: SSL Certificates → "Free SSL (Let's Encrypt)"
- **Short description**: Issue a Let's Encrypt certificate for a site's domain and know what's currently installed and when it expires.
- **Our implementation**: `ssl.issue_letsencrypt` (agent) runs certbot's `--nginx` plugin against the domain (fixed argv, no shell); certbot's own nginx plugin edits the site's vhost in place to add the HTTPS listener and redirect, and remembers the nginx installer for its own future renewals. A new `ssl.status` capability reads back whatever certificate is actually on disk (`/etc/letsencrypt/live/<domain>/fullchain.pem`, parsed with `crypto/x509` — not trusted from certbot's stdout) and reports source/expiry/issuer; every issuance now calls this immediately afterward so what's recorded is what's actually installed, not what was requested.
- **Frontend**: site-detail "SSL certificate" panel — status line (installed/none, expiry countdown, a `warn`-styled countdown under 14 days), "Issue Let's Encrypt certificate" and "Check status" actions.
- **Backend service**: `apiServer.handleIssueLetsEncryptSSL`, `apiServer.handleRefreshSSLStatus`, `apiServer.dispatchSSLStatus`/`persistSSLStatus` (`apps/controlplane/ssl.go`).
- **API endpoint(s)**: `POST /api/v1/servers/{id}/sites/{siteId}/ssl/letsencrypt`, `POST /api/v1/servers/{id}/sites/{siteId}/ssl/status`.
- **Agent command**: `ssl.issue_letsencrypt`, `ssl.status`.
- **DB tables**: `sites.ssl_status`, `sites.ssl_expires_at`, `sites.ssl_checked_at` (added via `runMigrations`/`addColumnIfMissing`, so an existing database file picks the columns up on next start).
- **Required permission**: authenticated session.
- **Security considerations**: domain is validated against the same allow-list regex `site.create` uses before it ever reaches certbot's argv; certificate status is always re-derived from the agent's filesystem, never trusted as a cached value, so a certbot renewal or manual `certbot delete` that happens outside this control plane is reflected the next time status is checked rather than silently going stale.
- **Test coverage**: `packages/capabilities/ssl_test.go` (`TestHandleSSLIssueLetsEncryptRejectsInvalidDomain`, `TestHandleSSLIssueLetsEncryptRequiresEmail`, `TestHandleSSLStatusRejectsInvalidDomain`, `TestReadCertStatusReportsNoneWhenNothingIsInstalled`); `apps/controlplane/http_test.go` (`TestSSLEndpointsRequireARealSite`, `TestSSLEndpointsValidateBeforeDispatch`); `apps/controlplane/store_test.go` (`TestSetSiteSSLPersistsAndIsScopedToServerID`). The full certbot ACME round trip (a real Let's Encrypt issuance against a publicly resolvable domain) is not exercised by `go test` — `BLOCKED_EXTERNAL` (needs a real domain + DNS + outbound port 80/443).
- **Current status**: `PARTIAL`
- **Completion date**: 2026-08-18 (dashboard wiring, status tracking, and tests); real ACME issuance remains `BLOCKED_EXTERNAL`.
- **Known differences**: certbot's own systemd renewal timer (installed by the `certbot` apt package `stack.install` already pulls in) is relied on for actual auto-renewal rather than a control-plane-driven renewal job; the control plane doesn't yet proactively alert on upcoming expiry (the dashboard only shows a warning when the page is open) and there's no multi-domain/SAN certificate support (`site.create` is single-domain today, tracked under APP-003).
- **Reason**: a control-plane-scheduled renewal/alerting job needs the durable background job queue called out as a Phase 1 architecture gap (`SYSTEM.md` §2 "Background job queue") — building it just for SSL renewal ahead of that would be a one-off workaround rather than the real fix; certbot's own timer is a safe interim default since it already reloads nginx on renewal for `--nginx`-issued certs.

### APP-015 — Custom SSL upload
- **Category**: Application Management → SSL
- **Documentation page**: SSL Certificates → "Custom SSL"
- **Short description**: Install a customer-provided certificate/key pair for a site.
- **Our implementation**: `ssl.install_custom` (agent) now actually activates the certificate, not just writes it to disk: the certificate and key are verified to match (`crypto/tls.X509KeyPair`) and to cover the requested domain (`x509.Certificate.VerifyHostname`) *before* anything is written, an already-expired certificate is rejected outright, and — the real gap this pass closed — the cert/key paths are wired into the site's existing nginx vhost (`injectHTTPSListen`, a pure text transform covering both first-install and idempotent re-install/renewal cases) with `nginx -t` verified before reload and an automatic revert to the last-known-good vhost if the test fails.
- **Frontend**: site-detail "SSL certificate" panel — "Install custom certificate" modal (cert/key textareas).
- **Backend service**: `apiServer.handleInstallCustomSSL` (`apps/controlplane/ssl.go`).
- **API endpoint(s)**: `POST /api/v1/servers/{id}/sites/{siteId}/ssl/custom`.
- **Agent command**: `ssl.install_custom`.
- **DB tables**: `sites.ssl_status`/`ssl_expires_at`/`ssl_checked_at` (shared with APP-016).
- **Required permission**: authenticated session.
- **Security considerations**: certificate/key mismatch and hostname-coverage checks happen before any file write, closing what was previously a silent-failure gap (a mismatched or non-matching cert could be "installed" with no functional HTTPS and no error); the private key is written `0600`, is only ever transmitted over the already-authenticated session-cookie API + mTLS agent channel, and is never written to the audit log.
- **Test coverage**: `packages/capabilities/ssl_test.go` (`TestHandleSSLInstallCustomRejectsInvalidDomain`, `TestHandleSSLInstallCustomRejectsMismatchedKey`, `TestHandleSSLInstallCustomRejectsWrongHostname`, `TestHandleSSLInstallCustomRejectsExpiredCert`, `TestInjectHTTPSListenAddsListenAndCertDirectives`, `TestInjectHTTPSListenIsIdempotentAndUpdatesInPlace`, `TestInjectHTTPSListenLeavesUnrecognizedVhostsAlone`); `apps/controlplane/http_test.go` (`TestSSLEndpointsValidateBeforeDispatch`). The nginx-reload/`nginx -t` path itself needs a real nginx install to exercise — `BLOCKED_EXTERNAL` in this environment; the vhost-text-transform it depends on is fully unit-tested without one.
- **Current status**: `PARTIAL`
- **Completion date**: 2026-08-18
- **Known differences**: no "force HTTPS" redirect is added for a custom-cert install (Let's Encrypt issuance gets one via certbot's `--redirect`; custom install deliberately leaves the existing plain-HTTP behavior alone rather than assuming every caller wants a redirect); no SSL "uninstall" capability yet (a mistaken/expiring custom cert can be replaced by installing a new one, but not cleanly removed back to HTTP-only).
- **Reason**: force-HTTPS-as-a-toggle and SSL uninstall are both small, well-scoped follow-ups tracked for the next SSL-focused iteration, not scoped into this pass so the higher-priority "SSL exists but does nothing" correctness gap could close first.

### ACC-001 — Authentication, 2FA, session management
- **Category**: Account Management
- **Documentation page**: Account Management → "Update Account Info"
- **Short description**: Email/password login with optional TOTP two-factor.
- **Our implementation**: bcrypt (cost 12) password hashing; RFC 6238 TOTP via stdlib `crypto/*` only (no third-party auth library); `HttpOnly`/`SameSite=Strict` session cookies, 12-hour TTL.
- **Frontend**: login/signup/MFA panes, Security tab (2FA enrollment).
- **Backend service**: `auth.go`, `totp.go`.
- **API endpoint(s)**: `/api/v1/auth/*`.
- **Agent command**: n/a.
- **DB tables**: `users`, `sessions`.
- **Required permission**: n/a (this *is* the permission layer).
- **Security considerations**: passwords never stored plaintext; TOTP secret only persisted after a successful confirming code; session tokens stored only as SHA-256 hashes.
- **Test coverage**: `apps/controlplane/totp_test.go`, `apps/controlplane/http_test.go` (`TestSignupLoginProtectedRouteFlow`, `TestTOTPEnrollmentGatesSession`).
- **Current status**: `COMPLETE`
- **Completion date**: 2026-08-14
- **Known differences**: no backup/recovery codes for 2FA, no login-history UI, no IP allowlisting, no API token management yet.
- **Reason**: those are listed Phase 2 account-security items (`product-plan.md` §9) not yet built.

---

## 2. Summary tables — not yet started

Every row below is `NOT_STARTED` unless otherwise noted. Full detail blocks will be
added the moment a row moves to `DESIGNING`/`IMPLEMENTING`, per §"How to read this
file" above. This section exists so the matrix reflects the *entire* documented
capability surface (per task-brief §3/§101), not just what's already built.

### Organization (ORG-*)
| ID | Feature | Doc page | Status | Notes |
|---|---|---|---|---|
| ORG-001 | Multi-user / multi-organization model | Organization → Introduction | `NOT_STARTED` | Currently single-user; no org boundary exists at all |
| ORG-002 | Teams, invitations, roles/permissions | Organization | `NOT_STARTED` | Depends on ORG-001 |
| ORG-003 | Resource sharing (server/app/DB-level) | Organization | `NOT_STARTED` | Depends on ORG-001/002 |
| ORG-004 | Organization activity log | Organization | `NOT_STARTED` | The append-only `audit_log` table already exists and is org-agnostic-ready (server/actor/action/detail); scoping it per-org is additive once ORG-001 lands |

### Integrations (INT-*)
| ID | Feature | Doc page | Status | Notes |
|---|---|---|---|---|
| INT-001 | Git providers (GitHub/GitLab/Bitbucket) | Integrations | `NOT_STARTED` | No `git.deploy` capability yet (deliberately absent from the allow-list — `SYSTEM.md` §12) |
| INT-002 | Cloudflare | Integrations | `NOT_STARTED` | |
| INT-003 | Cloud storage (S3-compatible) | Integrations / Backups | `NOT_STARTED` | Needed for BAK-001's remote-storage gap too |
| INT-004 | Notification channels (Slack/Discord/Telegram/webhook) | Integrations | `NOT_STARTED` | |

### Cloud provider adapters (PROV-*)
| ID | Provider | Status |
|---|---|---|
| PROV-001 | DigitalOcean | `NOT_STARTED` |
| PROV-002 | Vultr | `NOT_STARTED` |
| PROV-003 | Linode | `NOT_STARTED` |
| PROV-004 | AWS Lightsail | `NOT_STARTED` |
| PROV-005 | Hetzner | `NOT_STARTED` |
| PROV-006 | Custom VPS / manually connected dedicated server | `COMPLETE` | The bootstrap-token install flow (SRV-001) *is* this — a customer VPS regardless of where it's hosted connects the same way. |

### Billing (BILL-*)
| ID | Feature | Status | Notes |
|---|---|---|---|
| BILL-001 | Wallet / credit ledger | `NOT_STARTED` | Deliberately Phase 3 (`product-plan.md` §9) |
| BILL-002 | Plans / entitlements | `NOT_STARTED` | |
| BILL-003 | Payment provider adapters (Stripe/PayPal) | `NOT_STARTED` | |
| BILL-004 | Invoicing / tax configuration | `NOT_STARTED` | |

### Server management — not yet started (SRV-*)
| ID | Feature | Status | Notes |
|---|---|---|---|
| SRV-003 | SSH/SFTP management, key management, port/root-login controls | `NOT_STARTED` | `product-plan.md` Phase 2 |
| SRV-004 | Firewall (UFW) rule editing UI, Fail2Ban jail management | `PARTIAL` | Installed with safe defaults by `stack.install`; no rule-editing capability/UI yet |
| SRV-005 | Cron job management | `NOT_STARTED` | |
| SRV-006 | Supervisor/PM2 worker management | `NOT_STARTED` | |
| SRV-007 | Process list / kill | `NOT_STARTED` | |
| SRV-008 | Historical monitoring (CPU/RAM/disk/network graphs, alerts) | `PARTIAL` | Heartbeat carries current uptime/load/mem%/disk%; no history retention or alerting yet |
| SRV-009 | Disk cleaner | `NOT_STARTED` | |
| SRV-010 | Apache / OpenLiteSpeed stack adapters | `NOT_STARTED` | nginx-only today |
| SRV-011 | Node.js runtime support | `NOT_STARTED` | |

### Application management — not yet started (APP-*)
| ID | Feature | Status | Notes |
|---|---|---|---|
| APP-003 | Additional domains / domain management UI | `NOT_STARTED` | `site.create` takes one domain today |
| APP-004 | Maintenance mode | `NOT_STARTED` | |
| APP-005 | Basic auth (site password protection) | `NOT_STARTED` | |
| APP-006 | Per-app environment variables | `NOT_STARTED` | |
| APP-007 | Git-based deployment | `NOT_STARTED` | Depends on INT-001 |
| APP-008 | Staging environments | `NOT_STARTED` | |
| APP-009 | Site cloning | `NOT_STARTED` | |
| APP-010 | Cross-server migration | `NOT_STARTED` | |
| APP-011 | In-browser code editor | `PARTIAL` | `file.read`/`file.write` capabilities exist; no dedicated editor UI |
| APP-012 | Additional one-click installers (Laravel, Joomla, Mautic, Moodle, PrestaShop, Akaunting, Nextcloud, Statamic, Craft CMS, n8n, Node-RED, Uptime Kuma, NodeBB) | `NOT_STARTED` | WordPress is the only one-click installer today |
| APP-013 | Log Monitoring Suite (traffic analytics) | `NOT_STARTED` | |
| APP-014 | Application-level WAF / AI-bot blocker | `NOT_STARTED` | |

### Database management — not yet started (DB-*)
| ID | Feature | Status | Notes |
|---|---|---|---|
| DB-002 | MongoDB support | `NOT_STARTED` | |
| DB-003 | phpMyAdmin / DB admin UI integration | `NOT_STARTED` | |
| DB-004 | Database process/query monitoring | `NOT_STARTED` | |
| DB-005 | Control-plane persistence + dashboard UI for databases (mirroring what BAK-001 just got) | `NOT_STARTED` | See DB-001's "Known differences" |

### WordPress Toolkit (WP-*)
| ID | Feature | Status |
|---|---|---|
| WP-001 | Plugin/theme management | `NOT_STARTED` |
| WP-002 | Core/plugin/theme updates | `NOT_STARTED` |
| WP-003 | Auto-login | `NOT_STARTED` |
| WP-004 | Blueprints | `NOT_STARTED` |
| WP-005 | Search & replace | `NOT_STARTED` |
| WP-006 | Object cache (Redis) | `NOT_STARTED` |
| WP-007 | WP-Cron management | `NOT_STARTED` |
| WP-008 | Security hardening controls | `NOT_STARTED` |

### White-label / Reseller (WL-*, RS-*)
| ID | Feature | Status |
|---|---|---|
| WL-001 | Branding (name/logo/colors/custom domain) | `NOT_STARTED` |
| WL-002 | Custom landing/disabled-app pages | `NOT_STARTED` |
| RS-001 | Admin panel (customers, plans, revenue) | `NOT_STARTED` |
| RS-002 | Customer-facing scoped control panel | `NOT_STARTED` |
| RS-003 | Hosting packages / entitlement enforcement | `NOT_STARTED` |

### Human-delivered / not-a-software-feature (per task-brief §74)
| ID | Item | Status | Notes |
|---|---|---|---|
| HUMAN-001 | Premium/managed human support | `INTENTIONALLY_NOT_APPLICABLE` | Not a software capability; if this project ever offers paid support, only its software-supporting scaffolding (ticketing, SLA metadata) would be tracked here, never a claim of 24/7 human availability |

---

## 3. Progress summary

| Status | Count (detailed entries) | Count (summary-table rows) |
|---|---|---|
| `COMPLETE` | 3 (SRV-001, BAK-002, ACC-001) | 1 (PROV-006) |
| `PARTIAL` | 7 (SRV-002, APP-001, APP-002, APP-015, APP-016, DB-001, BAK-001 — see note) | 4 |
| `NOT_STARTED` | 0 | ~53 |
| `BLOCKED_EXTERNAL` | 0 (sub-scoped within BAK-001/BAK-002's db/full-scope MariaDB verification) | 0 |
| `INTENTIONALLY_NOT_APPLICABLE` | 0 | 1 |

*Note: BAK-001 and BAK-002 are each simultaneously `COMPLETE` for their files-scope path
and effectively `PARTIAL`/`BLOCKED_EXTERNAL` for their db/full-scope path pending a real
MariaDB environment to verify against — see their detail blocks above rather than a
single flattened status.*

This is an honest, small-fraction-covered snapshot, not a claim of broad parity. The
overwhelming majority of ServerAvatar's documented capability surface remains
`NOT_STARTED` in this project today — see `SYSTEM.md` §2-3 for the phase-by-phase plan
and `product-plan.md` for the estimates behind it.

## 4. BLOCKED_EXTERNAL detail

No feature is currently blocked *purely* on missing external credentials in a way that
would justify a top-level `BLOCKED_EXTERNAL` status (the sub-scoped MariaDB gap in
BAK-001/BAK-002 is an environment limitation of *this* session, not a missing
credential — a real Ubuntu host with MariaDB installed, per `INSTALLATION.md`, resolves
it without any external account). This section will be populated as provider
integrations (Cloudflare, cloud storage, cloud compute, payment processors) are
implemented and reach the point where only real credentials stand between "implemented"
and "verified end-to-end."

## 5. INTENTIONALLY_NOT_APPLICABLE detail

- **HUMAN-001** (premium human support): see the summary table above. Reason: this project
  builds software, not a support organization; claiming otherwise would violate
  task-brief §74/§96 ("never use fake success states" / "never claim 24/7 human support
  exists when it does not").

## 6. Continuous parity verification process

Per the task brief's completion standard: before this project can be called "done,"
the doc inventory must be rebuilt (recursive crawl, not just the top-level pass in
`SERVERAVATAR_DOC_INVENTORY.md`) and every discovered capability re-diffed against this
file. That has **not** happened yet — this is the first pass, covering enough ground to
establish the tracking process and close the single highest-priority gap
(BAK-002/backup restore) that the pre-existing `SYSTEM.md` had already flagged.

## 7. Workflow for future sessions

1. Refresh `SERVERAVATAR_DOC_INVENTORY.md` (recursive crawl this time).
2. Diff against this file's Feature IDs; add any newly discovered capability as a new
   summary-table row (`DISCOVERED`).
3. Pick the highest-priority `NOT_STARTED`/`PARTIAL` row per the task brief's
   prioritization order (security-critical → architecture blockers → agent correctness
   → data integrity → core provisioning → application lifecycle → databases → SSL →
   backups/restores → monitoring → ...).
4. Move it through `DESIGNING` → `IMPLEMENTING` → `TESTING` → `COMPLETE`, expanding it
   into a full detail block in §1 as soon as design starts.
5. Update `CHANGELOG.md` and this file's §3 summary counts in the same commit as the
   implementation.

## Change history

- **2026-08-17**: initial version. Established the tracking process; recorded
  SRV-001/002, APP-001/002, DB-001, ACC-001 (pre-existing work) at accurate status, and
  BAK-001/BAK-002 reflecting this session's backup-restore implementation. ~60
  capabilities enumerated overall (detailed + summary), the large majority honestly
  `NOT_STARTED`.
- **2026-08-18**: promoted APP-015/APP-016 (SSL) from summary-table `PARTIAL` rows to full
  detail blocks. This closed a real correctness gap, not just a documentation one: SSL
  capabilities existed agent-side but had no control-plane API/UI at all (unreachable
  outside a raw generic-task-dispatch call), and `ssl.install_custom` wrote the
  certificate/key to disk without ever wiring them into nginx — so a "successful" custom
  install left the site still serving plain HTTP. Both are now fixed: dedicated
  `POST .../ssl/{letsencrypt,custom,status}` endpoints, a dashboard SSL panel, cert/key
  match + hostname + expiry validation before any file write, an `ssl.status` capability
  that reads the agent's actual filesystem state rather than trusting a handler's own
  report, and `sites.ssl_status`/`ssl_expires_at`/`ssl_checked_at` persistence via a new
  migration. 14 new tests added (`packages/capabilities/ssl_test.go`,
  `apps/controlplane/http_test.go`, `apps/controlplane/store_test.go`).
