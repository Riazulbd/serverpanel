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

### APP-015 — Custom SSL upload
- **Category**: Application Management → SSL
- **Documentation page**: Application Management → SSL Management
- **Short description**: Install a customer-provided certificate/private-key pair for a site.
- **Expected behavior**: upload cert + key, validated and installed, site now serves HTTPS with it.
- **Our implementation**: `ssl.install_custom` validates the cert/key are a matching pair and that the certificate isn't already expired using Go's `crypto/tls`/`crypto/x509` (never shelling out to openssl, never logging key material) *before* writing anything to disk, then verifies the resulting nginx config with `nginx -t` before reloading — a mismatched, expired, or config-breaking certificate is never activated.
- **Frontend**: site-detail "SSL" panel — "Upload custom cert" modal (cert/key textareas).
- **Backend service**: `apiServer.handleInstallCustomSSL` (`apps/controlplane/ssl.go`).
- **API endpoint(s)**: `POST /api/v1/servers/{id}/sites/{siteId}/ssl/custom`.
- **Agent command**: `ssl.install_custom`.
- **DB tables**: `sites` (`ssl_status`, `ssl_expires_at` columns).
- **Required permission**: authenticated session.
- **Security considerations**: cert/key validated as a real matching pair server-side (not just "two non-empty fields"); private key material never appears in any log line, audit-log entry, or error message — only `domain`/`expires_at` are logged.
- **Test coverage**: `packages/capabilities/ssl_test.go` (`TestValidateCertKeyPairAcceptsMatchingPair`, `TestValidateCertKeyPairRejectsMismatchedKey`, `TestValidateCertKeyPairRejectsExpiredCert`, `TestHandleSSLInstallCustomRejectsMismatchedPairBeforeTouchingFilesystem`, using real in-memory-generated ECDSA certificates — no shelling out); `apps/controlplane/http_test.go` (`TestSSLEndpointsRequireARealSite`, `TestSSLEndpointsValidateBeforeDispatch`). The `nginx -t`/reload step itself is not exercised (requires a real nginx install — see `TESTING.md` §2).
- **Current status**: `COMPLETE`
- **Completion date**: 2026-08-25
- **Known differences**: none from the documented workflow.
- **Reason**: n/a — closed this session alongside APP-016 (auto-renewal), since both shared the same missing piece (a dedicated dashboard SSL panel/API layer on top of an already-existing agent capability).

### APP-016 — Let's Encrypt SSL + auto-renewal
- **Category**: Application Management → SSL
- **Documentation page**: Application Management → SSL Management
- **Short description**: One-click issuance of a Let's Encrypt certificate, kept renewed automatically.
- **Expected behavior**: issue a certificate for a site's domain; it renews itself before expiry without further action.
- **Our implementation**: `ssl.issue_letsencrypt` calls certbot's `--nginx` authenticator, then best-effort records the issued certificate's real expiry. Auto-renewal is handled at the OS level, not by a capability: `stack.install` now enables certbot's own `certbot.timer` (runs `certbot renew` twice daily, certbot's documented default) and installs a deploy hook (`/etc/letsencrypt/renewal-hooks/deploy/serverpanel-reload-nginx.sh`) that runs `nginx -t && systemctl reload nginx` after any certificate actually renews — closing the exact gap this row was tracking ("certbot's own renewal timer is not yet wired up by `stack.install`"). `ssl.check_renewal` (new capability) parses `certbot certificates -d <domain>` on demand so status/expiry can be refreshed without waiting for the next scheduled renewal.
- **Frontend**: site-detail "SSL" panel — status line, "Issue Let's Encrypt" modal (email field), "Check status" button.
- **Backend service**: `apiServer.handleIssueSSL`/`handleCheckSSLRenewal` (`apps/controlplane/ssl.go`).
- **API endpoint(s)**: `POST /api/v1/servers/{id}/sites/{siteId}/ssl/issue`, `POST /api/v1/servers/{id}/sites/{siteId}/ssl/check-renewal`.
- **Agent command**: `ssl.issue_letsencrypt`, `ssl.check_renewal`; `stack.install`'s two new idempotent steps (`certbot.timer` enable, deploy-hook install).
- **DB tables**: `sites` (`ssl_status`, `ssl_expires_at` columns, added via migration).
- **Required permission**: authenticated session.
- **Security considerations**: the domain dispatched is always the site's own recorded `domain`, never a caller-supplied one (same pattern as `handleCreateSite`); the deploy hook only ever runs `nginx -t && systemctl reload nginx`, a fixed two-command script with no caller-supplied input.
- **Test coverage**: `packages/capabilities/ssl_test.go` — `parseCertbotCertificates` parsing (single cert, multiple certs, an expired cert — including a regression test for a substring bug this suite caught: `"INVALID"` contains `"VALID"`), `annotateExpiry`'s domain matching, capability input-validation tests. `apps/controlplane/store_test.go` (`TestUpdateSiteSSLRoundTripsAndIsScoped`), `apps/controlplane/http_test.go` (SSL endpoint not-found/validation-before-dispatch tests). A desktop-viewport Playwright pass this session confirmed the SSL panel renders and all three actions correctly surface agent-side errors in the UI (see `TESTING.md` §3). Real certbot/ACME/`certbot.timer` behavior is not exercised — no certbot binary or public DNS in this environment (`BLOCKED_EXTERNAL`, same bucket as SRV-002/APP-002).
- **Current status**: `PARTIAL` (implementation, persistence, and dashboard UI complete and unit-tested; real-certbot/real-DNS end-to-end verification is `BLOCKED_EXTERNAL`)
- **Completion date**: n/a (see above); `BLOCKED_EXTERNAL` detail in §4.
- **Known differences**: no automated expiry-alerting job yet (checking is on-demand via "Check status", not a scheduled background check) — tracked as a monitoring/alerting gap, not an SSL gap.
- **Reason**: expiry alerting depends on the notification-channel infrastructure (`docs/SYSTEM.md` §10 "Notifications ⬜"), which is a separate, larger, not-yet-started piece of work.

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
| `COMPLETE` | 4 (SRV-001, BAK-002, ACC-001, APP-015) | 1 (PROV-006) |
| `PARTIAL` | 6 (SRV-002, APP-001, APP-002, DB-001, BAK-001, APP-016 — see note) | 4 |
| `NOT_STARTED` | 0 | ~55 |
| `BLOCKED_EXTERNAL` | 1 (sub-scoped within APP-016's real-certbot/DNS verification) | 0 |
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

- **APP-016** (Let's Encrypt SSL + auto-renewal): the real ACME issuance path
  (`ssl.issue_letsencrypt`) and the real `certbot.timer`/deploy-hook renewal path
  (`stack.install`'s two new steps) are both `BLOCKED_EXTERNAL` for end-to-end
  verification — Let's Encrypt's HTTP-01 challenge requires a domain that actually
  resolves to a real, publicly reachable server, and this environment has neither
  public DNS nor a `certbot` binary installed. **Already implemented and tested**:
  every input-validation path, the certbot plain-text-output parser
  (`parseCertbotCertificates`) against representative sample output, the full
  `ssl.install_custom` cert/key-validation logic (real `crypto/tls`/`crypto/x509`, no
  certbot dependency), the control-plane persistence/API/dashboard layers end-to-end
  (validated with real HTTP integration tests and a real-browser Playwright pass — see
  `TESTING.md` §1/§3), and `stack.install`'s new steps' idempotency *checks* (which
  only need `systemctl`/the filesystem, not a real certbot run, to unit-test their
  logic). **Exact test still required**: on a real Ubuntu 24.04 VPS with a domain
  pointed at it, run `stack.install`, confirm `systemctl is-enabled certbot.timer`
  reports `enabled` and the deploy hook file exists and is executable, issue a real
  certificate via the dashboard, confirm it's live in the browser, then either wait for
  or manually trigger (`certbot renew --force-renewal`) a real renewal and confirm
  nginx picked up the new certificate (e.g. via the certificate's serial number) without
  a manual reload.

No other feature is currently blocked *purely* on missing external credentials in a way
that would justify a top-level `BLOCKED_EXTERNAL` status (the sub-scoped MariaDB gap in
BAK-001/BAK-002 is an environment limitation of *this* session, not a missing
credential — a real Ubuntu host with MariaDB installed, per `INSTALLATION.md`, resolves
it without any external account). This section will be further populated as provider
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
- **2026-08-25**: closed APP-016 (Let's Encrypt SSL + auto-renewal)'s previously-flagged
  gap — `stack.install` now enables certbot's own `certbot.timer` and installs an
  nginx-reload deploy hook; added the `ssl.check_renewal` capability; gave both SSL
  capabilities a persisted (`sites.ssl_status`/`ssl_expires_at`) control-plane layer and
  a dedicated dashboard "SSL" panel for the first time (previously generic-task-dispatch
  only). Moved APP-015 (custom SSL upload) to `COMPLETE` alongside it, since it shared
  the same missing dashboard/API layer and gained real cert/key-pair validation
  (`crypto/tls`/`crypto/x509`) in the process. Real-certbot/real-DNS end-to-end
  verification remains `BLOCKED_EXTERNAL` (§4) — this environment has neither. A
  parser bug (`INVALID` containing `VALID` as a substring, misreporting every expired
  certificate as valid) was caught by the new tests before commit — see `TESTING.md`
  §4.
