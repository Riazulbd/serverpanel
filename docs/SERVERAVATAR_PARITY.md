# ServerAvatar Feature Parity Matrix

Authoritative tracker for feature-level parity with the capabilities documented by
ServerAvatar's public product documentation. See `docs/SERVERAVATAR_DOC_INVENTORY.md`
for what has (and, honestly, mostly has not yet) been reviewed from that documentation
site directly.

**Important scope note**: this matrix's rows below are seeded from this project's own
`docs/SYSTEM.md` §2 feature table and `docs/product-plan.md`, which were built at
project inception against the *general shape* of ServerAvatar/Webuzo-style hosting-
panel functionality — not from a completed page-by-page crawl of
`https://serveravatar.com/docs/intro/`. Where a row's "Doc page" column says "pending
inventory", that means: this capability is a reasonable, well-known hosting-panel
feature this project has scoped against, but it has not yet been cross-checked against
the current live ServerAvatar documentation for that specific page's exact documented
behavior. Treat this file as the correct *tracking structure* with an honest,
partially-seeded first pass — not as proof a full documentation audit was completed.
`docs/SERVERAVATAR_DOC_INVENTORY.md` explains what a completed pass would still need
to do.

No ServerAvatar source code, proprietary API, UI layout, copy, or asset is used
anywhere in this project — every implementation below is independently designed; see
root `README.md` "Non-goals".

## Status legend

`NOT_STARTED` · `DISCOVERED` · `DESIGNING` · `IMPLEMENTING` · `PARTIAL` · `TESTING` ·
`BLOCKED_EXTERNAL` · `COMPLETE` · `INTENTIONALLY_NOT_APPLICABLE`

`COMPLETE` is only used where the capability is actually implemented **and** has
automated or (explicitly noted) manual test coverage — see `docs/TESTING.md`.

## 1. Core platform / account

| ID | Feature | Our implementation | Backend / API | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|
| CORE-01 | Central web dashboard | `apps/controlplane/web/index.html`, single embedded page | `apiServer.mountDashboard` | Manual (Playwright, prior session) | PARTIAL | No build step by design; mobile responsiveness not yet verified with browser automation |
| CORE-02 | Password auth (bcrypt) | `auth.go` | `POST /api/v1/auth/signup`/`login` | Automated | COMPLETE | bcrypt cost 12 |
| CORE-03 | Two-factor auth (TOTP) | `totp.go` (stdlib `crypto/*`, RFC 6238) | `POST /api/v1/auth/totp/enroll`/`verify`, `/mfa/challenge` | Automated | COMPLETE | No backup/recovery codes yet |
| CORE-04 | 2FA recovery/backup codes | — | — | — | NOT_STARTED | |
| CORE-05 | Session management / login history | Session cookie CRUD only | `sessions` table | Automated (lifecycle) | PARTIAL | No login-history UI, no device list |
| CORE-06 | IP allowlisting | — | — | — | NOT_STARTED | |
| CORE-07 | API token management | — | — | — | NOT_STARTED | Only session-cookie auth exists today |
| CORE-08 | Multi-user / organizations / teams / RBAC | Single-user model | `users` table | Automated (user CRUD) | NOT_STARTED | Explicitly Phase 3, see `product-plan.md` §9 |
| CORE-09 | Multiple-server management, groups/tags | `servers` table, `grp`/`tags_json` | `POST/GET /api/v1/servers*` | Automated | COMPLETE | |
| CORE-10 | Background job queue (durable) | Synchronous request/response today | `gateway.dispatch` | Automated (dispatch path) | PARTIAL | Not a durable queue; 120s (or per-endpoint longer) HTTP timeout bound — see `ARCHITECTURE.md` §1 |
| CORE-11 | Audit log | Append-only `audit_log` table | `GET /api/v1/audit` | Automated | COMPLETE | Every privileged action logged |
| CORE-12 | Notifications (email/Slack/Discord/Telegram/webhook) | — | — | — | NOT_STARTED | Phase 2, `product-plan.md` §9 |
| CORE-13 | Public API + OpenAPI spec | Internal API exists (`docs/API.md`) but undocumented as a public/versioned surface, no OpenAPI spec | — | Automated (route-level) | PARTIAL | |
| CORE-14 | Webhooks (outbound) | — | — | — | NOT_STARTED | |

## 2. Server management

| ID | Feature | Our implementation | Backend / API | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|
| SRV-01 | Agent install/registration | Bootstrap-token → mTLS cert exchange | `POST /agents/register` | Automated + manual | COMPLETE | |
| SRV-02 | Agent identity, cert rotation, revocation | Issuance + revocation done | `ca.go` | Automated | PARTIAL | No auto-renewal before 30-day expiry yet |
| SRV-03 | Server health monitoring (heartbeat) | uptime/load/mem%/disk% | `gateway` heartbeat handling | Automated | COMPLETE | No historical retention/downsampling yet — latest snapshot only |
| SRV-04 | Hosting-stack install (LEMP) | nginx/php8.3-fpm/mariadb/redis/git/composer/wp-cli/certbot/ufw/fail2ban | `stack.install` capability | Manual (real Ubuntu 24.04 host, prior session) | COMPLETE | Idempotent/retryable |
| SRV-05 | Apache / OpenLiteSpeed | — | — | — | NOT_STARTED | Phase 3 |
| SRV-06 | Multiple PHP-FPM versions | Only 8.3 installed; version-parameterized code paths exist | `site.set_php_version` | Automated (rejection path) | PARTIAL | |
| SRV-07 | Node.js runtime/app support | — | — | — | NOT_STARTED | Phase 3 |
| SRV-08 | SSH/SFTP management, key mgmt, port mgmt | — | — | — | NOT_STARTED | Phase 2 |
| SRV-09 | Firewall (UFW) / Fail2Ban management UI | Installed with safe defaults at stack-install time; no rule-editing capability | — | Manual | PARTIAL | |
| SRV-10 | Service start/stop/restart/status | Allow-listed units/actions only | `service.control` | Automated (allow-list boundary incl. injection attempt) | COMPLETE | |
| SRV-11 | Cron job management | — | — | — | NOT_STARTED | Phase 2 |
| SRV-12 | Process/worker (Supervisor/PM2) management | — | — | — | NOT_STARTED | Phase 2 |
| SRV-13 | Disk usage analysis / safe cleanup | — | — | — | NOT_STARTED | |
| SRV-14 | Diagnostics | Read-only service-state check | `diagnostics.basic` | Manual | PARTIAL | No plain-language suggested-repair layer |

## 3. Application management

| ID | Feature | Our implementation | Backend / API | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|
| APP-01 | Custom PHP / static site deploy | `site.create` w/ `app_type` | `POST /api/v1/servers/{id}/sites` | Automated (validation) + manual (real deploy) | COMPLETE | |
| APP-02 | WordPress one-click deploy | Real `wp-cli` install as site's own user | `app.wordpress_install` | Manual | COMPLETE | |
| APP-03 | Other PHP one-click installers (Joomla, PrestaShop, Nextcloud, etc.) | — | — | — | NOT_STARTED | |
| APP-04 | Node.js one-click installers | — | — | — | NOT_STARTED | Phase 3 |
| APP-05 | System-user/app isolation | Own system user, php-fpm pool, `open_basedir`, disabled dangerous PHP functions, own DB grants | `site.create` | Automated (isolation-relevant unit tests) + manual | COMPLETE | |
| APP-06 | Custom domains / aliases | Single primary domain + temp domain only | `site.create` | Manual | PARTIAL | No multi-domain/alias support yet |
| APP-07 | Temporary/test domains | `<user>.<ip>.sslip.io` auto-generated | `site.create` | Automated (`tempDomainFor`) | COMPLETE | |
| APP-08 | Site enable/disable | nginx symlink toggle | `site.set_status` | Manual | COMPLETE | |
| APP-09 | Maintenance mode (framework-aware) | — | — | — | NOT_STARTED | |
| APP-10 | Basic auth on a site | — | — | — | NOT_STARTED | |
| APP-11 | Secure file manager | List/read/write/delete, scoped + symlink-safe | `file.list/read/write/delete` | Automated (path-traversal/symlink-escape defenses) | COMPLETE | |
| APP-12 | In-browser code editor UI | Underlying `file.read`/`file.write` exist; no editor UI | — | — | PARTIAL | |
| APP-13 | Let's Encrypt + custom SSL | `ssl.issue_letsencrypt`, `ssl.install_custom` | — | Manual | COMPLETE | No auto-renewal wiring yet |
| APP-14 | WordPress auto-login | — | — | — | NOT_STARTED | Must use short-lived signed tokens, never store reusable plaintext admin passwords, if/when built |
| APP-15 | WordPress Toolkit (plugins/themes/updates/cron/search-replace/blueprints) | — | — | — | NOT_STARTED | |
| APP-16 | Staging environments | — | — | — | NOT_STARTED | Phase 2 |
| APP-17 | Site cloning | — | — | — | NOT_STARTED | Phase 2 |
| APP-18 | Cross-server migration | — | — | — | NOT_STARTED | Phase 2 |
| APP-19 | Git deployment (GitHub/GitLab/Bitbucket) | — | — | — | NOT_STARTED | Phase 2 |
| APP-20 | Application/traffic log analytics suite | `logs.tail` (redacted, bounded) only | `logs.tail` | Automated (redaction, input validation) | PARTIAL | No analytics (top IPs, bot ID, geo, etc.) |
| APP-21 | Application firewall / WAF | — | — | — | NOT_STARTED | |
| APP-22 | AI bot / scraper blocker | — | — | — | NOT_STARTED | |
| APP-23 | Cloudflare integration | — | — | — | NOT_STARTED | |

## 4. Database management

| ID | Feature | Our implementation | Backend / API | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|
| DB-01 | MySQL/MariaDB create/delete/list | Least-privilege grants (never global `GRANT ALL`) | `db.create/delete/list` | Manual (real MariaDB, prior session) | COMPLETE | |
| DB-02 | MongoDB support | — | — | — | NOT_STARTED | |
| DB-03 | Multiple DB users per DB, remote-access rules | Single owner user only, localhost-only | `db.create` | Manual | PARTIAL | |
| DB-04 | phpMyAdmin / DB admin UI | — | — | — | NOT_STARTED | |
| DB-05 | Database process/query monitoring | — | — | — | NOT_STARTED | |

## 5. Backup and restore

| ID | Feature | Our implementation | Backend / API | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|
| BKP-01 | On-demand db/files/full backup, checksummed | `backup.run`, persisted via control-plane API | `POST/GET /api/v1/servers/{id}/backups` | Automated (`files` scope end-to-end) + manual (`db`/`full`, prior session) | COMPLETE | Local storage only |
| BKP-02 | Restore (same server) | `backup.restore` — checksum-verified, pre-restore checkpoint, then db/files restore | `POST /api/v1/servers/{id}/backups/{backupId}/restore` | Automated (`files` scope end-to-end incl. checksum-mismatch/path-escape rejection) + manual (`db`/`full`, needs live MariaDB) | COMPLETE | File restore is create/overwrite, not delete-then-replace — see `SYSTEM.md` §19 |
| BKP-03 | Restore to a different server | — | — | — | NOT_STARTED | `backup_path` is validated against the *target* agent's own local archive directory |
| BKP-04 | Scheduled/recurring backups + retention policy | — | — | — | NOT_STARTED | |
| BKP-05 | Remote storage (S3-compatible: AWS/R2/B2/Spaces/Wasabi/GDrive/Dropbox) | Local disk only | — | — | NOT_STARTED | |
| BKP-06 | Scheduled backup-restorability verification job | Checksum verified at restore time, not on a recurring schedule | — | Automated (checksum check itself) | PARTIAL | |
| BKP-07 | Dashboard UI for backup/restore | Agent + control-plane API/persistence only | — | — | NOT_STARTED | |

## 6. Security and monitoring

| ID | Feature | Our implementation | Backend / API | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|
| SEC-01 | mTLS agent transport, cert-bound identity | `ca.go`, `gateway.go` | — | Automated + manual | COMPLETE | |
| SEC-02 | Capability allow-list (no shell-exec RPC) | `packages/capabilities` fixed `Registry` map | — | Automated (dispatch-rejection, injection-attempt tests) | COMPLETE | |
| SEC-03 | Cert revocation | `revoked_certs` table, checked every handshake | `POST /api/v1/servers/{id}/revoke` | Automated | COMPLETE | |
| SEC-04 | Commit-confirm SSH/firewall change flow | — | — | — | NOT_STARTED | |
| SEC-05 | Historical monitoring (CPU/RAM/disk/load/network/disk I/O graphs) | Latest heartbeat snapshot only, no history/retention | — | — | PARTIAL | |
| SEC-06 | Alert thresholds + cooldown | — | — | — | NOT_STARTED | |
| SEC-07 | External notification channels | — | — | — | NOT_STARTED | |

## 7. Team / commercial (Phase 3)

All rows below are `INTENTIONALLY_NOT_APPLICABLE` for the *current* phase of this
project, not abandoned — they are explicitly scoped to a later phase in
`product-plan.md` §9, and this project's operating principle (see `docs/SYSTEM.md`)
is to not fake commercial/billing functionality that isn't real. They will move to
`NOT_STARTED`/`DESIGNING` when Phase 3 work actually begins.

| ID | Feature | Status | Notes |
|---|---|---|---|
| COM-01 | Teams / granular roles / custom permissions | INTENTIONALLY_NOT_APPLICABLE (current phase) | Phase 3 |
| COM-02 | White-label branding / custom domain | INTENTIONALLY_NOT_APPLICABLE (current phase) | Phase 3 |
| COM-03 | Reseller admin panel / hosting packages | INTENTIONALLY_NOT_APPLICABLE (current phase) | Phase 3 |
| COM-04 | Billing: wallet/credits/plans/invoicing/payment providers | INTENTIONALLY_NOT_APPLICABLE (current phase) | Phase 3; must never be implemented with fake payment success states — real provider adapters (Stripe/PayPal) or nothing |
| COM-05 | Cloud-provider provisioning (DigitalOcean/Vultr/Lightsail/Linode/Hetzner) | INTENTIONALLY_NOT_APPLICABLE (current phase) | Phase 3; this project connects to already-provisioned VPS servers only today |
| COM-06 | Managed infrastructure (operator-provisioned, billed to customers) | INTENTIONALLY_NOT_APPLICABLE (current phase) | Depends on COM-04 + COM-05 |

## Change history

- **2026-08-17**: Initial version. Seeded from `docs/SYSTEM.md` §2 / `docs/product-
  plan.md`. Backup/restore rows (BKP-01, BKP-02) updated to COMPLETE following this
  session's `backup.restore` implementation. A full live crawl of ServerAvatar's
  documentation site has not yet been performed — see `docs/SERVERAVATAR_DOC_
  INVENTORY.md`.
