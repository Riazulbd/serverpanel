# SYSTEM.md — ServerPanel System Reference

This is the single document meant to let any future developer or AI pick up this
project cold: what it is, what exists today, what's proven vs. assumed, and what to do
next. Other docs go deeper on specific topics; this one is the map.

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component design, transport, repo layout
- [`SECURITY.md`](SECURITY.md) — trust model, registration/revocation, what's
  implemented vs. still Phase 2
- [`API.md`](API.md) — every HTTP endpoint and the agent wire protocol
- [`TESTING.md`](TESTING.md) — test strategy, how to run tests, coverage, what's
  manually vs. automatically verified
- [`OPERATIONS.md`](OPERATIONS.md) — running it, backups, monitoring, upgrade/rollback,
  troubleshooting
- [`INSTALLATION.md`](INSTALLATION.md) — local dev setup and clean-Ubuntu install
- [`product-plan.md`](product-plan.md) — the original pre-implementation product/
  business plan (phase estimates, cost, postponed features, open product-owner
  questions) — still the source of truth for what's intentionally *not* built yet
- [`../CHANGELOG.md`](../CHANGELOG.md) — dated log of what changed and why

## 1. Product purpose

ServerPanel is a centralized, multi-server hosting control plane for Ubuntu VPS
fleets, combining the depth of Webuzo's per-server hosting controls with the
centralized, agent-based, multi-server model of ServerAvatar. It targets agencies and
non-technical users who manage several unmanaged/self-hosted Ubuntu VPS instances and
want one dashboard, one login, and one audit trail across all of them — without giving
up the ability to inspect or SSH into the underlying servers directly.

It is explicitly **not** a per-server local panel (that's the Webuzo model): there is
one control plane (this codebase's `apps/controlplane`) that many customer VPS servers
connect *out* to via a lightweight agent (`apps/agent`). No proprietary ServerAvatar or
Webuzo code, branding, copy, or design assets are used anywhere in this project — see
the root [`README.md`](../README.md) "Non-goals" section.

## 2. Complete feature list and current implementation status

Legend: ✅ implemented and tested (see `TESTING.md`) · 🚧 partially implemented ·
⬜ not started (planned, see `product-plan.md` for phase).

### Core platform
| Feature | Status |
|---|---|
| Central web dashboard | ✅ single embedded HTML/CSS/JS page, no build step |
| Secure authentication (bcrypt, cost 12) | ✅ |
| Two-factor authentication (TOTP, RFC 6238) | ✅ |
| User/organization management | 🚧 single-user model only; no orgs/teams yet |
| Multiple-server management | ✅ create/list/get/revoke, search/filter in UI |
| Secure agent install/registration | ✅ bootstrap token → mTLS cert exchange |
| Agent identity, cert rotation, revocation | 🚧 issuance + revocation done; no
  auto-renewal before expiry yet (see `SECURITY.md` §2) |
| Server health monitoring | ✅ heartbeat: uptime, load, mem%, disk% |
| Server groups/tags/metadata | ✅ `group`, `tags[]` on server records |
| Background job queue | ⬜ task dispatch is synchronous request/response today,
  not a durable queue (see `ARCHITECTURE.md` §1 "As built") |
| Audit logs | ✅ append-only, covers every privileged action |
| Notifications | ⬜ not implemented (no email/Slack/Telegram/Discord/webhook yet) |
| Error handling and recovery | 🚧 agent reconnects with exponential backoff; no
  on-disk task journal yet (a task in flight when the agent restarts is lost) |

### Server management
| Feature | Status |
|---|---|
| Ubuntu compatibility checks | ✅ `install.sh` + `checkOSSupported`/`checkResources` |
| Automated hosting-stack install (LEMP) | ✅ nginx, php8.3-fpm, mariadb, redis, git,
  composer, wp-cli, certbot, ufw, fail2ban — idempotent, retryable |
| Apache / OpenLiteSpeed support | ⬜ Phase 3 stack adapters |
| PHP-FPM, multiple PHP versions | 🚧 php-fpm pool-per-site works; only 8.3 is
  installed by `stack.install` today, though `site.set_php_version` and pool paths are
  already version-parameterized |
| MariaDB/MySQL | ✅ install + per-DB least-privilege grants |
| Redis, Git, Composer, WP-CLI | ✅ installed by `stack.install` |
| Node.js | ⬜ Phase 3 |
| UFW firewall, Fail2Ban | 🚧 installed with safe defaults; no rule-editing UI |
| SSH/SFTP management, SSH-key mgmt, port mgmt, root-login controls | ⬜ Phase 2 |
| Automatic security updates | ⬜ Phase 2 (`unattended-upgrades` integration) |
| Service controls | ✅ `service.control`, allow-listed units/actions only |
| Cron-job management | ⬜ Phase 2 |
| Process/worker management | ⬜ Phase 2 |
| Disk-usage analysis, safe cleanup | ⬜ not started |
| Server diagnostics | 🚧 `diagnostics.basic` (read-only service-state check); no
  plain-language suggested-repair layer yet |

### Application management
| Feature | Status |
|---|---|
| WordPress deployment | ✅ real `wp-cli` install as the site's own user |
| Custom PHP / static-site deployment | ✅ `site.create` with `app_type` |
| Laravel, Node.js, n8n, Mautic deployment | ⬜ Phase 3 |
| Application isolation | ✅ own system user, php-fpm pool, `open_basedir`,
  disabled dangerous PHP functions, own DB grants |
| Per-site PHP version/settings | 🚧 `site.set_php_version` exists; only 8.3 actually
  installed today |
| Custom webroot | ✅ `docroot` per site |
| Environment variables (per app) | ⬜ not implemented |
| Temporary sites, staging environments | ⬜ not implemented |
| Site cloning, cross-server migration | ⬜ Phase 2 |
| Maintenance mode | ⬜ not implemented |
| Basic auth on a site | ⬜ not implemented |
| Custom + Let's Encrypt SSL | ✅ `ssl.issue_letsencrypt` (certbot), `ssl.install_custom` |
| Automatic SSL renewal | ⬜ not implemented (certbot's own renewal timer is not
  wired up by `stack.install` yet) |
| WordPress auto-login/auto-update | ⬜ not implemented |
| Application enable/disable | ✅ `site.set_status` |
| Secure file manager | ✅ `file.list/read/write/delete`, scoped + symlink-safe |
| Code editor | 🚧 dashboard has no in-browser editor UI yet; the `file.read`/
  `file.write` capabilities it would use already exist |
| Archive creation/extraction | ⬜ not implemented |
| Application logs / advanced log viewer | 🚧 `logs.tail` (redacted) exists; no
  filtering/search UI yet |

### Git deployment
All ⬜ — explicitly scoped to Phase 2 (`product-plan.md` §9). No Git deployment,
webhook push-to-deploy, deploy keys, or rollback exist in this codebase yet.

### Backup and restoration
| Feature | Status |
|---|---|
| DB/file/full backups | ✅ `backup.run` — checksummed local tar.gz; the control plane
  now persists a `backups` row on every successful run (`POST /api/v1/servers/{id}/backups`),
  not just the agent's own TaskEvent detail |
| Scheduling, retention policies | ⬜ not implemented (backups are on-demand only) |
| Encryption | ⬜ not implemented (local tar.gz is unencrypted; relies on host
  filesystem permissions today) |
| Backup verification | ✅ SHA-256 checksum is recorded at backup time and
  re-verified by `backup.restore` before it touches anything — a restore whose archive
  doesn't match its recorded checksum is refused, not silently applied |
| Local storage | ✅ |
| S3-compatible / Amazon S3 / R2 / B2 / Spaces / Wasabi | ⬜ Phase 2 |
| Restore (same or another server) | ✅ `backup.restore` capability +
  `POST /api/v1/servers/{id}/backups/{backupId}/restore`. Restoring to a *different*
  server/site works for the files scope (it locates the archived site directory by
  structure, not by name) but is not yet exercised by an automated cross-server test —
  see `TESTING.md`. |
| Pre-restore checkpoints, progress tracking, failure recovery | 🚧 `backup.restore`
  takes a best-effort pre-restore checkpoint (a fresh `backup.run` of current state)
  before restoring, and that checkpoint is itself recorded as a `backups` row; progress
  is reported via `Progress` callbacks the same as every other long-running capability.
  What's still missing: scheduled/automatic retention of checkpoints (they accumulate
  like any other backup with no cleanup capability — see §21), and restore does not
  delete files absent from the archive (documented tradeoff, not a bug — see
  `OPERATIONS.md` §3). |

### Security and monitoring
See `SECURITY.md` for the detailed, section-by-section implemented-vs-planned
breakdown. Summary: application/server isolation, mTLS, revocation, TOTP 2FA, and the
audit log are implemented; commit-confirm SSH/firewall safety flow, IP allow-listing,
WAF/bot-blocking, alert thresholds, and external notification channels are not.

### Team and commercial features
All ⬜ — deliberately Phase 3 (`product-plan.md` §9): organizations/teams/roles,
white-label, reseller/hosting-packages, billing, public API, plugin architecture.

## 3. Completed and pending phases

Phase boundaries and full milestone/estimate tables are in `product-plan.md` §6; this
is the condensed status:

- **Phase 1 — secure working foundation:** the capability surface, an automated test
  suite, and backup **restore** (closed out this session — see §19) are all in place;
  the biggest remaining gaps are SSL auto-renewal, agent cert auto-rotation, backup
  scheduling/retention, and a background job queue for tasks longer than the current
  synchronous-dispatch model comfortably supports. Not "GA-ready" yet, but the
  architecture and security primitives it depends on (mTLS, allow-listed capabilities,
  per-app isolation, audit log, checksum-verified backup/restore) are real and proven,
  not stubs.
- **Phase 2 — professional server management:** not started. Git deployment,
  cron/process management, SSH/firewall management UI, remote backups, cross-server
  migration all remain ⬜.
- **Phase 3 — commercial platform:** not started.

## 4. System architecture

See `ARCHITECTURE.md` for the full diagram and rationale. One-paragraph summary: a
browser talks to `apps/controlplane`'s public HTTP API over authenticated HTTPS
(session cookie + TOTP); the same binary also runs a separate mTLS-only "gateway"
listener that customer VPS agents connect *out* to (agent-initiated, so no inbound
port needs opening on the VPS). The control plane dispatches one of a fixed set of
named capabilities to a connected agent and waits for a terminal result; the agent
never accepts a free-form command. Everything is backed by one SQLite database file.

## 5. Frontend architecture

`apps/controlplane/web/index.html` — a single self-contained file (no React/Vue, no
bundler, no `node_modules`), embedded into the Go binary via `//go:embed`. Plain
`fetch()` calls against `/api/v1/*`, cookie-based session auth (the browser never
handles the session token directly — `HttpOnly` cookie). This trades "modern SPA
tooling" for "the entire frontend is one deployable file with zero build step and zero
frontend dependency surface to patch," a deliberate Phase 1 choice given the security-
sensitive nature of the product. Verified mobile-responsive (no horizontal overflow) at
320/375/390/414/768/1280px with real Playwright browser automation against the core
flows — see §21 and `TESTING.md` §Mobile responsiveness for what was covered and what
wasn't (modals and the Security tab weren't screenshotted in this pass).

## 6. Backend architecture

Go, standard library `net/http` (Go 1.22+ method+pattern routing, e.g.
`"POST /api/v1/servers"`), no web framework. Two logical components sharing one
process and one `*store`:

- **`apiServer`** (`http.go`, `auth.go`, `sites.go`, `dashboard.go`) — the public,
  session-authenticated API + dashboard host.
- **`gateway`** (`gateway.go`) — the mTLS-only, certificate-authenticated agent-facing
  listener. See `API.md` for the full endpoint/message list.

Persistence: `store` (`store.go`) wraps a single `*sql.DB` (SQLite,
`modernc.org/sqlite`, pure Go/no cgo) with `SetMaxOpenConns(1)` to avoid
`SQLITE_BUSY` — acceptable because this control plane's write volume is nowhere near
where that serialization matters. Every caller goes through `store`'s method set,
never raw SQL, which is what makes a future Postgres swap a driver change, not a
rewrite (see `db.go`'s doc comment).

Certificate authority: `agentCA` (`ca.go`) — an in-process ECDSA (P-256) CA, persisted
to disk (`agent-ca-cert.pem`/`agent-ca-key.pem`) and reloaded on restart so a
control-plane restart is never a silent mass-revocation event (this was a real bug
caught during integration testing — see `TESTING.md`).

## 7. Server-agent architecture

`apps/agent/main.go` — a single static Go binary, stdlib-only plus a pure-Go
Unix-socket MySQL driver (no cgo, no external runtime deps). Lifecycle:

1. **First run**: `register.go` exchanges the one-time bootstrap token for a signed
   client certificate (`POST /agents/register`), persists the cert/key under
   `-data-dir` (0600, root-only).
2. **Every subsequent run**: `connect.go` dials the gateway over mTLS, sends `Hello`
   (agent version), then loops sending periodic `Heartbeat`s (`metrics.go`: uptime via
   `/proc/uptime`, 1-minute load average via `/proc/loadavg`, memory% via
   `/proc/meminfo`, disk% via `syscall.Statfs("/")`) and receiving `Task`s, which it
   dispatches into `packages/capabilities.Default().Dispatch(...)` and reports back as
   `TaskEvent`s.
3. **Reconnect**: on any connection loss, `main.go`'s loop retries with exponential
   backoff (1s → 30s cap) until the process is signaled to stop (`SIGTERM`/`SIGINT`).

The agent has **no shell-exec entry point in its protocol or code** — see §8.

## 8. Database schema

SQLite, schema defined inline in `apps/controlplane/db.go` (`CREATE TABLE IF NOT
EXISTS`, applied on every `openDB` call — idempotent, no separate migration tool yet):

| Table | Purpose |
|---|---|
| `users` | id, email (unique, lowercased), bcrypt password hash, TOTP secret/enabled |
| `sessions` | SHA-256-hashed session token → user, expiry, `mfa_verified` flag |
| `servers` | id, name, group, tags (JSON), status, cert serial, last heartbeat (JSON) |
| `bootstrap_tokens` | SHA-256-hashed single-use token → server, expiry |
| `revoked_certs` | cert serial → server, revoked-at (checked on every gateway handshake) |
| `audit_log` | append-only: seq, timestamp, server, actor, action, detail |
| `sites` | id, server, domain, system user, docroot, app type, PHP version, status |
| `backups` | id, server, site, scope, path, size, sha256, db_name, status, created_at |

No ORM — every query is a small, explicit SQL statement in `store.go`. All secrets
(session tokens, bootstrap tokens) are stored only as SHA-256 hashes; passwords use
bcrypt (cost 12); nothing is stored in plaintext.

`db.go`'s `applyMigrations` is this project's entire migration story so far: additive
`ALTER TABLE ... ADD COLUMN` statements run after the `CREATE TABLE IF NOT EXISTS`
block, each one safe to re-run (a "duplicate column name" error means it already
applied, and is swallowed rather than treated as failure). `backups.db_name` is the
first column added this way, needed so a restore can recover which database a backup
came from without the caller having to remember and re-supply it.

## 9. API endpoints

Full list with request/response shapes in `API.md`. Summary: `/api/v1/auth/*`
(signup/login/logout/TOTP enroll+verify/MFA challenge/me), `/api/v1/servers*` (CRUD,
revoke, task dispatch, sites, audit), `/agents/register` (the one unauthenticated
agent-facing endpoint, secured by the bootstrap token itself), `/healthz`.

## 10. Background jobs

None exist as a separate durable queue today — see the "Background job queue" ⬜ row
above. Task dispatch (`gateway.dispatch`) is synchronous: the HTTP handler blocks
(bounded by a 120s context timeout) waiting for the agent's terminal `TaskEvent`. This
is a known scaling limit, not an oversight — see `ARCHITECTURE.md` §1 "As built" and
the recommended next step in `OPERATIONS.md`.

## 11. Agent authentication and security

See `SECURITY.md` in full. Summary: single-use, short-lived (15 min default),
hashed-at-rest bootstrap tokens exchanged exactly once for a 30-day mTLS client
certificate bound (by `CommonName`) to the server's ID; the gateway independently
derives identity from the certificate on every connection (never trusts anything the
agent asserts in-band) and checks a revocation list on every handshake.

## 12. Privileged operations and allow-list

Every privileged action the agent can perform is one of the named constants in
`packages/capabilities/capabilities.go` (`Cap*`). `Registry.Dispatch` rejects any
capability name not in this fixed map — there is no fallback to a generic executor.
Within capabilities that shell out, every `exec.Command`/`exec.CommandContext` call
uses a literal argv built only from allow-listed or already-validated values (e.g.
`service.control`'s `unit`/`action` are checked against `managedUnits`/
`serviceActions` maps before ever reaching `systemctl`) — never a shell string with
caller-supplied text concatenated in. This is enforced by tests (`TestServiceControl*`
in `packages/capabilities/capabilities_test.go`), not just convention.

Current capability list: `system.ping`, `service.control`, `diagnostics.basic`,
`stack.install`, `site.create`, `site.set_php_version`, `site.set_status`,
`app.wordpress_install`, `ssl.issue_letsencrypt`, `ssl.install_custom`, `db.create`,
`db.delete`, `db.list`, `file.list`, `file.read`, `file.write`, `file.delete`,
`backup.run`, `backup.restore`, `logs.tail`. Notably absent (by design, until reviewed
and added): `git.deploy`, `cron.upsert`, `ssh.*`, `firewall.*`, `agent.self_update`.

## 13. Installation and deployment

See `INSTALLATION.md` for both local development and a clean-Ubuntu-VPS walkthrough.

## 14. Supported operating systems

Ubuntu 24.04 LTS only, on `x86_64` or `aarch64` — enforced twice (defense in depth):
once by `install.sh` before the agent binary is even fetched, and independently again
by the agent itself (`checkOSSupported` in `packages/capabilities/exec_helpers.go`) at
`stack.install` time, so a check bypassed upstream still can't reach an unsupported OS.

## 15. Supported hosting stacks

Phase 1 ships exactly one stack profile: `phase1-lemp` — nginx, PHP 8.3-FPM (+
extensions), MariaDB, Redis, Git, Composer, WP-CLI, Certbot, UFW, Fail2Ban. Apache,
OpenLiteSpeed, and additional app-type adapters (Node.js, Laravel, n8n, Mautic) are
explicitly postponed to Phase 3 (`product-plan.md` §9), though the capability registry
is structured so adding a new stack profile or app type is additive (a new capability
+ review), not a rewrite of the dispatch model.

## 16. Environment variables / flags

Control plane (`apps/controlplane`, all flags, no env vars read directly):
`-api-addr`, `-gateway-addr`, `-gateway-public-addr`, `-bootstrap-token-ttl`, `-db`,
`-ca-dir`, `-public-dir`, `-insecure-cookies`. See `main.go` for defaults.

Agent (`apps/agent`): `-api`, `-token`, `-data-dir`, `-register-only`. `run()`
(`packages/capabilities/exec_helpers.go`) sets `DEBIAN_FRONTEND=noninteractive` and
`COMPOSER_ALLOW_SUPERUSER=1` in the child-process environment for every shelled-out
command.

## 17. Dependencies and licenses

From `go.mod` (all pinned to exact versions, all permissively licensed, no GPL/AGPL
copyleft dependency — checked before adding each one, per the open-source policy in
the task brief):

| Module | License | Purpose |
|---|---|---|
| `github.com/go-sql-driver/mysql` | MPL-2.0 | Agent's DB capability (Unix-socket MySQL/MariaDB client) |
| `golang.org/x/crypto` | BSD-3-Clause | `bcrypt` password hashing |
| `modernc.org/sqlite` | BSD-3-Clause | Control-plane storage (pure-Go SQLite, no cgo) |
| `filippo.io/edwards25519`, `github.com/google/uuid`, `github.com/mattn/go-isatty`, `github.com/ncruces/go-strftime`, `github.com/remyoudompheng/bigfft`, `golang.org/x/sys`, `modernc.org/libc`, `modernc.org/mathutil`, `modernc.org/memory`, `github.com/dustin/go-humanize` | various permissive (BSD/MIT/Apache-2.0) | transitive deps of the above two |

No dependency requires a paid API/license. TOTP, mTLS/PKI, and password hashing use
Go's standard library directly (`crypto/*`) rather than a third-party auth library —
a deliberate choice to minimize the dependency surface for security-critical code (see
`totp.go`'s doc comment). There is currently no automated vulnerability-scanning step
in CI (no CI pipeline exists yet at all — see `OPERATIONS.md`); `go list -m all` +
`govulncheck` is the recommended next addition.

## 18. Security model

See `SECURITY.md`. One-line summary: capability allow-list (no shell-exec RPC), mTLS
with short-lived certs and immediate revocation, per-app OS-level isolation
(system user + php-fpm pool + `open_basedir` + disabled functions + scoped DB grants),
bcrypt + TOTP for dashboard auth, append-only audit log, path-traversal/symlink-escape
defenses on the file manager (`resolveScopedPath`).

## 19. Backup and restore model

**Backup**: `backup.run` — local, checksummed tar.gz of DB and/or files, written under
`/var/backups/serverpanel` on the agent's own disk. The control plane's
`POST /api/v1/servers/{id}/backups` dispatches it and persists a `backups` row
(id, server, site, scope, path, size, sha256, db_name, status, created_at) — this
persistence step didn't exist for the first several sessions of this project (only the
capability itself did) and was closed out alongside restore.

**Restore**: `backup.restore` — the counterpart capability, dispatched via
`POST /api/v1/servers/{id}/backups/{backupId}/restore`. It:
1. Refuses to read anything outside `/var/backups/serverpanel` and, when a checksum is
   on record (always, for a backup this control plane created), refuses to restore from
   an archive whose current SHA-256 doesn't match — a corrupted or tampered archive is
   rejected before extraction, not partway through it.
2. Takes a **best-effort pre-restore checkpoint**: a fresh `backup.run` of whatever's
   currently on disk, using the same scope/site/db as the restore, before changing
   anything. If the checkpoint itself fails (e.g. the database being restored is
   already gone — the exact disaster-recovery case restore exists for), that failure is
   reported in the result rather than blocking the restore, and the checkpoint (when it
   succeeds) is itself persisted as a `backups` row so a bad restore can be rolled back
   the same way.
3. Restores the database scope via `mysql <db_name> < dump.sql` (mysqldump's default
   output includes `DROP TABLE IF EXISTS` before each `CREATE TABLE`, so this correctly
   replaces existing table contents) and the files scope via `cp -a` from the extracted
   archive into the target `site_root`.
4. Does **not** delete anything from the target before restoring. Files restored are
   overwritten; files present on disk but absent from the archive are left in place.
   This is a deliberate consequence of the same "never implement unrestricted recursive
   deletion as a capability" rule `backup.run`'s doc comment already states — see
   `OPERATIONS.md` §3 for the operational implication.

A real bug was caught while writing the automated round-trip test for this
(`TestHandleBackupRestoreFilesScopeRoundTrip`, `packages/capabilities/backup_test.go`):
`backup.run`'s output filename only had second-resolution timestamps, so a pre-restore
checkpoint created moments after the archive it was restoring from (well within the
same UTC second) could collide on filename and silently overwrite the original archive
with the checkpoint's contents — corrupting the very archive being restored from mid-
restore. Fixed by appending a random hex suffix to every backup filename
(`packages/capabilities/backup.go`'s `randHex`), which also incidentally makes
concurrent `backup.run` calls for the same site/db collision-safe.

What's still missing, honestly: scheduled/automatic backups, retention/cleanup of old
backups and checkpoints (there is still no disk-cleanup capability at all — by design,
see `backup.go`'s doc comment — so backups accumulate until an operator manually prunes
`/var/backups/serverpanel`), encryption at rest, and remote/S3-compatible storage
targets. All ⬜, Phase 2 per `product-plan.md` §9. The `db.create`/`db.delete`
capabilities also have no persisted database↔site association in the control plane's
schema (see §8) — a `db`-scope backup's `db_name` is whatever the caller typed at
backup time, not derived from anything the control plane tracks, so there is currently
no dashboard UI listing "this site's databases" to back up from; the operator supplies
the database name directly.

## 20. Monitoring and alerting

Heartbeat-based only: uptime/load/mem%/disk% every connection cycle, surfaced in the
dashboard's server-detail view. No threshold-based alerting, no email/Slack/Telegram/
Discord/webhook notifications, no SSL-expiration or backup-failure alerts exist yet —
all ⬜, scoped to Phase 2 per `product-plan.md` §9.

## 21. Known limitations

- Backup **restore** does not delete files absent from the archive before restoring
  (merge/overwrite, never a wipe) — see §19. No scheduled backups, retention/cleanup,
  encryption at rest, or remote/S3-compatible storage yet.
- A `backup.restore`'s pre-restore checkpoint is best-effort: if it fails (e.g. the
  thing being restored is already gone), the restore proceeds anyway rather than
  blocking on it — see §19.
- No persisted database↔site association — a database-scope backup's `db_name` is
  operator-supplied at backup time, not tracked against a site record (see §19, §8).
- No on-disk agent task journal — a task in flight when the agent process restarts is
  lost, not resumed (see `ARCHITECTURE.md` §4 "As built").
- No agent certificate auto-renewal before its 30-day expiry (see `SECURITY.md` §2).
- No agent self-update mechanism (see `SECURITY.md` §3).
- No background job queue — task dispatch is synchronous, bounded by a 120s HTTP
  timeout for most capabilities (backup run/restore use a longer 10-minute bound — see
  `API.md`); this will not scale past a moderate number of concurrent long-running
  tasks (e.g. many simultaneous `stack.install` runs) without becoming a queue.
- Single-user model: no organizations/teams/RBAC yet.
- The in-process CA, while functionally correct, is not yet isolated as its own
  tightly-scoped trust boundary (see `SECURITY.md` §2).
- `systemctl start/stop/restart`, Let's Encrypt issuance, and the `backup.restore`
  database-scope `mysql` import have not been verified against a real
  systemd/MariaDB/public-DNS environment in *this* sandbox (no systemd as PID 1, no
  MariaDB installed, no public DNS) — see `TESTING.md` §What hasn't been verified. The
  files-scope restore path *has* been verified end-to-end with real `tar`/`cp` in this
  environment (`TestHandleBackupRestoreFilesScopeRoundTrip`).
- Dashboard mobile responsiveness has been verified with real Playwright browser
  automation at 320/375/390/414/768/1280px against the live dashboard (login, server
  list, server detail incl. the new Backups section, audit log) — no horizontal
  overflow at any width. One real bug was found and fixed in the process: the topbar
  didn't wrap and the login card's fixed width exceeded a 320px viewport; see
  `TESTING.md` §Mobile responsiveness for what was and wasn't covered (e.g. the
  Security tab and every modal dialog were not screenshotted in this pass).
- No CI pipeline / automated vulnerability scanning configured yet.

## 22. Performance decisions

- SQLite with `SetMaxOpenConns(1)` — deliberately serializes writes; acceptable at
  Phase 1's write volume (server/task/audit events, not request-path traffic), avoids
  `SQLITE_BUSY` entirely instead of building retry logic around it.
- Heartbeats carry only aggregated numbers (four floats/ints), never raw logs or
  per-request data, keeping steady-state agent↔control-plane bandwidth minimal.
- `logs.tail` bounds its read to `maxTailLines` (1000) via a fixed-size ring buffer,
  and `file.read`/`file.write` cap at 5MB (`maxFileManagerReadBytes`) — both prevent an
  unbounded-memory or unbounded-transfer request through the file manager/log viewer.
- The agent reconnects with exponential backoff (1s → 30s cap), not a tight retry
  loop, to avoid hammering the gateway during an outage.
- `stack.install` and `site.create` are written to be idempotent (checked via
  `isPackageInstalled`, "don't clobber an existing deployment on a retried create" in
  `writeDefaultIndex`), so a retried task after a transient failure is safe/cheap
  rather than needing its own separate retry-safety design.

## 23. Test strategy

See `TESTING.md` for the full breakdown (what's automated, what was manually verified
against a real Ubuntu 24.04 host, and why). Summary: `go test ./...` covers
auth/session/TOTP/bootstrap-token/revocation logic and the capability allow-list
boundary (including path-traversal/symlink-escape defenses) with real SQLite and real
filesystem operations — no mocks for anything that has a cheap real implementation.
Capabilities that require actual system services (package installs, systemd, real
DNS-backed Let's Encrypt issuance) are documented as manually verified in a real
container in a prior session, not re-verified by the automated suite, and that
distinction is called out explicitly rather than glossed over.

## 24. Local development instructions

See `INSTALLATION.md` §Local development.

## 25. Clean Ubuntu installation instructions

See `INSTALLATION.md` §Production install on a clean Ubuntu 24.04 VPS.

## 26. Upgrade and rollback procedures

See `OPERATIONS.md` §Upgrade and rollback. Summary of current reality: there is no
automated upgrade mechanism for either the control plane or the agent yet (§17, §21);
upgrading today means rebuilding/redeploying the control-plane binary (data survives in
the SQLite file/CA dir) and re-running the agent installer with a new `-version` on
each VPS. This is a documented manual procedure, not a one-click feature, until the
Phase 1 "agent safe-update mechanism" milestone (`product-plan.md` §6) is built.

## 27. Troubleshooting

See `OPERATIONS.md` §Troubleshooting for the concrete list, sourced from real bugs
found and fixed during integration testing (missing IP SANs on the gateway cert,
premature "connected" logging, CA regenerating on restart, UFW's `OpenSSH` profile
assumption, Composer's root-warning-as-version bug, MariaDB's `?`-placeholder
limitation in `CREATE USER`, IPv6 `nginx -t` failures, `server_names_hash_bucket_size`
sizing, and two persistence bugs where a successful operation wasn't actually saved).

## 28. Assumptions and design decisions

- **Centralized control plane over per-server local panel** — see `product-plan.md`
  §1 for the full comparison; chosen for fleet-wide visibility/consistency, accepting
  higher upfront build complexity.
- **Go for both control plane and agent** — single static binary, no runtime deps,
  easy cross-compilation, small footprint; matches `product-plan.md` §2's
  recommendation.
- **SQLite over Postgres for Phase 1** — a pragmatic single-file store; the `store`
  type's method set is the only thing any caller touches, so this is a driver swap
  later, not a rewrite (see `db.go`).
- **Newline-delimited JSON over TLS instead of gRPC** — simpler to implement with zero
  extra dependencies for Phase 1's message volume; the wire types in `packages/proto`
  already model what a protobuf schema would, so migrating later is additive.
- **No third-party TOTP/JWT/session library** — `crypto/hmac`/`crypto/sha1`/
  `crypto/rand`/`crypto/x509` directly, on the reasoning that pulling in a dependency
  for ~60 lines of well-specified crypto (RFC 6238) is a worse security trade than
  reviewing 60 lines of stdlib-only code.
- **Capability allow-list is the security boundary, not process privilege** — the
  agent currently runs as root (needed for package installs, `/etc/nginx`, systemd,
  UFW), but "no arbitrary shell exec" is enforced by the fixed `Registry` map and
  argv-only `exec.Command` calls, not by process sandboxing (which remains a
  documented future hardening step — `SECURITY.md` §4).
- **Backup before restore** — `backup.run` shipped in this codebase before any restore
  capability; flagged clearly (§19, §21) rather than left as a silent gap, since
  "backups exist" without "restore works" is a false sense of safety if not documented.
- **No proprietary Webuzo/ServerAvatar code, branding, or assets** — every protocol,
  UI, and mechanism here is independently designed against open standards (mTLS,
  systemd, ACME/Let's Encrypt, RFC 6238 TOTP).

## 29. Dated change log

See [`../CHANGELOG.md`](../CHANGELOG.md).
