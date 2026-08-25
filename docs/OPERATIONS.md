# Operations

## 1. Running the control plane

```
go build -o controlplane ./apps/controlplane
./controlplane \
  -api-addr=0.0.0.0:8080 \
  -gateway-addr=0.0.0.0:8843 \
  -gateway-public-addr=controlplane.example.com:8843 \
  -db=/var/lib/serverpanel/serverpanel.db \
  -ca-dir=/var/lib/serverpanel/ca
```

- `-db` and `-ca-dir` must point at persistent storage — losing the CA directory
  invalidates every registered agent (it would need full re-registration); losing the
  DB file loses every account, server, audit entry, and site record. Back both up.
- `-insecure-cookies` must **never** be set in production — it disables the `Secure`
  flag on the session cookie, meaning a session token could leak over plain HTTP. It
  exists solely for local development without a TLS terminator in front.
- The public API (`-api-addr`) should sit behind a real TLS terminator (nginx, Caddy,
  a cloud load balancer) in production — the Go binary itself does not terminate TLS
  for the public API; only the agent gateway does its own TLS/mTLS.
- The agent gateway (`-gateway-addr`) does its own TLS/mTLS termination directly
  (`gateway.listenAndServe`) — do not put a reverse proxy in front of it, since that
  would terminate the mTLS the agent's identity depends on.

There is currently **no process manager / systemd unit checked into this repo for the
control plane itself** (only the agent ships one, via `install.sh`). Run it under
systemd, a container orchestrator, or equivalent with automatic restart in production.

## 2. Running the agent

Covered in full in `INSTALLATION.md`. Operationally: `systemctl status
serverpanel-agent`, `journalctl -u serverpanel-agent -f`. The agent's identity lives
under `-data-dir` (default `/etc/serverpanel-agent`), `0600`/`0700` permissioned —
back this up if you want to avoid a full re-registration after a lost disk, though
re-registration itself is cheap (just requires a fresh bootstrap token from the
dashboard).

## 3. Backup and restore

**Backup** (implemented): from the dashboard, open a server → a site → "Create backup"
(scope `files`, `db`, or `full`; `db_name` required for `db`/`full`). This calls
`POST /api/v1/servers/{id}/sites/{siteId}/backups`, which dispatches `backup.run`
(`packages/capabilities/backup.go`) with `site_root` taken from the site's own recorded
`docroot`. The agent writes a checksummed local tar.gz under
`/var/backups/serverpanel` on the VPS itself; on success the control plane persists a
`backups` row (path, scope, size, SHA-256) — a raw dispatch success alone is never
enough, the row is the durable record a restore can later be pointed at.

**Restore** (implemented): from the same site's Backups list, click "Restore" on any
recorded backup and confirm. This calls
`POST /api/v1/servers/{id}/backups/{backupId}/restore`, which looks up the backup's own
recorded `archive_path`/`scope`/`db_name`/`sha256` (never accepts these as free-form
input) and dispatches `backup.restore`. On the agent:

1. the checksum is re-verified against the recorded SHA-256 before anything is touched;
2. the archive is extracted with Go's `archive/tar` directly into a private temp
   directory, rejecting any entry that would traverse outside it;
3. a fresh checkpoint backup of the *current* live state (database and/or files) is
   taken and its path returned — so a restore is always recoverable, never a one-way
   trip;
4. the database is restored via `mysql <db> < dump.sql` (streamed, not read into
   memory) and/or the site's files are swapped in via an atomic-as-possible
   rename-based directory replace, then ownership is restored to the site's own system
   user.

Restore is currently **same-server only**: `backup.restore` runs on the same agent
whose backup directory holds `archive_path`. Restoring a backup onto a *different*
server requires transferring the archive there first — that transfer step, and a
dedicated cross-server restore flow, remain a Phase 2 gap (tracked alongside
cross-server migration; see `SYSTEM.md` §21).

To restore manually (e.g. the control plane itself is unreachable): SSH to the VPS,
the archive is at the `archive_path` your `backups` row (or the original `backup.run`
task detail) recorded, verify its SHA-256 matches, then either re-run the same restore
via a direct `backup.restore` task dispatch or extract/restore by hand as a last
resort.

## 3a. SSL and renewal

**Issue a Let's Encrypt certificate**: from the dashboard, open a server → a site →
"Issue Let's Encrypt" in the SSL panel, supply a notification email. This calls
`POST /api/v1/servers/{id}/sites/{siteId}/ssl/issue`, which dispatches
`ssl.issue_letsencrypt` for the site's own recorded domain (never a caller-supplied
one) with a 5-minute timeout — Let's Encrypt performs a real HTTP-01 validation
challenge, so the domain must already resolve to this server first. On success the
site's `ssl_status`/`ssl_expires_at` are persisted.

**Auto-renewal**: `stack.install` enables certbot's own `certbot.timer` (runs
`certbot renew` twice daily, certbot's documented default) and installs a deploy hook
at `/etc/letsencrypt/renewal-hooks/deploy/serverpanel-reload-nginx.sh` that
runs `nginx -t && systemctl reload nginx` after any certificate actually renews —
this is what makes a renewed certificate on disk actually reach nginx's live worker
processes, not just sit unused. Running `stack.install` again on a server that already
has certbot installed is safe and idempotent: it only adds the timer/hook if they're
missing.

**Check renewal status on demand**: "Check status" in the SSL panel calls
`POST /api/v1/servers/{id}/sites/{siteId}/ssl/check-renewal`, which dispatches the
read-only `ssl.check_renewal` capability (parses `certbot certificates -d <domain>`)
and refreshes the persisted status/expiry — useful for confirming the auto-renewal
timer actually renewed a certificate, without waiting for the next scheduled run.
There is no automated expiry-alerting job yet (see §4) — this is a manual/on-demand
check today.

**Custom certificates**: "Upload custom cert" in the SSL panel accepts a PEM
certificate (with any intermediate chain) and private key. The agent validates they're
a matching pair and that the certificate isn't already expired (`crypto/tls`/
`crypto/x509`, never shelling out to openssl) *before* writing anything to disk or
reloading nginx — a mismatched or expired pair is rejected with the existing
certificate left untouched.

**Manual verification** (e.g. the control plane itself is unreachable): SSH to the VPS
and run `certbot certificates` directly, or `systemctl status certbot.timer` to confirm
the renewal timer is active.

## 4. Monitoring and alerting

Server health is visible in the dashboard's server-detail view (uptime, 1-minute load
average, memory-used %, disk-used %), sourced from the agent's periodic heartbeat.
There is no threshold-based alerting and no external notification channel (email/
Slack/Telegram/Discord/webhook) implemented yet — an operator must actively check the
dashboard; nothing pushes a notification if a server goes offline, a backup fails, or
a certificate is about to expire. This is a known Phase 2 gap (`product-plan.md` §9),
not an oversight.

Operationally, watch: the control plane's own process (no self-monitoring endpoint
beyond `GET /healthz`, which only confirms the HTTP listener is up — it does not check
DB connectivity or gateway health), and `journalctl -u serverpanel-agent` on each VPS
for reconnect-loop messages, which indicate a network or certificate problem.

## 5. Upgrade and rollback

**Control plane**: no automated upgrade mechanism. Build a new binary, stop the old
process, start the new one pointed at the same `-db`/`-ca-dir`. Because every schema
change so far has been additive `CREATE TABLE IF NOT EXISTS` statements (no destructive
migrations exist in this codebase), an old binary can generally be restarted against a
DB a newer binary has already touched, but this has not been formalized as a supported
downgrade path — take a copy of the `.db` file and the CA dir before upgrading so a
rollback is "restore the file," not "hope for the best."

**Agent**: no self-update mechanism yet (`SECURITY.md` §3). Re-run `install.sh` with a
newer `--version` to upgrade; this replaces the binary and restarts the systemd unit,
but does not currently re-run the compatibility/security pre-check that the original
install did (a gap worth closing before this is relied on for fleet-wide upgrades).
Because the agent's identity (cert/key) lives under `-data-dir`, separate from the
binary, an upgrade does not require re-registration.

**Rollback**: for the control plane, restoring the pre-upgrade binary + a backed-up
copy of `-db`/`-ca-dir` from just before the upgrade. For the agent, re-running
`install.sh --version=<previous>`. Neither path has been exercised end-to-end in this
project yet — see `TESTING.md` §5 item 2 (this is one of the scenarios a scripted
real-VPS/container test pass should cover before either is called a supported,
tested procedure rather than a documented manual fallback).

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Agent connects then immediately shows "offline" in the dashboard | Check `journalctl -u serverpanel-agent` for a handshake error; confirm the agent's cert hasn't expired (30-day TTL, no auto-renew yet — see `SECURITY.md` §2) and re-register with a fresh bootstrap token if so. |
| Every registered agent shows "disconnected" after a control-plane restart | This was a real bug (CA regenerated in memory every start) — fixed by persisting the CA to `-ca-dir`. If it recurs, confirm `-ca-dir` actually points at persistent storage and the process has write access to it. |
| `stack.install` fails nginx config test | Likely an IPv6-disabled host; `stack.install` already probes `ipv6Available()` and should handle this automatically — if it still fails, check for a leftover `listen [::]:80` in a manually-edited vhost, or too many vhosts tripping `server_names_hash_bucket_size` (already raised generously by `stack.install`, but a very large fleet of vhosts on one box could still exceed it). |
| Composer or WP-CLI install step reports a version that looks wrong | Confirm `COMPOSER_ALLOW_SUPERUSER=1` is actually reaching the child process (`run()` in `exec_helpers.go` sets it); a version string containing "as root" instead of a real version number is the known symptom of the fixed bug recurring. |
| `db.create` fails with a MariaDB syntax error near `IDENTIFIED BY` | Confirm the driver DSN still has `interpolateParams=true` (`packages/capabilities/db.go`) — MariaDB rejects a `?` placeholder inside `CREATE USER` over the prepared-statement protocol. |
| Dashboard shows a server's site list as empty after a successful `site.create` dispatch | Confirm you're calling `POST /api/v1/servers/{id}/sites` (which persists a record), not the generic `POST /api/v1/servers/{id}/tasks` with `capability: "site.create"` (which dispatches but does not persist — see `API.md` §2). |
| Login succeeds but every subsequent API call returns `403 two-factor verification required` | Expected behavior once 2FA is enabled — call `POST /api/v1/auth/mfa/challenge` with a valid TOTP code before any other route will accept the session. |
| Any privileged action's effect isn't showing up | Check `GET /api/v1/audit` — every capability dispatch is logged with its `task_id` before being sent, and its terminal outcome is logged as `task.event`; cross-reference the task ID to see whether the agent actually reported success. |

## 7. Data/secrets hygiene

Never commit `.db` files, CA key material, or agent identity files. `.gitignore`
already excludes the common build/data artifacts (`*.db`/`*.db-shm`/`*.db-wal`,
`agent-ca-cert.pem`/`agent-ca-key.pem`, `/serverpanel-agent/`, compiled binaries) —
verify before adding new persistent-storage paths (e.g. a non-default `-ca-dir` or
`-db` filename) that they're covered too.
