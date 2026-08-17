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

**Backup** (implemented): `POST /api/v1/servers/{id}/sites/{siteId}/backups` with
`{"scope": "db"|"files"|"full", "db_name": "..."}` dispatches the `backup.run`
capability and, only on success, persists a `backups` row (`apps/controlplane/backups.go`
`handleCreateBackup`, mirroring `handleCreateSite`'s "dispatch → parse result → insert
row" pattern). The archive is a checksummed local tar.gz on the VPS itself, with a
fixed internal layout (`manifest.json`, `db.sql`, `files/` — see
`packages/capabilities/backup.go`) so a later restore never has to guess where the
dump/files live inside it. `GET` on the same path lists a site's backups (and any
pre-restore checkpoints — see below), newest first.

**Restore** (implemented): `POST /api/v1/servers/{id}/backups/{backupId}/restore`
dispatches the `backup.restore` capability against a previously recorded backup — no
request body; the source archive, its expected checksum, and the restore destination
are all read from the stored record, never re-supplied by the caller. Before touching
anything, the agent verifies the archive's SHA-256 against the value recorded at
backup time (refusing a corrupted/tampered archive) and takes its own fresh checkpoint
backup of the destination's *current* state, so a bad restore is itself recoverable.
That checkpoint is persisted as an ordinary `backups` row
(`Status: "pre_restore_checkpoint"`) — it shows up in the same list as any other
backup, restorable the same way. See `SYSTEM.md` §12 and §19, and
`packages/capabilities/backup_test.go` for the files-scope round-trip test (the
db-scope path needs a live MariaDB to exercise for real — see `TESTING.md` §5).

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
