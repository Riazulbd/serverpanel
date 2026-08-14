# Implementation Status

What actually exists in this repo today, as working and tested code — kept separate
from `product-plan.md` (the target roadmap) so this document can stay a plain, current
snapshot rather than aspirational.

## What's implemented

**Control plane** (`apps/controlplane`, Go, stdlib `net/http` + SQLite):
- Public HTTP API with session-cookie auth (bcrypt) and TOTP 2FA (RFC 6238, implemented
  directly against `crypto/hmac`/`crypto/sha1`, no third-party OTP library).
- A separate mTLS-only agent gateway on its own port, backed by an internal CA
  (`crypto/x509`) that issues short-lived (30-day) client certificates.
- The CA's key and every server/user/token/audit record persist in SQLite
  (`modernc.org/sqlite`, pure Go, no cgo) so a control-plane restart does not invalidate
  already-registered agents or lose state — this was a real bug caught and fixed during
  integration testing (see below).
- Server CRUD, single-use/short-lived bootstrap tokens, revocation, task dispatch, an
  append-only audit log, and a site-creation endpoint that persists what an agent
  reports back after `site.create` succeeds.
- A self-contained embedded browser dashboard (`apps/controlplane/web/index.html`, no
  build step, no framework) — login/signup, 2FA enrollment, server list with
  search/filter, server detail with live heartbeat stats and one-click actions, a site
  list/create flow, and an audit log view.

**Agent** (`apps/agent`, Go, stdlib only + a Unix-socket MySQL driver):
- Bootstrap-token registration, persistent reconnecting mTLS session, real heartbeats
  (uptime, 1-minute load average, memory-used %, disk-used % via `/proc` and `statfs`).
- A fixed capability registry (`packages/capabilities`) — no shell-exec entry point
  exists in the protocol or the agent. Capabilities implemented and exercised against a
  real Ubuntu 24.04 host in this session:
  - `system.ping`, `diagnostics.basic`, `service.control` (allow-listed units/actions)
  - `stack.install` (`phase1-lemp` profile: nginx, php8.3-fpm + extensions,
    mariadb-server, redis-server, git, composer, wp-cli, certbot, ufw, fail2ban) —
    idempotent, safely retryable, writes a version report
  - `site.create` / `site.set_status` — isolated system user, `open_basedir` +
    disabled-functions php-fpm pool, nginx vhost, automatic `sslip.io` temp domain
  - `app.wordpress_install` — real `wp-cli` core download/config/install as the site's
    own unprivileged user via `runuser`'s argv form (never a shell string)
  - `ssl.issue_letsencrypt` (certbot, nginx plugin) / `ssl.install_custom`
  - `db.create` / `db.delete` / `db.list` — least-privilege per-database MariaDB grants
  - `file.list` / `file.read` / `file.write` / `file.delete` — scoped to a site's own
    directory, with symlink-escape and path-traversal defenses
  - `backup.run` — checksummed local tar.gz (db dump and/or files)
  - `logs.tail` — redacts tokens/passwords/Authorization headers before returning lines

## What's been genuinely tested, and how

Everything above was exercised end-to-end against this session's own Ubuntu 24.04
container — real `apt-get` installs, a manually-started MariaDB, a real WordPress
install with actual database tables, real file writes with real ownership, a real
signed backup archive — not just unit-level or mocked. The browser dashboard was driven
with a real headless Chromium (Playwright) through signup → login → server creation →
task dispatch → site creation → audit log, not just visually inspected.

Bugs this testing found and fixed (kept here because they're evidence the testing was
real, not because they're still open):
- Gateway's TLS certificate was missing IP SANs, so dialing by bare IP failed.
- Agent logged "connected" before the gateway had actually accepted the session.
- **The CA was regenerated in memory on every control-plane start, silently
  invalidating every already-registered agent's certificate on restart.** Now persisted
  to disk and loaded back, with the serial counter reseeded from the DB's own records.
- `stack.install`'s UFW step assumed an `OpenSSH` app profile that only exists if
  `openssh-server` happens to be installed; it now allows the actual configured SSH port
  instead.
- Composer's "running as root" warning was being captured as its "version" in the
  install report; fixed by setting `COMPOSER_ALLOW_SUPERUSER=1`.
- MariaDB rejects a `?` placeholder inside `CREATE USER ... IDENTIFIED BY` over the
  prepared-statement protocol; fixed via `interpolateParams=true` (still safe,
  client-side escaping, not string concatenation).
- Generated nginx vhosts unconditionally included `listen [::]:80`, which breaks
  `nginx -t` outright on any host with IPv6 disabled — now probed at runtime.
- The stock Ubuntu nginx package's own default site has the same unconditional IPv6
  listener; `stack.install` now disables that placeholder site.
- Once enough vhosts (each contributing a real domain *and* a generated temp domain to
  `server_name`) accumulate, nginx's default `server_names_hash_bucket_size` is too
  small and breaks config testing for the whole server; `stack.install` now sets it
  generously up front.
- `site.create` succeeding was never actually persisted as a site record — the
  dashboard's site list was always empty. Added a dedicated
  `POST /servers/{id}/sites` endpoint that dispatches the task and only then writes
  the record.
- Agent-reported version was logged to the audit trail but never actually saved onto
  the server record, so the dashboard always showed "—".
- Heartbeats only ever populated uptime; load/memory/disk were left at zero because
  nothing collected them. Implemented via `/proc/loadavg`, `/proc/meminfo`, and
  `syscall.Statfs`.

What is **not** independently verified in this environment (documented rather than
glossed over): `systemctl start/stop/restart` of the installed services, since this
sandbox has no systemd as PID 1 — the code path is the standard `systemctl <action>
<unit>` invocation and should work unmodified on a real VPS, but a real systemd host is
the next place to confirm that specifically. Let's Encrypt issuance likewise can't be
tested here (no public DNS pointing at this box).

## Known gaps vs. the Phase 1 target (see `product-plan.md`)

- No teams/RBAC (single-user model only, as scoped for the MVP).
- No remote/object-storage backups (local only, as scoped for Phase 1).
- No push-to-deploy/Git deployment yet (Phase 2 per the roadmap).
- The in-process CA is a real, working PKI (persisted, correctly bound identities,
  correctly enforced revocation) but is not yet the "dedicated, tightly
  access-controlled service" called for in `security-trust-model.md` §2 — that
  separation is an infra decision for when this moves toward production, not a code
  change.
- SQLite (not Postgres) backs the control plane for now; the `store` type's method set
  is the only thing any caller touches, so this is a swap, not a rewrite, when it's time.
- No automated test suite yet — verification so far is the manual integration pass
  described above. Adding `go test` coverage (especially around the capability
  allow-list boundaries and the auth/session logic) is worth prioritizing next.

## Running it locally

```
go build -o controlplane ./apps/controlplane
go build -o agent ./apps/agent

# terminal 1
./controlplane -api-addr=127.0.0.1:8080 -gateway-addr=127.0.0.1:8843 \
  -db=./serverpanel.db -insecure-cookies
# -insecure-cookies is for plain-HTTP local dev only; omit it (the default) whenever
# the dashboard is served over TLS.

# browser: http://127.0.0.1:8080/  → create the first admin account, add a server,
# copy the install command it shows you.

# terminal 2, on the box you want to manage (root):
./agent -api=http://127.0.0.1:8080 -token=<from the install command> \
  -data-dir=/etc/serverpanel-agent -register-only
./agent -data-dir=/etc/serverpanel-agent   # long-running
```
