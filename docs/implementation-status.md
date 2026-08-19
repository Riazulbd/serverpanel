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
- The install command shown by the dashboard was hardcoded to placeholder domains
  (`get.serverpanel.example`, `api.serverpanel.example`) that don't exist — the one-line
  install flow was not actually installable. Fixed: see "Self-hosted install flow" below.

Two further bugs were found later by the automated test suite (see "Tests" below), both
in `systemUserForDomain`, both confirmed against a real Ubuntu host:
- **Site creation was broken outright for longer domains.** The derived name was
  `"site_"` (5 chars) + up to 28 = up to 33 characters, and Ubuntu's `useradd` *rejects*
  names over 32 rather than truncating them (`invalid user name ... use --badname to
  ignore`), so `site.create` failed for any domain past that length.
- **Distinct domains could collide onto one system user, silently removing the isolation
  boundary between two sites.** Sanitizing folds both `.` and `-` to `_`, so
  `foo-bar.com` and `foo.bar.com` — plausibly two different customers — both produced
  `site_foo_bar_com`; truncation of long domains caused the same collision. Two sites
  sharing a system user share a PHP-FPM pool and file ownership, which is precisely the
  isolation the security model depends on. Names now always carry a short hash of the
  full domain, keeping them unique and within the 32-character limit. Verified on a real
  host: the two domains above now get separate Linux users with separate, mutually
  inaccessible home directories.

## Self-hosted install flow (now real, not just designed)

`install.sh`, the systemd unit, and the agent binary itself are now all served by the
control plane at its own `-public-url` (`GET /install.sh`, `GET
/downloads/serverpanel-agent.service`, `GET
/downloads/serverpanel-agent-linux-{amd64,arm64}[.sha256]` —
`apps/controlplane/downloads.go`) — there's no separate release host to stand up or keep
in sync. `handleCreateServer` builds the install command from `-public-url` instead of a
placeholder. `scripts/build-agent-releases.sh` cross-compiles the agent for both
architectures into a directory the control plane serves from (`-agent-binaries-dir`,
default `./dist`).

This was verified for real, not just wired up: built real release binaries, started the
control plane with `-public-url` pointing at itself, created a server through the API to
get a real install command, and ran the **exact** `curl -fsSL .../install.sh | sudo bash
-s -- ...` a user would copy-paste — not a bypassed/manual equivalent. It ran the
compatibility checks, downloaded the real binary, verified its checksum ("OK"),
registered, and only stopped at the systemd step (`daemon-reload`), which fails here
because this sandbox has no systemd as PID 1 — the same documented limitation as
everywhere else in this file, not a new one. Starting the installed binary manually
confirmed it connects and the dashboard shows it live.

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
- Test coverage is focused on security boundaries and pure logic (see "Tests" below).
  The capability handlers' *effects* on a real system — apt installs, systemd calls,
  certbot — are still covered by manual integration testing rather than automated tests,
  since they need a real VPS to be meaningful.

## Tests

`go test -race ./...` — run in CI (`.github/workflows/ci.yml`, which also enforces
`gofmt`, `go vet`, cross-compiles the agent, and shellchecks the installer).

The suite deliberately targets the security boundaries and the pure logic behind them,
which is where a silent regression would be both most likely and most damaging:

- **Capability allow-list** — the registry is pinned to an exact reviewed set (a new
  capability appearing without review fails the test), no capability name may look like
  an execution entry point, unknown names are rejected by `Dispatch`, and
  `service.control` refuses non-allow-listed units (including `sshd`) and actions.
- **File-manager containment** — path traversal, symlinks planted inside a site pointing
  out of it, symlinked parent directories, and unmanaged `site_root` values are all
  rejected; deleting the site root itself is refused.
- **Input validation** — SQL identifier and domain allow-lists (with injection attempts),
  WordPress docroot confinement, log-tail selectors, backup scopes, SSL params.
- **System-user derivation** — length bound and, importantly, collision-freedom, since a
  collision means two sites share an isolation boundary.
- **Log redaction** — tokens, passwords, API keys, and `Authorization` headers are
  stripped, while ordinary log lines pass through untouched.
- **Bootstrap tokens** — single-use (including under 16-way concurrency, which is what
  the "atomically" claim in the security model actually rests on), expiry, hash-only
  storage, and absence from the audit log.
- **Auth** — every protected route rejects anonymous and forged sessions, login errors
  don't reveal whether an account exists, passwords are bcrypt-hashed, logout and expiry
  invalidate sessions, and a 2FA-enabled account's password-only session is blocked
  until it passes the challenge (and is *not* promoted by a failed one).
- **TOTP** — validated against the published RFC 6238 test vectors, so real
  authenticator apps interoperate rather than the implementation merely agreeing with
  itself; plus skew-window bounds in both directions.
- **PKI / mTLS** — the CA stamps identity from the validated `server_id` so an agent
  can't claim another server's identity via its CSR; issued certs are client-auth-only
  and non-CA; serials are unique and reseeded above known-max after a restart; the CA
  survives restart (the regression that once invalidated every agent); and, over a real
  TLS listener, the gateway accepts enrolled agents while rejecting revoked
  certificates and certificates from an untrusted CA.
- **Downloads** — the unauthenticated `/downloads/` endpoint refuses path traversal, and
  the served checksum actually matches the served binary.

## Running it locally

```
go build -o controlplane ./apps/controlplane
go build -o agent ./apps/agent
scripts/build-agent-releases.sh   # cross-compiles the agent into ./dist for install.sh to serve

# terminal 1
./controlplane -api-addr=127.0.0.1:8080 -gateway-addr=127.0.0.1:8843 \
  -public-url=http://127.0.0.1:8080 -agent-binaries-dir=./dist \
  -db=./serverpanel.db -insecure-cookies
# -public-url must be an address the target VPS can actually reach — for anything
# beyond same-machine local dev, that's your real domain/IP, not 127.0.0.1.
# -insecure-cookies is for plain-HTTP local dev only; omit it (the default) whenever
# the dashboard is served over TLS.

# browser: http://127.0.0.1:8080/  → create the first admin account, add a server,
# copy the install command it shows you — it's now a real, runnable command:
#   curl -fsSL <public-url>/install.sh | sudo bash -s -- --server=... --token=... --api=...

# on the actual VPS you want to manage (root), just run that copied command. Or, for
# local dev without a second machine, do what it does by hand:
./agent -api=http://127.0.0.1:8080 -token=<from the install command> \
  -data-dir=/etc/serverpanel-agent -register-only
./agent -data-dir=/etc/serverpanel-agent   # long-running
```
