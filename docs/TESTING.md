# Testing

## 1. Current automated coverage

`go test ./...` — 58 test functions across two packages, all passing, no `-race`
failures, `go vet` clean, `gofmt -l` clean:

```
go build ./...
go vet ./...
gofmt -l .          # should print nothing
go test ./...
go test ./... -race
```

| Package | Tests | What they cover |
|---|---|---|
| `apps/controlplane` | 25 | Auth/session lifecycle (create, MFA-verify, expiry, delete), bcrypt password rules, email normalization/uniqueness, TOTP round-trip/skew/rejection, bootstrap-token single-use/expiry/unknown-token, server create/list/get, revocation (cert-serial blocking + status transitions, including that a stray disconnect can't resurrect a revoked server), heartbeat recording, audit-log append, site create/list/get (including cross-server-ID isolation), backup create/list/get (including cross-server-ID isolation), and 5 full HTTP integration tests through `routes()` with `httptest` covering signup→login→protected-route, the full 2FA enroll→logout→login→MFA-challenge→access flow, server create/list/revoke, agent registration with a bad token, and the backup endpoints against a server with no connected agent (list-empty, create fails 502 without persisting a row, restore-unknown-ID 404s without dispatching) |
| `packages/capabilities` | 33 | Capability dispatch (unknown name rejected, `system.ping` works, nil `Progress` doesn't panic, the registry has a handler for every declared `Cap*` constant), `service.control`'s allow-list boundary (unit, action, and an explicit shell-metacharacter-injection attempt, all rejected before `systemctl` is ever invoked), the file manager's path-traversal and symlink-escape defenses (`resolveScopedPath`), oversized-read/write rejection, refusal to delete the site root itself, a real list+write round trip against a real filesystem, log redaction (token/password query params, `Authorization: Bearer`/`Basic`), `logs.tail`'s input validation, domain-name validation (including injection-shaped inputs), `systemUserForDomain`'s bounding/sanitization, the deterministic php-fpm-pool/socket/vhost path builders, and `backup.restore`'s validation (bad scope, archive path confinement including a `..`-traversal attempt, missing/mismatched checksum, unmanaged site root, an archive whose contents don't match the claimed scope) plus a real, non-mocked `backup.run` → mutate → `backup.restore` round trip for the `files` scope that also verifies the pre-restore checkpoint archive is itself valid and independently checksums correctly |

None of this is mocked where a cheap real implementation was possible: sessions/users/
servers/audit run against a real temp-file SQLite database with the real schema (not
`:memory:` with a fake driver); the file-manager tests create and traverse real
directories/symlinks under `/home/sites` (skipped gracefully if that path isn't
writable, so the suite still runs in an unprivileged container); the HTTP tests run the
real `routes()` mux with a real in-process CA and gateway, not a hand-rolled router
stub.

## 2. What's deliberately not covered by `go test`

Capabilities that require real system services this environment can't safely or
meaningfully fake are **not** exercised by the automated suite:
`stack.install` (apt/systemd), `app.wordpress_install` (real `wp-cli` + a running
MariaDB), `ssl.issue_letsencrypt` (real ACME/public DNS), `db.create/delete/list`
(a running MariaDB), the **`db`/`full`-scope paths of `backup.run`/`backup.restore`**
(real `mysqldump`/`mysql` client against a running MariaDB — the `files`-scope path of
both **is** covered by a real, non-mocked round-trip test, see §1), `service.control`'s
actual `systemctl` invocation, and the agent's registration/connect/reconnect loop
against a live gateway.

These were **manually verified against a real Ubuntu 24.04 host in a prior session**
(see `SYSTEM.md` §27 / the bug list below) — real `apt-get` installs, a manually
started MariaDB, a real WordPress install with actual DB tables, real file writes with
real ownership, a real signed backup archive, and the browser dashboard driven with a
real headless Chromium (Playwright) through signup → login → server creation → task
dispatch → site creation → audit log. That verification is not re-run automatically on
every change today — turning the manual integration pass into a scripted one (e.g. a
Docker-Compose-based Ubuntu container the test suite can provision against) is the
next testing investment worth making, tracked below.

## 3. What has never been verified in any environment

- `systemctl start/stop/restart` of installed services — this session's sandbox has no
  systemd as PID 1. The code path is a standard `systemctl <action> <unit>` argv
  invocation and should work unmodified on a real VPS, but hasn't been confirmed there.
- Let's Encrypt issuance — no public DNS points at any environment this project has
  been built/tested in.
- Agent behavior across a real network disconnect/reconnect cycle, a real VPS reboot,
  or a real control-plane restart while agents are live.
- The `db`/`full`-scope path of `backup.restore` (real `mysql`-client dump import)
  against a live MariaDB — validated by code review and the `files`-scope round trip
  sharing the same code path up to the database-specific step, but not run end-to-end
  against a real database in any environment this project has been built in.
- Restoring a backup onto a **different** server than the one that produced it — not
  implemented yet (§19 in `SYSTEM.md`), so not testable.
- Load/performance testing (dashboard CPU/memory under load, agent CPU/memory at idle
  and under task load, backup/restore throughput) — no measurements have been taken.
- Cross-server workflows (migration/cloning) — not applicable yet, since the feature
  itself isn't implemented (Phase 2).

## 4. Bugs found and fixed by testing (kept as evidence testing was real)

From the prior session's manual integration pass:
- Gateway's TLS certificate was missing IP SANs, so dialing by bare IP failed.
- Agent logged "connected" before the gateway had actually accepted the session.
- The CA was regenerated in memory on every control-plane start, silently invalidating
  every already-registered agent's certificate on restart — now persisted to disk.
- `stack.install`'s UFW step assumed an `OpenSSH` app profile that only exists if
  `openssh-server` happens to be installed; now allows the actual configured SSH port.
- Composer's "running as root" warning was being captured as its "version" in the
  install report; fixed via `COMPOSER_ALLOW_SUPERUSER=1`.
- MariaDB rejects a `?` placeholder inside `CREATE USER ... IDENTIFIED BY` over the
  prepared-statement protocol; fixed via `interpolateParams=true` (still safe,
  client-side escaping, not string concatenation).
- Generated nginx vhosts unconditionally included `listen [::]:80`, breaking
  `nginx -t` on any host with IPv6 disabled — now probed at runtime.
- The stock nginx default site has the same unconditional IPv6 listener; disabled.
- Enough vhosts accumulating broke nginx's default `server_names_hash_bucket_size`;
  now set generously up front.
- `site.create` succeeding was never persisted as a site record; added a dedicated
  endpoint that dispatches the task and only then writes the record.
- Agent-reported version was logged but never saved onto the server record.
- Heartbeats only ever populated uptime; load/memory/disk were implemented via
  `/proc/loadavg`, `/proc/meminfo`, and `syscall.Statfs`.

From this session's `backup.restore` implementation pass:
- `backup.run`'s output filename had only second-resolution granularity
  (`20060102T150405Z`), so two backups of the same site/database within the same
  second silently overwrote each other on disk. This surfaced as a real, reproducible
  failure in `TestHandleBackupRunThenRestoreFilesRoundTrip`: the pre-restore checkpoint
  (itself a `backup.run` call) collided with the very archive `backup.restore` was
  about to read, overwriting it with the *corrupted* current state before extraction —
  so the "restore" silently restored the corruption instead of the original backup.
  Fixed by adding a random 4-byte hex suffix to every backup filename, which closes
  the general "two backups of the same thing in the same second" collision class, not
  just the checkpoint-vs-original case that happened to be exercised by the test.

This session's automated-test pass otherwise found **no new defects** in the
pre-existing code — every other test passed on the first correctly-written attempt,
which is consistent with (not independent proof beyond) the prior manual pass having
been genuine.

## 5. Known gaps / recommended next testing investment, in priority order

1. **`backup.restore`'s `db`/`full`-scope path against a real MariaDB instance** — the
   `files`-scope path is now covered by a real round-trip test (§1); the
   database-import step (`mysql` client + `ensureDatabaseExists`) still needs the same
   treatment against a live MariaDB, plus a restore-to-a-different-server scenario once
   that feature exists (§19 in `SYSTEM.md`).
2. **Scripted real-VPS/container integration tests** — turn the manual pass in §2 into
   a repeatable script (a disposable Ubuntu 24.04 Docker container or cloud-init VM),
   runnable in CI, covering the installation-test checklist in the project brief
   (agent install → register → stack install → site create → WordPress deploy →
   DB create → SSL issue → file ops → backup → restore → agent restart → network
   disconnect/reconnect → failed-install recovery → upgrade → rollback → revoke).
3. **Load/failure testing of agent reconnect** under real network partition
   conditions (not just the backoff-loop code review already done).
4. **`govulncheck`/dependency vulnerability scanning** wired into a CI pipeline (none
   exists yet).

## 6. Browser and mobile testing

Run manually (not yet wired into `go test`, since it needs a running binary + a
headless browser — see "next testing investment" §5 for scripting this into CI):

1. Build and run the control plane against a scratch SQLite DB/CA dir:
   `go build -o /tmp/serverpanel-cp ./apps/controlplane && /tmp/serverpanel-cp -db
   /tmp/sp-test/test.db -ca-dir /tmp/sp-test/ca -api-addr 127.0.0.1:8081 -gateway-addr
   127.0.0.1:8082 -insecure-cookies`.
2. Drive it with Playwright (Chromium) through signup → login → create server → open
   server detail → every tab (Servers/Audit Log/Security) → the new-site and
   new-backup modals, at each of 320/375/390/414/768/1280px, checking
   `document.documentElement.scrollWidth - document.documentElement.clientWidth <= 1`
   (i.e. no horizontal overflow) after each navigation.

Last run (this session): all six widths × six views (servers list, server detail,
audit log, security, new-site modal, new-backup modal) — zero horizontal overflow.
Found and fixed one real bug in the process: `header.topbar` had no `flex-wrap`, so on
narrow viewports the session info (email + sign-out button) overflowed the page
instead of wrapping to a second line — confirmed with `getBoundingClientRect()` on the
widest offending element, not just visual inspection. Fixed with `flex-wrap: wrap` on
the topbar and `min-width: 0` + `text-overflow: ellipsis` on the email span (a flex
item needs an explicit `min-width: 0` to actually shrink/truncate below its content
width — the parent alone isn't enough). Also added a shared `.table-scroll` class
(`overflow-x: auto`) around every table (server list, sites, backups, audit log) so
a wide table scrolls within its own card rather than the page scrolling horizontally,
per the project's mobile-responsiveness requirement. Touch-target sizing, screen-reader
labeling, and keyboard navigation were not part of this pass — still open, see
`SYSTEM.md` §21.

## 7. Running the suite

```
go build ./...          # both binaries
go vet ./...
gofmt -l .               # expect no output
go test ./...             # ~4s
go test ./... -race        # ~50s
go test ./... -cover        # per-package coverage summary
```

No test requires network access or a running MariaDB/nginx. The file-manager tests
need `/home/sites` to be creatable (root, or an already-writable path) — they call
`t.Skip` rather than fail if it isn't, so the suite stays green in an unprivileged CI
runner while still exercising the real filesystem where it can.
