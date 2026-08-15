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
| `apps/controlplane` | 25 | Auth/session lifecycle (create, MFA-verify, expiry, delete), bcrypt password rules, email normalization/uniqueness, TOTP round-trip/skew/rejection, bootstrap-token single-use/expiry/unknown-token, server create/list/get, revocation (cert-serial blocking + status transitions, including that a stray disconnect can't resurrect a revoked server), heartbeat recording, audit-log append, site create/list/get (including that a site is unreachable via a different server's ID), backup create/list/get, and 5 full HTTP integration tests through `routes()` with `httptest` covering signup→login→protected-route, the full 2FA enroll→logout→login→MFA-challenge→access flow, server create/list/revoke, agent registration with a bad token, and the backups endpoints' validation/not-found paths (missing scope, `db` scope without `db_name`, `files` scope without `site_id`, restoring an unknown backup ID) without requiring a live agent connection |
| `packages/capabilities` | 33 | Capability dispatch (unknown name rejected, `system.ping` works, nil `Progress` doesn't panic, the registry has a handler for every declared `Cap*` constant), `service.control`'s allow-list boundary (unit, action, and an explicit shell-metacharacter-injection attempt, all rejected before `systemctl` is ever invoked), the file manager's path-traversal and symlink-escape defenses (`resolveScopedPath`), oversized-read/write rejection, refusal to delete the site root itself, a real list+write round trip against a real filesystem, log redaction (token/password query params, `Authorization: Bearer`/`Basic`), `logs.tail`'s input validation, domain-name validation (including injection-shaped inputs), `systemUserForDomain`'s bounding/sanitization, the deterministic php-fpm-pool/socket/vhost path builders, and `backup.restore`'s validation (archive path confined to `backupBaseDir`, `..`-traversal rejected, invalid scope rejected, missing archive rejected, checksum mismatch rejected before extraction) plus a **real end-to-end `backup.run` → corrupt-the-file → `backup.restore` → verify-original-content-came-back** round trip through real `tar`/`cp` (not mocked) that caught a genuine collision bug — see §4 |

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
(a running MariaDB), `service.control`'s actual `systemctl` invocation, and the agent's
registration/connect/reconnect loop against a live gateway. `backup.run`/
`backup.restore`'s **files** scope *is* exercised end-to-end with real `tar`/`cp`
(this sandbox has those tools); their **database** scope (`mysqldump`/`mysql`) is not,
since no MariaDB is installed here — that half of both capabilities remains manually-
verified-only (`backup.run`'s dump step was verified in the prior session per §4 below;
`backup.restore`'s `mysql`-import step has not yet been verified against a real
MariaDB instance at all, automated or manual — see §3).

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
- `backup.restore`'s database scope (`mysql <db_name> < dump.sql`) — no MariaDB
  instance is installed in this sandbox. The files scope of the same capability *has*
  been verified end-to-end (§1); the db scope's logic (locating the `.sql` file inside
  the extracted archive) is covered in isolation by
  `TestFindFileWithSuffixAndFindSiteFilesDir`, but the actual `mysql` import has not.
- Agent behavior across a real network disconnect/reconnect cycle, a real VPS reboot,
  or a real control-plane restart while agents are live.
- Restoring a backup to a *different* server than the one it was taken on — the
  `backup.restore` capability's file-lookup logic (`findSiteFilesDir`) is written to
  support this (it locates the archived site directory by tree structure, not by
  matching name — see `SYSTEM.md` §19), but no test exercises an actual two-agent
  cross-server restore.
- Load/performance testing (dashboard CPU/memory under load, agent CPU/memory at idle
  and under task load, backup/restore throughput on a realistically large site or
  database) — no measurements have been taken.
- Cross-server workflows (migration/cloning) — not applicable yet, since the feature
  itself isn't implemented (Phase 2).
- The Security tab and every modal dialog (new server, new site, DB backup) at mobile
  widths — the mobile-responsiveness pass in §1/§4 covered the login screen, server
  list, server detail (including the new Backups section), and audit log, but not
  every screen in the app.

## 4. Mobile responsiveness

Verified with real Playwright browser automation (headless Chromium) driving the live
dashboard at 320/375/390/414/768/1280px, checking `document.documentElement.scrollWidth
> clientWidth` (i.e. actual horizontal overflow, not a visual guess) at each width, on:
the login screen, the server list, server detail (stats, actions, sites, and the new
Backups section), and the audit log. All six widths passed cleanly *after* a fix — see
the bug below. Not covered by this pass: the Security tab and the three modal dialogs
(new server, new site, database backup) — see §3.

**Bug found and fixed**: at 320–414px, the topbar (`header.topbar`) didn't wrap, so the
email address + sign-out button ran off the right edge and forced page-level horizontal
scroll; separately, `.auth-card`'s fixed `width: 360px` exceeded a 320px viewport
outright. Fixed by making the topbar `flex-wrap`, giving the auth card `max-width: 90vw`
(matching the pattern the modal dialogs already used), and wrapping the two tables that
are nested inside the server-detail card (sites, backups) in their own
`overflow-x: auto` containers so a table needing more width than the viewport scrolls
independently instead of blowing out the whole page
(`apps/controlplane/web/index.html`).

## 5. Bugs found and fixed by testing (kept as evidence testing was real)

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
- **(This session)** `backup.run`'s output filename used a second-resolution timestamp
  only. A `backup.restore` pre-restore checkpoint runs a fresh `backup.run` moments
  after reading the archive it's about to restore from; if both happened within the
  same UTC second (easily true in an automated test, and not impossible in production
  under load) they produced the *same* filename, so the checkpoint silently overwrote
  the original archive with corrupted (post-modification) contents mid-restore. Caught
  by `TestHandleBackupRestoreFilesScopeRoundTrip` failing with the restored content
  matching the *corrupted* state instead of the original. Fixed by appending a random
  hex suffix to every backup filename (`randHex` in `packages/capabilities/backup.go`),
  which also makes concurrent `backup.run` calls collision-safe generally, not just for
  this one restore-checkpoint interaction.
- **(This session)** Dashboard mobile layout: topbar overflow and an oversized
  fixed-width auth card at ≤414px — see §4.

This session's automated-test pass (see §1) found the two new defects listed above,
both while writing new tests for backup.restore and the mobile-responsiveness pass
respectively — both fixed and now covered by regression tests/checks, consistent with
(not independent proof beyond) the project's stated "every bug found gets a regression
test" policy.

## 6. Known gaps / recommended next testing investment, in priority order

1. **Scripted real-VPS/container integration tests** — turn the manual pass in §2 into
   a repeatable script (a disposable Ubuntu 24.04 Docker container or cloud-init VM
   with MariaDB actually installed), runnable in CI, covering the installation-test
   checklist in the project brief (agent install → register → stack install → site
   create → WordPress deploy → DB create → SSL issue → file ops → backup → **restore**
   → agent restart → network disconnect/reconnect → failed-install recovery → upgrade →
   rollback → revoke). This is now the single highest-value next step: it would close
   the `backup.restore` database-scope gap (§3) and the cross-server-restore gap (§3)
   in one pass, alongside everything else on that checklist.
2. **Load/failure testing of agent reconnect** under real network partition
   conditions (not just the backoff-loop code review already done).
3. **`govulncheck`/dependency vulnerability scanning** wired into a CI pipeline (none
   exists yet).
4. **Mobile coverage of the remaining screens** — the Security tab and the three modal
   dialogs (§3), plus touch-target sizing and keyboard/screen-reader navigation, which
   this session's overflow-only check did not assess.

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
