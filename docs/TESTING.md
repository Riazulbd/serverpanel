# Testing

## 1. Current automated coverage

`go test ./...` — 62 test functions across two packages, all passing, no `-race`
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
| `apps/controlplane` | 27 | Auth/session lifecycle (create, MFA-verify, expiry, delete), bcrypt password rules, email normalization/uniqueness, TOTP round-trip/skew/rejection, bootstrap-token single-use/expiry/unknown-token, server create/list/get, revocation (cert-serial blocking + status transitions, including that a stray disconnect can't resurrect a revoked server), heartbeat recording, audit-log append, site create/list, `getSite`'s per-server scoping, backup create/list/get and their per-server scoping, and 6 full HTTP integration tests through `routes()` with `httptest` covering signup→login→protected-route, the full 2FA enroll→logout→login→MFA-challenge→access flow, server create/list/revoke, agent registration with a bad token, backup-creation request validation (bad scope / missing site_id / missing db_name all rejected before dispatch, a validly-shaped request against a disconnected server failing at dispatch with 502, never persisting a row), and restore-of-an-unknown-backup returning 404 |
| `packages/capabilities` | 35 | Capability dispatch (unknown name rejected, `system.ping` works, nil `Progress` doesn't panic, the registry has a handler for every declared `Cap*` constant), `service.control`'s allow-list boundary (unit, action, and an explicit shell-metacharacter-injection attempt, all rejected before `systemctl` is ever invoked), the file manager's path-traversal and symlink-escape defenses (`resolveScopedPath`), oversized-read/write rejection, refusal to delete the site root itself, a real list+write round trip against a real filesystem, log redaction (token/password query params, `Authorization: Bearer`/`Basic`), `logs.tail`'s input validation, domain-name validation (including injection-shaped inputs), `systemUserForDomain`'s bounding/sanitization, the deterministic php-fpm-pool/socket/vhost path builders, `backup.run`/`backup.restore` scope validation, `validateBackupPath`'s traversal/symlink-escape defenses (mirroring `resolveScopedPath` for the fixed `backupBaseDir`), restore's checksum-mismatch rejection, and a real end-to-end `backup.run` → mutate → `backup.restore` → verify round trip for the `files` scope (real `tar`, real filesystem, confirms the pre-restore checkpoint archive is written and that restored content matches the original exactly) |

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
registration/connect/reconnect loop against a live gateway. `backup.run`'s `files` scope
and `backup.restore`'s `files`-scope round trip *are* now covered for real (this
environment has `tar` and runs as root, both of which those need) — see §1. Their
`db`/`full` scopes (the `mysqldump`/`mysql` path) remain untested here: this
environment has neither `mysqldump` nor `mysql` installed, so
`TestBackupRunRestoreFullRoundTripRequiresMySQL` skips itself rather than silently
passing.

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
- `backup.run`/`backup.restore`'s `db` and `full` scopes end-to-end against a live
  MariaDB (the `mysqldump`/`mysql` binaries aren't available in this environment — see
  §2). The `files` scope's real tar-based round trip *has* been verified (§1); the
  extraction/restore mechanics that scope shares with `db`/`full` (archive validation,
  checksum check, pre-restore checkpoint, path resolution) are exercised, but the
  `mysqldump`/`mysql` invocations themselves are not.
- Load/performance testing (dashboard CPU/memory under load, agent CPU/memory at idle
  and under task load, backup/restore throughput) — no measurements have been taken.
- Cross-server workflows (migration/cloning, and cross-server backup restore) — not
  applicable yet, since the feature itself isn't implemented (Phase 2).

## 4. Mobile responsiveness verification

Verified this session with real headless-Chromium (Playwright) automation against a
running control-plane instance — not a code-inspection guess. Signed up, logged in,
created a server, opened the server-detail view (stats grid, actions, sites table,
backups table, the "run backup" modal), and checked every tab (Servers, Audit Log,
Security) and the pre-login auth screen, at each of 320/375/390/414/768/1024px, by
asserting `document.documentElement.scrollWidth <= clientWidth` (no horizontal page
scroll) at every one. Screenshotted the 375px server-detail view for visual review.

**First pass failed** at 320px and 375px: the topbar (brand + nav tabs + account/sign-out)
didn't wrap and the auth card had a hard `width: 360px`, both overflowing a 320–375px
viewport; the servers/sites/backups tables also overflowed the page itself instead of
scrolling within their own box. Fixed (`apps/controlplane/web/index.html`): `header.topbar`
and `nav.tabs` gained `flex-wrap`; `.auth-card` and `.center-screen` got a `max-width`/
padding so the login card can't exceed the viewport; every table (static and
JS-rendered) is now wrapped in a `.table-wrap` (`overflow-x: auto`) container, so a wide
table scrolls horizontally within its own card instead of forcing the whole page to.
Re-ran the same checks after the fix: **no overflow at any of the six breakpoints, on
any view.**

Not yet covered by this pass: the in-browser code editor (doesn't exist yet — see
`SYSTEM.md` §2 "Application management"), the log viewer's filtering/search UI (same),
and touch-target-size auditing beyond "buttons are the same tappable size as desktop" —
no dedicated touch-target-size assertion was scripted. A scripted version of this same
Playwright flow (rather than an ad hoc script run once) is still worth adding as a
checked-in test — see §6.

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

From this session's work on `backup.restore`:
- `backup.run`'s output filename used only second-granularity timestamps
  (`20060102T150405Z`), so two backups of the same site/scope started within the same
  wall-clock second could collide on one output path and silently overwrite each other.
  This was latent in `backup.run` alone but became a real, easily-triggered bug once
  `backup.restore` started calling it internally for a pre-restore checkpoint — a
  checkpoint taken moments after the backup being restored would land on the same
  filename and overwrite the very archive the restore was mid-way through reading. Caught
  by `TestBackupRunRestoreFilesRoundTrip` (it failed on first run: restored content came
  back as the *post-mutation* state, not the original). Fixed by adding a random 4-byte
  hex suffix to every backup filename (`randSuffix()`), making a collision require an
  actual random-number collision rather than just fast sequential calls.
- The dashboard's topbar/auth-card/tables overflowed at narrow viewports — see §4.

This session's automated-test pass (see §1) found the two defects above; the prior
session's manual integration pass found the ones listed before them. Both are kept in
one list because both are real, testing-discovered bugs, not hypothetical ones.

## 6. Known gaps / recommended next testing investment, in priority order

1. **Scripted real-VPS/container integration tests** — turn the manual pass in §2 into
   a repeatable script (a disposable Ubuntu 24.04 Docker container or cloud-init VM),
   runnable in CI, covering the installation-test checklist in the project brief
   (agent install → register → stack install → site create → WordPress deploy →
   DB create → SSL issue → file ops → backup → restore → agent restart → network
   disconnect/reconnect → failed-install recovery → upgrade → rollback → revoke). This
   is also the only way to get `backup.restore`'s `db`/`full` scopes past "code review +
   files-scope round trip" (§2/§3) to a real, live-MariaDB-verified state.
2. **Checked-in browser/mobile end-to-end tests** — turn the ad hoc Playwright script
   used for §4 into a real test (Go's `testing` package shelling out to a small Node/
   Playwright harness, or an equivalent), so viewport-overflow regressions are caught by
   `go test` / CI rather than requiring another manual pass.
3. **Load/failure testing of agent reconnect** under real network partition
   conditions (not just the backoff-loop code review already done).
4. **`govulncheck`/dependency vulnerability scanning** wired into a CI pipeline (none
   exists yet).

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
