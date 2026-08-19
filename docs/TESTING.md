# Testing

## 1. Current automated coverage

`go test ./...` — 87 test functions across three packages, all passing, no `-race`
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
| `apps/controlplane` | 35 | Auth/session lifecycle (create, MFA-verify, expiry, delete), bcrypt password rules, email normalization/uniqueness, TOTP round-trip/skew/rejection, bootstrap-token single-use/expiry/unknown-token, server create/list/get, revocation (cert-serial blocking + status transitions, including that a stray disconnect can't resurrect a revoked server), heartbeat recording, audit-log append, site create/list, `getSite`'s cross-server scoping, backup create/list/get round trip and its own cross-server scoping, database create/list/get/delete round trip and its own cross-server scoping, `commitCertRenewal`'s atomic adopt-new/revoke-old transaction, 4 certificate-rotation integration tests against a **real mTLS gateway listener, real CA, and real database** (a full request→sign→confirm→revoke round trip verifying the successor is bound to the same server identity, uses a new serial, and that nothing changes before the agent confirms; refusal of a second renewal on one session; refusal to renew a revoked certificate; and that an unsolicited renewal acknowledgement revokes nothing), and 8 full HTTP integration tests through `routes()` with `httptest` covering signup→login→protected-route, the full 2FA enroll→logout→login→MFA-challenge→access flow, server create/list/revoke, agent registration with a bad token, the backup endpoints' not-found boundaries, backup-request validation (bad scope, missing `db_name`, and confirming validation runs before dispatch), the database endpoints' empty-list/not-found boundaries, and database-name validation (confirming an injection-shaped name is rejected before dispatch, and before any password is generated) |
| `apps/agent` | 5 | Certificate-expiry parsing (including rejection of empty/malformed/non-certificate PEM), that each renewal generates a genuinely fresh keypair and a self-consistent CSR, and `persistRenewedIdentity`'s durability properties against a real filesystem: files replaced with 0600 preserved, no temporary file left behind, and — the property the whole renewal ordering depends on — the previous identity left intact and usable when the new one can't be written |
| `packages/capabilities` | 47 | Capability dispatch (unknown name rejected, `system.ping` works, nil `Progress` doesn't panic, the registry has a handler for every declared `Cap*` constant), `service.control`'s allow-list boundary (unit, action, and an explicit shell-metacharacter-injection attempt, all rejected before `systemctl` is ever invoked), the file manager's path-traversal and symlink-escape defenses (`resolveScopedPath`), oversized-read/write rejection, refusal to delete the site root itself, a real list+write round trip against a real filesystem, log redaction (token/password query params, `Authorization: Bearer`/`Basic`), `logs.tail`'s input validation, domain-name validation (including injection-shaped inputs), `systemUserForDomain`'s bounding/sanitization, the deterministic php-fpm-pool/socket/vhost path builders, `backup.run`'s scope validation and a real files-backup-and-checksum round trip, and `backup.restore`'s archive-location/checksum validation, a real files backup→corrupt→restore round trip (with a real throwaway system user, verifying both content restoration and pre-restore checkpoint creation), and `extractTarGzSafely`'s rejection of path-traversal entries, absolute-path entries, and oversized archives, plus `db.create`/`db.delete`'s pre-connection input validation (invalid database name, invalid owner user, under-length owner password) and `ValidIdentifier`'s boundary cases (leading digit/uppercase, spaces, punctuation, and exactly-at vs. one-over the 31-character cap), `validSystemUser`'s path-traversal rejection (a regression test for a real defect — see §4) including that every name `systemUserForDomain` generates passes its own validation, and custom-SSL validation against **real generated X.509 material**: a matching pair accepted, a mismatched certificate/key pair rejected, an expired certificate rejected, a certificate not covering the domain rejected, and that no validation error ever echoes the submitted key material |

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
MariaDB), `ssl.issue_letsencrypt` (real ACME/public DNS), `db.create/delete/list`'s
actual SQL execution (a running MariaDB — their input validation, which runs entirely
before the connection is opened, *is* covered), `service.control`'s actual `systemctl`
invocation, and the agent binary's own reconnect-with-backoff loop against a live
gateway (agent *enrollment*, mTLS *session establishment*, and certificate *rotation*
are covered for real by `gateway_test.go`; what isn't is the long-running
process-level retry behavior across a genuine network partition). `backup.run`'s and
`backup.restore`'s **files** scope are exercised for real (real files, real archive,
real throwaway system user, real `chown`); their **db**/**full** scope (real
`mysqldump`/`mysql` against a running MariaDB) is not — this environment doesn't run
MariaDB, so those paths remain in the same manually-verified-in-a-prior-session bucket
as the rest of this list.

These were **manually verified against a real Ubuntu 24.04 host in a prior session**
(see `SYSTEM.md` §28 / the bug list below) — real `apt-get` installs, a manually
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
- Dashboard mobile responsiveness at 320/375/390/414/768px — no browser-automation
  screenshot pass has been run against the dashboard in this session. The dashboard is
  plain HTML/CSS with no fixed-width layout assumptions spotted on inspection, but
  "should be responsive" is not the same claim as "verified responsive," and this
  should not be reported as done until it's actually been checked with real viewport
  screenshots.
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

This session's automated-test pass (see §1) found **no new defects** — every test
passed on the first correctly-written attempt, which is consistent with (not
independent proof beyond) the prior manual pass having been genuine.

Found by code review while extending SSL support (2026-08-19), each now covered by a
regression test:

- **Path traversal to arbitrary root-level file operations.** `system_user` is
  interpolated directly into nginx/php-fpm/TLS config paths, but was validated only by
  `strings.HasPrefix(sysUser, "site_")`. A value like
  `site_../../../../etc/nginx/sites-enabled/evil` satisfies that check and still
  escapes the directory it is joined to — so `site.set_status` would `os.Remove` or
  `os.Symlink` an attacker-chosen path, as root, reachable through the authenticated
  task-dispatch API. Replaced with a strict `^site_[a-z0-9_]{1,28}$` allow-list
  (`validSystemUser`), applied everywhere the value reaches a path.
- **`ssl.install_custom` reported success without installing anything.** It wrote the
  certificate and key to a directory, then ran `nginx -t` — which passed precisely
  because nothing referenced those files — and reported "custom certificate
  installed". No vhost ever served the certificate. It now validates the material,
  generates a real TLS server block, and rolls back if nginx rejects the result.
- **No verification that a certificate and key actually match.** A mismatched pair was
  accepted and would only surface at nginx reload, with the site already down.
- **Let's Encrypt certificates had no guaranteed renewal.** Nothing enabled
  `certbot.timer`, so whether a certificate ever renewed depended on the base image —
  a 90-day outage with a delayed fuse. Now enabled at stack-install time and
  re-verified at issuance, with the outcome surfaced to the operator.
- **Data race on the agent's connection encoder.** Heartbeat and task goroutines shared
  one `json.Encoder` with no synchronization; two interleaved encodes emit a corrupt
  frame that desynchronizes the session. Now mutex-guarded (`sender`).

## 5. Known gaps / recommended next testing investment, in priority order

1. **Backup restore is unit- and integration-tested (`packages/capabilities/backup_test.go`,
   `apps/controlplane/store_test.go`, `apps/controlplane/http_test.go`) but not yet
   exercised against a real, systemd-managed MariaDB + real site directory on an actual
   Ubuntu VPS** — the automated suite covers path/checksum validation, tar-extraction
   safety, and a full files-scope restore round trip against real files and a real
   throwaway system user; it does not cover a real `mysqldump`/`mysql` round trip
   (this environment's MariaDB, if any, is not exercised by these tests) or
   restore-to-a-different-server (not yet implemented — see `SYSTEM.md` §22).
2. **Scripted real-VPS/container integration tests** — turn the manual pass in §2 into
   a repeatable script (a disposable Ubuntu 24.04 Docker container or cloud-init VM),
   runnable in CI, covering the installation-test checklist in the project brief
   (agent install → register → stack install → site create → WordPress deploy →
   DB create → SSL issue → file ops → backup → agent restart → network
   disconnect/reconnect → failed-install recovery → upgrade → rollback → revoke).
3. **Browser/mobile end-to-end tests** — Playwright driving the dashboard at each of
   the 320/375/390/414/768/desktop breakpoints, checking for horizontal overflow,
   clipped content, and usable touch targets, screenshotted for review.
4. **Load/failure testing of agent reconnect** under real network partition
   conditions (not just the backoff-loop code review already done).
5. **`govulncheck`/dependency vulnerability scanning** wired into a CI pipeline (none
   exists yet).

## 6. Running the suite

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
