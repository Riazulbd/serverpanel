# API Reference

Two separate surfaces, on two separate listeners (see `ARCHITECTURE.md` §1):

1. **Public API** (`apiServer.routes()`, `apps/controlplane/http.go`) — browser-facing,
   plain HTTPS + session cookie, default `-api-addr=127.0.0.1:8080`.
2. **Agent gateway wire protocol** (`gateway`, `apps/controlplane/gateway.go`) — mTLS
   TCP, newline-delimited JSON `Envelope`s (`packages/proto`), default
   `-gateway-addr=127.0.0.1:8843`. Not HTTP.

All public-API request/response bodies are JSON. Error responses are always
`{"error": "<message>"}` with a non-2xx status.

## 1. Authentication

Session auth is an `HttpOnly`, `SameSite=Strict` cookie (`sp_session`), 12-hour TTL.
Every route except the ones listed under "Unauthenticated" below requires a valid,
non-expired session whose MFA requirement (if the account has 2FA enabled) is
satisfied — enforced by `requireAuth` (`auth.go`), applied identically to every
protected route; there is no route that skips it by omission.

### Unauthenticated
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/agents/register` | Agent bootstrap-token → certificate exchange (see below) |
| `POST` | `/api/v1/auth/signup` | Create the first/an account |
| `POST` | `/api/v1/auth/login` | Password login; returns `mfa_required` |
| `POST` | `/api/v1/auth/logout` | Clears the session |
| `POST` | `/api/v1/auth/mfa/challenge` | Submit a TOTP code to promote a login-only session to MFA-verified |
| `GET` | `/healthz` | Liveness check, returns `"ok"` |
| `GET` | `/` (and any other unmatched GET) | Dashboard HTML |

### Requires a valid session
| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/auth/me` | Current user (`user_id`, `email`) |
| `POST` | `/api/v1/auth/totp/enroll` | Issue a fresh TOTP secret + `otpauth://` URI |
| `POST` | `/api/v1/auth/totp/verify` | Confirm a code against the pending secret, enabling 2FA |
| `POST` | `/api/v1/servers` | Create a server record + one-time bootstrap token |
| `GET` | `/api/v1/servers` | List all servers |
| `GET` | `/api/v1/servers/{id}` | Get one server |
| `POST` | `/api/v1/servers/{id}/revoke` | Revoke the server's cert, force-disconnect, mark disconnected |
| `POST` | `/api/v1/servers/{id}/tasks` | Dispatch an arbitrary allow-listed capability (see §3) |
| `GET` | `/api/v1/servers/{id}/sites` | List sites on a server |
| `POST` | `/api/v1/servers/{id}/sites` | Dispatch `site.create` and persist the resulting site record |
| `GET` | `/api/v1/servers/{id}/sites/{siteId}/backups` | List backups for a site, newest first |
| `POST` | `/api/v1/servers/{id}/sites/{siteId}/backups` | Dispatch `backup.run` and persist the resulting backup record |
| `POST` | `/api/v1/servers/{id}/backups/{backupId}/restore` | Dispatch `backup.restore` for a previously recorded backup |
| `GET` | `/api/v1/servers/{id}/sites/{siteId}/cron` | Dispatch `cron.list`: live cron entries for the site's system user |
| `POST` | `/api/v1/servers/{id}/sites/{siteId}/cron` | Dispatch `cron.create`: add a cron entry |
| `PUT` | `/api/v1/servers/{id}/sites/{siteId}/cron/{cronId}` | Dispatch `cron.update`: change an entry's schedule/command/label |
| `DELETE` | `/api/v1/servers/{id}/sites/{siteId}/cron/{cronId}` | Dispatch `cron.delete`: remove an entry |
| `POST` | `/api/v1/servers/{id}/sites/{siteId}/cron/{cronId}/enable` | Dispatch `cron.set_enabled` (`true`) |
| `POST` | `/api/v1/servers/{id}/sites/{siteId}/cron/{cronId}/disable` | Dispatch `cron.set_enabled` (`false`) |
| `GET` | `/api/v1/audit` | Most recent 500 audit-log entries, newest first |

## 2. Request/response details

### `POST /api/v1/auth/signup`
```json
{"Email": "you@example.com", "Password": "at least 12 characters"}
```
→ `201 {"user_id": "...", "email": "..."}`. Password shorter than 12 chars, or an
already-registered email, → `400`.

### `POST /api/v1/auth/login`
```json
{"Email": "...", "Password": "..."}
```
→ `200 {"mfa_required": bool}` and sets the session cookie. Wrong email or password →
`401 {"error": "invalid email or password"}` — deliberately identical for both cases,
so the response never discloses whether an account exists.

### `POST /api/v1/auth/mfa/challenge`
```json
{"Code": "123456"}
```
Requires the `sp_session` cookie from a login where `mfa_required` was `true`. →
`200` and the session is promoted to MFA-verified. Wrong/expired code → `401`.

### `POST /api/v1/auth/totp/enroll` → `POST /api/v1/auth/totp/verify`
Two-step enrollment: enroll returns `{"secret": "...", "otpauth_uri": "otpauth://..."}`
(scan into an authenticator app); verify takes `{"Code": "123456"}` and, only on a
correct code, sets `totp_enabled = true` on the account and promotes the current
session to MFA-verified.

### `POST /api/v1/servers`
```json
{"Name": "web-1", "Group": "prod", "Tags": ["lemp"]}
```
→ `201 {"server_id": "...", "install_command": "curl ... | sudo bash -s -- ...", "token_expires_in_s": 900}`.
`install_command` embeds the plaintext bootstrap token — shown exactly once; it is
never retrievable again (the store only ever holds its hash).

### `POST /api/v1/servers/{id}/tasks`
```json
{"capability": "service.control", "params": {"unit": "nginx", "action": "restart"}}
```
Synchronously dispatches to the connected agent and blocks (up to 120s) for a terminal
`TaskEvent`. → `200` with the `TaskEvent` JSON (`task_id`, `status`, `message`,
`detail`, `at`) on any terminal outcome (`succeeded`/`failed`/`rejected` all return
`200` — check `status`, not the HTTP code, for the task's own outcome). Returns `502`
only for a transport-level failure (server not connected, context deadline exceeded).
See `SYSTEM.md` §12 for the full list of valid `capability` values.

### `POST /api/v1/servers/{id}/sites`
```json
{"domain": "example.com", "app_type": "wordpress", "php_version": "8.3"}
```
Dispatches `site.create`, and only on the agent reporting success, persists a `sites`
row. → `201 {"site": {...siteRecord}, "temp_domain": "<user>.<ip-with-dashes>.sslip.io"}`.
A dispatch failure or agent-side failure never leaves an orphan site record — the
row is written after (and only after) the agent confirms success.

### `POST /api/v1/servers/{id}/sites/{siteId}/backups`
```json
{"scope": "files", "db_name": ""}
```
`scope` is one of `db`, `files`, `full`; `db_name` is required when `scope` is `db` or
`full`. Dispatches `backup.run` with `site_root` taken from the site's own recorded
`docroot` (never caller-supplied), with a 20-minute dispatch timeout (backups of large
sites can run long). Only on the agent reporting success is a `backups` row persisted.
→ `201` with the `backupRecord` JSON (`ID`, `ServerID`, `SiteID`, `Scope`, `Path`,
`DBName`, `SizeBytes`, `SHA256`, `Status`, `CreatedAt`). `404` if the site doesn't exist
on that server; `400` for an invalid/missing scope; `502` if the agent isn't connected;
`422` if `backup.run` itself failed on the agent.

### `GET /api/v1/servers/{id}/sites/{siteId}/backups`
→ `200` with an array of `backupRecord`, newest first. `404` if the site doesn't exist
on that server.

### `POST /api/v1/servers/{id}/backups/{backupId}/restore`
No request body — the backup's own recorded `archive_path`, `scope`, `db_name`, and
`sha256` (as `expected_sha256`) are read from the `backups` table and passed to
`backup.restore` verbatim; a caller can only ever restore a backup that was actually
created and recorded, never point restore at an arbitrary path. For a `files`/`full`
scope backup, the owning site's current `docroot` is looked up fresh (not cached from
backup time) and passed as `site_root`. 20-minute dispatch timeout. → `200` with the
agent's `restoreResult` JSON (`scope`, `archive_path`, `checkpoints` — paths to the
pre-restore safety backups taken automatically before anything was overwritten,
`restored_at`). `404` if the backup doesn't exist on that server; `502` if the agent
isn't connected; `422` if `backup.restore` itself failed on the agent (the agent-side
error message explains why, and any checkpoint already taken is named in it so it's
never a silent loss).

### `GET /api/v1/servers/{id}/sites/{siteId}/cron`
Dispatches `cron.list` (30s timeout) and returns whatever the site's system user's
real crontab currently holds — there is no local cache, so this call requires the
server's agent to be connected. → `200` with an array of cron-entry JSON objects
(`id`, `label`, `schedule`, `command`, `enabled`). `404` if the site doesn't exist on
that server; `502` if the agent isn't connected; `422` if `cron.list` itself failed.

### `POST /api/v1/servers/{id}/sites/{siteId}/cron`
```json
{"schedule_preset": "daily", "command": "/usr/bin/php /home/sites/site_x/artisan schedule:run", "label": "Laravel scheduler", "enabled": true}
```
Either `schedule_preset` (one of `every_minute`, `hourly`, `daily`, `weekly`,
`monthly`) or a raw `schedule` (standard 5-field cron expression) is required — if
both are omitted, or `schedule_preset` names an unknown preset, or `command` is
missing, this is rejected with `400` before anything is dispatched. `label` and
`enabled` are optional (`enabled` defaults to `true`). The system user the entry is
created for is always the resolved site's own `system_user` — never a client-supplied
value, so a caller cannot target another site's or another user's crontab. Dispatches
`cron.create` (30s timeout); the agent independently re-validates the resolved
schedule and the command/label text (crontab-line-injection guards — see
`SYSTEM.md`/`SERVERAVATAR_PARITY.md` SRV-005), so a request that gets past this
endpoint's presence checks can still be rejected agent-side (`422`) by that deeper
validation. → `201` with the created cron-entry JSON (including the agent-generated
`id`). `404` if the site doesn't exist on that server; `502` if the agent isn't
connected.

### `PUT /api/v1/servers/{id}/sites/{siteId}/cron/{cronId}`
Same body shape as create (`schedule_preset`/`schedule`, `command`, `label`); replaces
those fields on the named entry without changing its enabled state (use the
enable/disable endpoints for that). → `200` with the updated cron-entry JSON. `400` for
missing/invalid schedule or command; `404` if the site doesn't exist on that server;
`422` if the agent reports the entry `id` doesn't exist in that user's crontab.

### `DELETE /api/v1/servers/{id}/sites/{siteId}/cron/{cronId}`
No request body. → `200 {"status": "deleted"}`. `404` if the site doesn't exist on
that server; `422` if the agent reports the entry `id` doesn't exist.

### `POST /api/v1/servers/{id}/sites/{siteId}/cron/{cronId}/enable` / `.../disable`
No request body — the target state is fixed by which of the two routes is called, not
read from the body. Disabling comments out the entry's schedule/command line in the
real crontab (cron never runs it) while preserving the exact command, rather than
deleting it — re-enabling restores it byte-for-byte. → `200` with the updated
cron-entry JSON. `404` if the site doesn't exist on that server; `422` if the agent
reports the entry `id` doesn't exist.

### `POST /agents/register`
```json
{"token": "<bootstrap token>", "csr_pem": "<PEM-encoded CSR>"}
```
The one call an agent can make with no client certificate — authenticated instead by
the single-use bootstrap token. → `200
{"server_id": "...", "cert_pem": "...", "ca_pem": "...", "gateway_addr": "..."}`.
Invalid/expired/already-used token → `401`, with a message that never echoes the
token value (see `SECURITY.md` §1).

## 3. Agent gateway wire protocol

Not REST. After the mTLS handshake (client cert required, verified against the
internal CA, checked against the revocation list — `gateway.handleConn`), the
connection carries newline-delimited JSON `Envelope`s in both directions
(`packages/proto/proto.go`):

```json
{"type": "hello", "hello": {"server_id": "...", "agent_version": "..."}}
{"type": "heartbeat", "heartbeat": {"sent_at": "...", "uptime_secs": 0, "load_avg_1": 0, "mem_used_pct": 0, "disk_used_pct": 0}}
{"type": "task", "task": {"id": "...", "capability": "...", "params": {}, "issued_at": "..."}}
{"type": "task_event", "task_event": {"task_id": "...", "status": "queued|running|succeeded|failed|rejected", "message": "...", "detail": "...", "at": "..."}}
{"type": "ack"}
```

Flow: gateway accepts → verifies cert → sends `ack` → agent sends `hello`, then
`heartbeat`s on its own interval → gateway may send a `task` at any time → agent
replies with one or more `task_event`s, the last one terminal
(`succeeded`/`failed`/`rejected`). The gateway's `dispatch()` blocks its caller (an
HTTP handler) until it sees a terminal event for the task ID it sent, or its context
deadline expires. There is no message type for a free-form command — `capability` must
be a name in `packages/capabilities`'s fixed registry, or the agent returns `rejected`
without executing anything.

## 4. Capability reference

The full allow-listed capability names `packages/capabilities.Default()` registers
(see `SYSTEM.md` §12 for the allow-list rationale): `system.ping`, `service.control`,
`diagnostics.basic`, `stack.install`, `site.create`, `site.set_php_version`,
`site.set_status`, `app.wordpress_install`, `ssl.issue_letsencrypt`,
`ssl.install_custom`, `db.create`, `db.delete`, `db.list`, `file.list`, `file.read`,
`file.write`, `file.delete`, `backup.run`, `backup.restore`, `logs.tail`, `cron.list`,
`cron.create`, `cron.update`, `cron.delete`, `cron.set_enabled`.

### `cron.list` / `cron.create` / `cron.update` / `cron.delete` / `cron.set_enabled`
All five take `system_user` (the site's own isolated system user — supplied by the
control plane from its stored site record, never accepted from an unauthenticated
client). `cron.list` takes nothing else and returns a JSON array of entries.
`cron.create` additionally takes `schedule` (a standard 5-field cron expression,
already resolved from any preset by the control plane), `command`, and optionally
`label`/`enabled` (default `true`); returns the created entry, including its
agent-generated `id`. `cron.update` takes `id`, `schedule`, `command`, `label` and
replaces those fields on the matching entry (its `enabled` state is untouched — that's
`cron.set_enabled`'s job). `cron.delete` takes `id`. `cron.set_enabled` takes `id` and
a boolean `enabled`. Every one of these reads the target user's crontab
(`crontab -u <user> -l`), applies the change to a parsed in-memory document that
preserves any other content in that crontab byte-for-byte, then writes the whole
document back (`crontab -u <user> -`) — never a blind append or in-place string edit.
`schedule` is validated field-by-field (5 fields, each within its numeric range);
`command`/`label` reject embedded newlines/carriage-returns/NUL bytes and an
unescaped `%` — the specific ways a caller-supplied string could otherwise break out
of its single crontab line into a forged, arbitrarily-scheduled entry (this is *not* a
shell-metacharacter blocklist: a cron command is handed to the user's shell by cron
itself, so `;`/`|`/`&&`/backticks are ordinary, expected cron usage). An entry that's
disabled keeps its exact schedule/command as a commented-out line rather than being
deleted, so re-enabling it is lossless. See `SERVERAVATAR_PARITY.md` SRV-005 for the
full design rationale and test coverage.

### `backup.restore`
```json
{"archive_path": "/var/backups/serverpanel/wpdb-full-20260101T000000Z.tar.gz",
 "scope": "full", "site_root": "/home/sites/site_example", "db_name": "wpdb",
 "expected_sha256": "<sha256 backup.run originally returned>"}
```
Restores a `backup.run` archive. `archive_path` must resolve to a file directly inside
the agent's backup directory (`/var/backups/serverpanel`) — never an arbitrary path.
If `expected_sha256` is supplied it's verified before any extraction happens.
Extraction uses Go's `archive/tar` directly (not a shelled-out `tar`), rejecting any
entry with an absolute path or one that would resolve outside the private extraction
directory, and skipping anything that isn't a plain file or directory (no symlinks,
hardlinks, or device nodes are ever written). Immediately before touching the live
database or site files, a fresh checkpoint backup of the *current* state is taken via
`backup.run` — its path is returned in the result's `checkpoints`, so a restore is
always recoverable, never a one-way trip. Returns
`{"scope", "archive_path", "checkpoints": [...], "restored_at"}` on success.
