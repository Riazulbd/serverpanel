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
| `GET` | `/api/v1/servers/{id}/backups` | List backups recorded for a server |
| `POST` | `/api/v1/servers/{id}/backups` | Dispatch `backup.run` and persist the resulting backup record |
| `POST` | `/api/v1/servers/{id}/backups/{backupId}/restore` | Dispatch `backup.restore` for a previously-recorded backup |
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
{"domain": "example.com", "app_type": "wordpress", "php_version": "8.3",
 "admin_email": "you@example.com", "admin_user": "admin", "site_title": "My Site"}
```
Dispatches `site.create`, and only on the agent reporting success, persists a `sites`
row. → `201 {"site": {...siteRecord}, "temp_domain": "<user>.<ip-with-dashes>.sslip.io"}`.
A dispatch failure or agent-side failure never leaves an orphan site record — the
row is written after (and only after) the agent confirms success.

`admin_email` is **required** when `app_type` is `wordpress` (→ `400` without it) and
ignored otherwise; `admin_user` defaults to `admin` and `site_title` to the domain. For
`app_type=wordpress`, this endpoint additionally chains `db.create` and
`app.wordpress_install` after `site.create` succeeds, generating a least-privilege
database plus a random admin password, and returns them once:

```json
{"site": {...}, "temp_domain": "...",
 "wordpress": {"db_name": "wp_a1b2c3d4e5f6", "admin_user": "admin", "admin_password": "<generated>"}}
```

The admin password and DB credentials are **not persisted anywhere** in the control
plane (there is no databases table yet) — this response is the only time they are
shown, the same treatment `POST /api/v1/servers` gives the bootstrap token. If a
chained step fails, the response is still `201` but carries
`{"wordpress_error": "..."}` instead of `wordpress` — the site itself already exists at
that point and there is no automatic rollback of a successful `site.create`, so the
caller is told the site exists *and* that the WordPress layer on top of it needs a
retry, rather than being given a misleading error for the whole call.

### `POST /api/v1/servers/{id}/backups`
```json
{"site_id": "site_abc123", "scope": "files", "site_root": "/home/sites/sp_abc123/public", "db_name": ""}
```
`site_id` is optional (only used to associate the backup record with a site for
listing purposes); `scope` is required (`db`/`files`/`full`); `site_root` is required
for `files`/`full`, `db_name` for `db`/`full` — same validation `backup.run` itself
applies. Dispatches `backup.run`, and only on success, persists a `backups` row
(including the `site_root`/`db_name` used, so a later restore doesn't need them
re-supplied). → `201` with the `backupRecord` JSON. `502` for a transport-level
dispatch failure (e.g. server not connected) — no row is written in that case.

### `GET /api/v1/servers/{id}/backups`
→ `200` with an array of `backupRecord` (`ID`, `ServerID`, `SiteID`, `SiteRoot`,
`DBName`, `Scope`, `Path`, `SizeBytes`, `SHA256`, `Status`, `CreatedAt`), newest first.

### `POST /api/v1/servers/{id}/backups/{backupId}/restore`
No request body — every parameter `backup.restore` needs (`scope`, `backup_path`,
`site_root`, `db_name`, `sha256`) is read from the backup record itself, not from the
caller, specifically so a restore request can't be pointed at a different site's data
than the one the archive actually came from. → `404` if the backup ID isn't found for
this server; `502` for a transport-level dispatch failure; `422` if the agent reports
the restore itself failed (e.g. its own pre-restore checkpoint failed, or a checksum
mismatch was detected); `200 {"restored": {...backupRecord}, "detail": {...}}` on
success, where `detail` is `backup.restore`'s own result (including
`checkpoint_detail`, the pre-restore checkpoint backup that was taken automatically).

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
