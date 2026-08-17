# Architecture

> **Status note:** this document was written before implementation began, as the
> pre-build architecture proposal. Phase 1 has since been built and the design held up
> well, with a few deliberate simplifications called out inline below (marked **As
> built**). For what's actually implemented today, see [`SYSTEM.md`](SYSTEM.md); this
> document remains the source of truth for the target architecture at full scale.

## 1. Component overview

```mermaid
flowchart LR
    subgraph Browser
        UI[Dashboard SPA]
    end

    subgraph ControlPlane["Control Plane (our infra)"]
        API[Public API\nREST/GraphQL + WS]
        AUTH[Auth service\nsessions, 2FA, RBAC]
        REG[Agent Registration\nservice]
        CA[Internal Agent CA\nstep-ca / self-managed PKI]
        GATE[Agent Gateway\nmTLS terminator + WS/gRPC fanout]
        JOBS[Job Queue / Workers\n(backups, deploys, installs)]
        AGG[Log/Metric Aggregator]
        DB[(Postgres)]
        Q[(Redis / Queue)]
        OBJ[(Object storage:\naudit export, agg. metrics)]
    end

    subgraph VPS1["Customer VPS #1 (Ubuntu 24.04)"]
        AG1[Server Agent\n(systemd service)]
        SVC1[nginx / php-fpm / mariadb\n/ redis / fail2ban / ufw]
    end

    subgraph VPS2["Customer VPS #2"]
        AG2[Server Agent]
        SVC2[...]
    end

    UI <-->|HTTPS + session/JWT| API
    API --> AUTH
    API --> JOBS
    API --> DB
    JOBS --> GATE
    GATE <-->|mTLS persistent conn| AG1
    GATE <-->|mTLS persistent conn| AG2
    AG1 --- SVC1
    AG2 --- SVC2
    REG --> CA
    AG1 -.->|one-time bootstrap| REG
    AG2 -.->|one-time bootstrap| REG
    AG1 -->|batched, aggregated| AGG
    AG2 -->|batched, aggregated| AGG
    AGG --> DB
    AGG --> OBJ
```

**As built:** Phase 1 has no Redis, no object storage, and no separate job-queue
process — the control plane is one binary backed by one SQLite file
(`modernc.org/sqlite`, pure Go, no cgo), and task dispatch is a synchronous
request/response over the gateway's persistent connection rather than an async queue.
This keeps local dev and a single-VPS control-plane deployment to "run one binary,
point it at one file," and is a straightforward swap to Postgres later (see
`db.go`) once multi-instance control-plane deployment is needed — every caller goes
through the `store` type's method set, never raw SQL, by design.

Key property: the **agent always initiates the outbound connection** to the control
plane (standard HTTPS/WSS egress, port 443). No inbound port needs to be opened on the
VPS for management traffic, so it works unmodified behind NAT/most provider firewalls
and doesn't require a cloud-provider API or console access.

## 2. Why "thin agent + control plane" over "full local panel"

See `docs/product-plan.md` §1 for the full comparison. The short version: a local panel
(Webuzo-style) is simpler to build per-server but doesn't scale operationally past a
handful of servers, and it maximizes attack surface per box (full UI + DB + auth stack
running on every customer VPS). A thin, capability-scoped agent minimizes what's exposed
per server while the control plane carries the complexity (UI, auth, orchestration,
billing later) in infrastructure we control and can patch centrally.

Critical design constraint: **hosted sites must keep serving traffic even if the control
plane is unreachable.** The agent is not a reverse proxy or dependency for request
serving — nginx/php-fpm/mariadb run as ordinary systemd services independent of the
agent's connection state. The agent's job is orchestration and observability, not
runtime traffic handling. On reconnect, the agent reports any drift and resumes queued
tasks.

## 3. Agent capability model (no arbitrary exec)

The agent process exposes an internal dispatch table of **named, versioned
capabilities**, each implemented as real Go code (not string-built shell commands),
e.g.:

| Capability | Example params | Implementation note |
|---|---|---|
| `stack.install` | `{profile: "phase1-lemp", version: "1.0"}` | Runs a pinned, idempotent install adapter; writes install report |
| `site.create` | `{domain, docroot, php_version, system_user}` | Creates isolated system user, php-fpm pool, nginx vhost from template |
| `site.set_php_version` | `{site_id, php_version}` | Validated against installed PHP versions only |
| `ssl.issue_letsencrypt` | `{domain}` | Invokes certbot/ACME client with fixed flags, no shell interpolation of user input |
| `service.control` | `{unit: "nginx", action: "restart"}` | `unit` restricted to an allow-list of managed systemd units |
| `db.create` | `{name, owner}` | Executes via MySQL client library with parameter binding, not raw SQL string concat |
| `cron.upsert` | `{schedule, command_id, user}` | `command_id` maps to a pre-registered, reviewed command template — not a free-text shell string |
| `firewall.apply_rules` | `{rules: [...]}` | Validated, dry-run diffed, applied via the commit-confirm flow (see security doc) |
| `backup.run` | `{scope: "db"\|"files"\|"full", target}` | Streams progress events back over the same channel |
| `backup.restore` | `{scope, backup_path, expected_sha256, site_root, db_name}` | Checksum-verified against the value recorded at backup time; takes a pre-restore checkpoint backup before any destructive step — see `SYSTEM.md` §19 |

Every capability call is logged (request + result) into the append-only audit log.
Capabilities are versioned so the control plane can detect an agent that doesn't yet
support a requested action and prompt an agent update instead of guessing.

There is intentionally **no `exec.run_command` capability**. Anything not covered by an
explicit capability is out of scope for the agent until a reviewed capability is added —
this is the mechanism that satisfies "must not offer arbitrary shell-command execution."

## 4. Task/RPC transport

- Transport: gRPC (bidirectional streaming) or WebSocket carrying a small
  protobuf/JSON-schema-defined envelope — either is fine; gRPC gives typed contracts and
  built-in mTLS support cheaply, so it's the default recommendation.
- Pattern: control plane enqueues a `Task{id, capability, params, not_before}`; agent
  acks receipt, executes, and streams `TaskEvent{task_id, status, progress, log_line}`
  back. Tasks are idempotent (safe to retry) and the agent persists an on-disk task
  journal so a task in progress survives an agent restart or reconnect.
- Heartbeats carry lightweight health/metrics snapshots (CPU/RAM/disk/load, service
  states) at a modest interval (e.g. 30–60s), independent of task traffic.

**As built:** the transport is a single persistent TLS 1.3 (`crypto/tls`,
`RequireAndVerifyClientCert`) TCP connection carrying newline-delimited JSON
`Envelope`s (`packages/proto`), not gRPC — this was simpler to implement with zero
extra dependencies and is easy to replace with gRPC later since `proto.Envelope`
already models the same Task/TaskEvent/Heartbeat/Hello shape a protobuf schema would.
The on-disk task journal for surviving an agent restart mid-task is **not yet
implemented** — a task in flight when the agent restarts is simply lost and must be
re-dispatched; this is called out in `SYSTEM.md`'s known-limitations section.

## 5. Data flow for logs/metrics (bandwidth-conscious)

Raw nginx/php/app logs are **not** shipped wholesale to the control plane. The agent:

1. Tails logs locally.
2. Aggregates into rollups (request counts by status code, top URLs, top IPs, error
   counts/samples, slow-request counts) over a short window (e.g. 1 minute).
3. Redacts obvious sensitive fields (auth headers, query-string tokens) before anything
   leaves the box.
4. Batches and compresses rollups, ships them on the existing control connection.
5. Keeps a configurable local raw-log retention window (for the in-agent log viewer /
   "advanced log monitoring" search) and never assumes the control plane is a full log
   warehouse.

## 6. Repo layout

Proposed layout at the time this document was first written:

```
/apps/dashboard        # Browser SPA (control-plane frontend)
/apps/api               # Public API + auth + orchestration (control plane backend)
/apps/gateway            # Agent-facing mTLS/gRPC gateway
/apps/agent              # Server agent (single static binary, Go)
/packages/proto          # Shared capability/task schema (protobuf or JSON schema)
/packages/ui             # Shared design system components
/infra                   # IaC for control-plane infra (Terraform/Ansible), CA setup
/docs                    # This documentation
```

**As built** (simpler than proposed — the public API and agent gateway turned out not
to need separate deployable processes for Phase 1, so they share one Go module and one
running binary, structured as two distinct types (`apiServer`, `gateway`) that could
still be split into separate processes later without a protocol change):

```
/apps/controlplane      # Public HTTP API (apiServer) + agent mTLS gateway (gateway),
                         # one binary; embeds the dashboard (web/index.html)
/apps/agent              # Server agent (single static binary, Go, stdlib + a
                         # Unix-socket MySQL driver)
/packages/capabilities   # The agent's fixed, allow-listed capability handlers
/packages/proto          # Shared Envelope/Task/TaskEvent/Heartbeat wire types
/docs                    # This documentation
```

No `/apps/dashboard` SPA and no `/packages/ui` exist — the dashboard is one
self-contained, dependency-free HTML/CSS/JS file (`apps/controlplane/web/index.html`),
a deliberate choice to avoid a frontend build pipeline for Phase 1 (see `SYSTEM.md`
§Frontend architecture for the rationale and its limits). There is no `/infra`
directory yet; control-plane deployment is currently "run the binary," documented in
`OPERATIONS.md` rather than codified as IaC.
