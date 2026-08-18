# Product & Architecture Plan

Pre-implementation deliverable covering the ten items requested before building begins.
Deeper technical detail lives in [`architecture.md`](architecture.md) and
[`security-trust-model.md`](security-trust-model.md); this document focuses on the
product/business framing and decisions.

---

## 1. Local-only vs. centralized multi-server architecture

| | **Local-only panel** (Webuzo-style, installed per server) | **Centralized control plane** (ServerAvatar-style, this project) |
|---|---|---|
| Onboarding | Install full panel per server; each has its own login | Create server in dashboard → run one install command → agent registers |
| Visibility across fleet | None natively; user checks each server separately | Single dashboard: search/filter/group across all servers |
| Consistent security policy | Configured per server, drifts over time | Enforced/audited centrally, one source of truth |
| Attack surface per VPS | Large — full UI, DB, auth stack exposed on every box | Small — thin agent, no UI/DB, no arbitrary exec |
| Cross-server actions (clone, migrate) | Not possible without manual scripting | Native: control plane orchestrates both ends |
| Upgrades | Per-server, easy to fall behind | Central release, agents pull signed updates |
| Works if control plane is down | N/A (no control plane) | Sites must still serve — see below |
| Works behind NAT / no public IP for management | Yes trivially (it's local) | Yes — agent makes outbound-only connection |
| Build complexity | Lower per-server, but no fleet features ever | Higher upfront (auth, multi-tenancy, agent protocol) but scales operationally |

**Recommendation: centralized control plane**, matching the requested direction, with
one non-negotiable design constraint carried through every layer: **the control plane is
an orchestration/observability layer, not a runtime dependency.** nginx/php-fpm/mariadb
keep serving traffic under systemd whether or not the agent's connection to the control
plane is up. This gets most of the local-panel's resilience while keeping the
centralized model's operational advantages.

## 2. Recommended control-plane and agent architecture

Summary (full detail + diagrams in `architecture.md`):

- **Control plane**: multi-tenant backend (API + auth + job queue + Postgres) that the
  browser talks to over normal authenticated HTTPS/WebSocket, and an **agent gateway**
  that terminates mutually-authenticated agent connections separately from the public
  API surface.
- **Agent**: a single static binary (Go recommended — no runtime deps, easy to
  cross-compile and checksum/sign, small footprint) running as a systemd service. It
  exposes a **fixed, versioned set of allow-listed capabilities** (install stack, manage
  a site, control an approved service, issue a cert, etc.) — never a generic
  shell-exec RPC.
- **Transport**: agent-initiated outbound persistent connection (gRPC or WSS over mTLS)
  so no inbound port needs opening on the VPS and no cloud-provider API is required to
  reach it.
- **Data flow discipline**: metrics/log data is aggregated and redacted on the agent
  before batched transmission — raw logs are not hauled to the control plane wholesale.

## 3. Server-agent security and trust model

Summary (full detail + sequence diagrams in `security-trust-model.md`):

- Bootstrap tokens are single-use, short-lived (~15 min), stored only as salted hashes,
  never written to permanent logs, and are exchanged exactly once for a durable
  certificate-based identity.
- Ongoing agent↔control-plane auth is **mutual TLS** with short-lived, auto-rotating
  client certificates signed by an internal Agent CA; renewal is authenticated by the
  current cert, never a shared long-lived secret.
- Revocation is immediate and one-directional: a revoked server must go through full
  re-registration with a fresh token to regain trust.
- Each hosted application is isolated at the OS level (own system user, PHP-FPM pool,
  DB grants) so a compromised app cannot reach another app's data.
- Any SSH/firewall change that could cause lockout uses a mandatory
  apply → hold → confirm-or-auto-rollback sequence, timed locally on the agent so it
  fires even if the risky change itself severed the control-plane connection.
- Diagnostics only *propose* fixes; applying one is an explicit, audited, user-approved
  action — never automatic.

## 4. Expected infrastructure cost (operating the central platform)

Rough MVP-stage estimate (dozens of orgs, up to a few hundred connected agents), all
figures monthly and provider-agnostic (DigitalOcean/Hetzner-class pricing):

| Component | Estimate |
|---|---|
| App/API servers (2x, for HA) | $40–80 |
| Agent gateway (can co-locate with API initially) | included above, split out later |
| Managed Postgres (HA + backups) | $50–150 |
| Redis / job queue | $15–30 |
| Object storage (audit export, aggregated metrics/log rollups) | $5–20 |
| Transactional email (2FA codes, alerts) | $0–20 |
| Monitoring/observability (self-hosted or hosted) | $0–50 |
| Static frontend hosting / CDN | $0–10 |
| Internal PKI / Agent CA (self-managed, e.g. step-ca) | ~$0 (shares existing compute) |
| **Total** | **~$150–400/mo** |

This scales sub-linearly at first (control plane cost is dominated by fixed HA
infrastructure, not per-agent cost) until the fleet reaches roughly the low thousands of
concurrently-connected agents, at which point the main cost drivers become:
persistent-connection fan-out (horizontally scaling the agent gateway), Postgres
IOPS/storage, and aggregated log/metric storage volume. None of this requires
committing to a specific cloud provider for the *product* — customers' VPS servers can
be anywhere; this is only the cost of the control plane itself, which we do host.

## 5. Data-retention and privacy plan

- **Raw logs stay on the VPS.** The control plane receives aggregated, redacted rollups
  (request counts, status-code breakdowns, top URLs/IPs, error samples, slow-request
  flags), not full log lines, by default.
- **Retention windows** (configurable per org/plan, sane defaults):
  - Metrics: 30–90 days raw, downsampled/discarded beyond that.
  - Aggregated logs: 14–30 days.
  - Audit log: kept longer (e.g. 1 year) since it's low-volume and compliance-relevant;
    audit entries are append-only and cannot be edited, only retention-expired.
  - Deployment history: kept per plan (e.g. last N releases, or indefinitely on paid
    tiers).
  - Backups: stored on the VPS itself initially (Phase 1); the control plane stores only
    backup *metadata* (timestamp, size, checksum, verification result), not backup
    contents, until remote object-storage integration ships (Phase 2+).
- **Secrets** (DB credentials, deploy keys, env vars, agent certs) are encrypted at rest
  with envelope encryption; audit-log entries redact secret values by field allow-list,
  not by best-effort deny-list.
- **Data export/delete**: an org can request full export and deletion of its data;
  deleting an org cascades to de-registering and revoking all its agents.
- **PII minimization**: IP addresses in aggregated logs are the main PII surface; make
  IP retention/anonymization period configurable, and never ship request bodies or auth
  headers off-box.

## 6. Detailed milestone estimates

Assuming a small focused team (~1 backend/control-plane engineer, 1 systems/agent
engineer, 1 frontend engineer, blended; adjust linearly for a bigger/smaller team).
Estimates in engineer-weeks of effort, not calendar weeks (parallelizable across the
three tracks).

### Phase 1 — Secure working foundation

| Milestone | Est. (eng-weeks) |
|---|---|
| Control-plane skeleton: auth, orgs, sessions, 2FA (TOTP) | 3 |
| Agent CA + registration flow (bootstrap token → mTLS identity) | 3 |
| Agent binary skeleton: systemd service, task loop, heartbeat, capability dispatch | 3 |
| Server CRUD + dashboard shell (list, search, filter, groups/tags) | 2 |
| Compatibility/security pre-check on registration (OS, resources, conflicting software) | 2 |
| Phase-1 stack installer (nginx/php-fpm/mariadb/redis/git/composer/wp-cli/ACME/ufw/fail2ban) with pre-install report, progress, safe retry | 5 |
| Site/app model: system-user isolation, php-fpm pool per app, docroot, temp domain | 4 |
| WordPress / custom PHP / static-site one-click install | 3 |
| Let's Encrypt SSL issuance + renewal | 2 |
| Basic database management (create DB/user, scoped grants) | 2 |
| Basic file manager (scoped to app's isolated user, no arbitrary path escape) | 3 |
| Monitoring basics: CPU/RAM/disk/load, service health, agent heartbeat/version status | 3 |
| Local backups (db/files/full, scheduled, local storage) | 3 |
| Log viewer + basic diagnostics (read-only checks, plain-language findings) | 3 |
| Audit trail (append-only, covers all privileged actions) | 2 |
| Agent safe-update mechanism (signature-verified self-update) | 2 |
| Hardening, security review, load/failure testing of agent reconnect logic | 3 |
| **Phase 1 subtotal** | **~44 eng-weeks** (~4–5 months with a 3-person team working in parallel) |

### Phase 2 — Professional server management

| Milestone | Est. (eng-weeks) |
|---|---|
| Git deployment (public + deploy-key private repos), branch/build-dir config, deploy scripts, history/logs, rollback | 5 |
| Webhook push-to-deploy (GitHub/GitLab/Bitbucket signature verification) | 2 |
| Staging environments + application cloning | 3 |
| Cron job management (approved command templates, execution history) | 2 |
| Process/worker management via systemd (queue workers, restart policies) | 3 |
| UFW + Fail2Ban management UI, SSH/SFTP management, commit-confirm safety flow | 4 |
| Automated OS security updates (unattended-upgrades integration + reporting) | 2 |
| Advanced monitoring/alerts (thresholds; Email + Telegram + generic Webhook notification channels only — product decision 2026-08-18, Slack/Discord/Pushover out of scope) | 3 |
| Advanced log search UI (filters, top URLs/IPs, suspicious-traffic indicators) | 3 |
| Remote backups — **Amazon S3 only** (product decision 2026-08-18; not a pluggable multi-provider adapter) | 2 |
| Cross-server app migration/cloning | 3 |
| **Phase 2 subtotal** | **~33 eng-weeks** (~3–4 months) |

### Phase 3 — Commercial platform

> **Product decision (2026-08-18): white-label, reseller/self-hosted panel, and
> billing/wallet/subscriptions are out of scope for this product entirely** — not
> deferred, removed from the roadmap. The rows below are struck through and kept only
> so this document's history stays honest about what was originally scoped and why it
> changed; see `SERVERAVATAR_PARITY.md` §2 "White-label / Reseller" and "Billing" for
> the corresponding parity-tracker entries (marked `INTENTIONALLY_NOT_APPLICABLE`).

| Milestone | Est. (eng-weeks) |
|---|---|
| Organizations/teams, custom roles, granular (server/app/db) permissions | 5 |
| Team audit logs, temporary/expiring access | 2 |
| ~~White-label (branding, custom domain), customer-facing limited panel~~ — descoped 2026-08-18 | ~~5~~ |
| ~~Reseller accounts, hosting packages, usage limits~~ — descoped 2026-08-18 | ~~4~~ |
| ~~Billing/subscriptions~~ — descoped 2026-08-18 | ~~4~~ |
| Cloud-provider integrations (provisioning VPS via provider APIs) | 4 |
| Additional stack adapters (Node.js, Laravel, n8n, Mautic, OpenLiteSpeed, Apache) | 6+ (per-adapter, incremental) |
| Public API + plugin system | 5 |
| **Phase 3 subtotal** | **~16+ eng-weeks** (down from ~35+ after the 2026-08-18 descoping), and open-ended as adapters/integrations grow |

These are effort estimates, not calendar commitments — actual calendar time depends on
team size, review cadence, and how much security review/pen-testing is built into the
schedule (recommended: a dedicated external security review before Phase 1 GA, given the
root-on-customer-infrastructure trust model).

## 7. MVP cost estimate

"MVP" here = Phase 1 only, to first paying-ready release.

- **Engineering**: ~44 eng-weeks of effort. At a blended fully-loaded contractor/employee
  rate of roughly $80–150/hr (varies hugely by market/seniority), that's roughly
  **$140,000–$260,000** if built by hired engineers, or 4–5 months of a 3-person team's
  time if built in-house with existing staff (opportunity cost rather than new cash
  spend).
- **Infrastructure during MVP build + early access**: ~$150–250/mo (lower end of the
  §4 estimate — no need for full HA/scale infra until real customer load arrives).
- **Third-party/one-time**: a pre-GA external security review of the agent trust model
  and registration flow is strongly recommended given the "root access on customer
  servers" trust profile — budget for a focused pentest engagement
  (order of magnitude $10,000–$25,000 depending on scope/provider) before onboarding
  real customer servers beyond a closed beta.
- **Total order-of-magnitude MVP cost**: roughly **$150k–$290k** if fully outsourced/
  hired, materially less if built by existing in-house staff where the main cost is
  calendar time, not new spend. Treat this as a planning range, not a quote — refine
  once team composition and rates are known.

## 8. Major security risks

1. **Agent compromise → lateral movement.** A compromised agent has privileged access to
   its own VPS. Mitigation: capability allow-list (no generic exec), per-app OS-level
   isolation so damage doesn't spread *within* the box, and no agent-to-agent trust (each
   agent only trusts the control plane, never peers).
2. **Control plane as a high-value single point of compromise.** Since it can dispatch
   privileged tasks to every connected agent, a control-plane compromise is the
   worst-case scenario. Mitigation: separate the Agent CA signing authority from the
   general app tier, strong RBAC/2FA on control-plane admin access, audit every
   privileged dispatch, rate-limit and anomaly-detect unusual task patterns (e.g. one
   compromised account suddenly issuing destructive tasks fleet-wide).
3. **Bootstrap-token leakage.** Shoulder-surfing, shell history, screen recordings of the
   install command. Mitigation: short TTL (~15 min), single-use, token never printed to
   persistent shell history by default (documented as a one-time copy/paste command),
   and the token alone can only *register*, never gain ongoing access on its own.
4. **Supply-chain risk on agent binary/updates.** Mitigation: signed releases, agent
   verifies signature before self-updating (§ security doc), reproducible builds as a
   later hardening step.
5. **SSH/firewall misconfiguration lockout.** Mitigation: mandatory commit-confirm
   rollback flow (§ security doc) for any connectivity-risking change.
6. **Malicious/compromised hosted application escaping isolation** (e.g. via PHP
   `exec()`, symlink attacks, writable shared paths). Mitigation: per-app system user,
   `open_basedir`, disabled dangerous PHP functions by default, isolated DB grants,
   regular review of the isolation boundary as new app types are added in Phase 2/3.
7. **Secrets sprawl** across env vars, deploy keys, DB credentials. Mitigation: envelope
   encryption at rest, field-level redaction in audit logs, scoped deploy keys instead of
   stored Git passwords (explicit product requirement already).
8. **Denial of service via the agent gateway** (fleet-wide persistent-connection
   fan-out is a concentrated target). Mitigation: connection-level rate limiting,
   horizontal scaling design from day one even if not needed at MVP scale.
9. **Certificate authority compromise.** Mitigation: isolate CA signing key access,
   short-lived certs limit blast radius of a leaked (not CA-level) key, revocation list
   checked on every handshake.
10. **Confused-deputy risk in the capability protocol itself** (e.g. a capability's
    parameters being loosely validated enough to be repurposed maliciously — the classic
    way "allow-listed" systems quietly regain arbitrary-exec). Mitigation: strict
    schema validation per capability, no capability that takes a raw path/command
    string without allow-listing/templating it, security review of every new capability
    before it ships.

## 9. Features that should be postponed

Consistent with the phase plan already given, explicitly calling out what stays out of
Phase 1:

- Git deployment, push-to-deploy, staging/cloning (Phase 2 — Phase 1 ships direct
  file/one-click deploy only).
- Cron/process/worker management (Phase 2).
- Firewall/Fail2Ban *management UI* and SSH/SFTP management, automated OS updates
  (Phase 2) — Phase 1 installs and runs Fail2Ban/UFW with safe defaults but doesn't yet
  expose full rule-editing UI.
- Advanced monitoring/alerting thresholds beyond basic up/down + resource display —
  Phase 1 is email + in-dashboard only. Phase 2 adds exactly three external channels —
  **Email, Telegram, and a generic outbound Webhook** — per product decision
  2026-08-18; Slack, Discord, and Pushover are intentionally out of scope, not
  deferred.
- Remote/object-storage backups — Phase 1 is local-storage only. Phase 2 adds exactly
  one remote target — **Amazon S3** — per product decision 2026-08-18; this is not a
  pluggable multi-provider adapter, and R2/B2/Spaces/Wasabi/Google Drive/Dropbox are
  intentionally out of scope, not deferred.
- Cross-server application migration/cloning (Phase 2).
- Teams, roles, granular permissions, temporary access — single-user MVP first.
- **White-label, custom domains/branding, reseller accounts, hosting packages, and
  billing/subscriptions are out of scope for this product entirely** (product decision
  2026-08-18) — not a later phase, removed from the roadmap. See §6's Phase 3 table
  note above and `SERVERAVATAR_PARITY.md`.
- Cloud-provider VPS provisioning integrations — Phase 1 works against any existing
  clean Ubuntu VPS with no provider API.
- Additional stacks (OpenLiteSpeed, Apache, Node.js, Laravel, n8n, Mautic) and their
  application types — architecture should support pluggable stack/app adapters from day
  one, but only the Phase 1 LEMP stack + WordPress/PHP/static apps actually ship in the
  first release.
- Public API and plugin system — Phase 3, once the core product and its own internal API
  have proven stable.
- Configurable WAF beyond basic safe defaults, hardware-key 2FA (start TOTP-only),
  IP allow-listing beyond a basic form — nice-to-haves that can follow once core
  security primitives (isolation, mTLS, audit log) are solid.

## 10. Questions requiring product-owner decisions

1. ~~**Pricing/packaging model**~~ — **resolved 2026-08-18**: not applicable. Billing/
   subscriptions were descoped from this product entirely (see §6 Phase 3 note, §9),
   so no org/billing data model is needed.
2. ~~**Self-hosted/on-prem control plane offering / reseller panel**~~ — **resolved
   2026-08-18**: not applicable. White-label and reseller/self-hosted-panel
   functionality were descoped from this product entirely (see §6 Phase 3 note, §9).
3. **OS/target support beyond Ubuntu 24.04** — which Ubuntu LTS versions and Debian
   version should be prioritized next, and on what timeline?
4. **"Clean VPS only" vs. import** — should Phase 1 explicitly refuse to install on a
   VPS with pre-existing conflicting software (recommended, simpler and safer), or is
   there a near-term need to "adopt" an already-configured server?
5. **Compliance targets** — is SOC 2 / ISO 27001 / similar a near-term goal? This
   materially affects audit-log design, access reviews, and vendor choices from day one
   rather than being retrofitted later.
6. **Open-source vs. closed-source agent** — publishing the agent's source (even if the
   control plane stays closed) could build trust given it runs as root on customer
   infrastructure. Is that acceptable/desired?
7. **Data residency** — do we need EU (or other regional) data residency for the control
   plane's stored metrics/logs/audit data for target customers?
8. **Support/SLA commitments** for connected servers — what uptime/response
   expectations are we making, and does that require an on-call rotation before GA?
9. **Branding/naming** — "ServerPanel" is a placeholder working name used in this repo;
   confirm final product name before it's baked into user-facing strings, domains, and
   the agent's install-script hostnames.
10. **Beta/rollout strategy** — closed beta with a capped number of design-partner
    agencies before general availability, given the security review recommended in §7?
