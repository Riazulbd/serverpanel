# ServerPanel

A centralized, multi-server hosting control plane for Ubuntu VPS fleets — combining the
depth of Webuzo's hosting controls with the centralized, multi-server experience of
ServerAvatar, wrapped in a modern interface aimed at agencies and non-technical users.

ServerPanel is **not** a per-server local control panel. It is a hosted (or
self-hostable) dashboard that manages many externally-hosted, unmodified Ubuntu VPS
servers through a lightweight, security-hardened **server agent** installed on each one.
The agent never exposes arbitrary shell execution — it only performs a fixed, versioned
set of allow-listed operations requested by the control plane over a mutually
authenticated connection.

## Start here

- [`docs/SYSTEM.md`](docs/SYSTEM.md) — **start here.** The single reference for what
  this project is, the complete feature list with current implementation status,
  architecture, database schema, known limitations, and links to every other doc.
- [`docs/product-plan.md`](docs/product-plan.md) — the original pre-implementation
  plan: architecture comparison, trust model summary, infra cost, data retention,
  milestones, MVP cost, risks, postponed features, and open product-owner questions.
  Still the source of truth for what's intentionally *not* built yet.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — control-plane and agent
  architecture, component diagram, task/RPC model, repo layout (with "as built" notes
  where the implementation simplified the original proposal).
- [`docs/SECURITY.md`](docs/SECURITY.md) — agent registration flow, mTLS and
  certificate rotation, revocation, per-app isolation — each section marked
  implemented/partial/not-yet-built.
- [`docs/API.md`](docs/API.md) — every public API endpoint and the agent gateway wire
  protocol.
- [`docs/TESTING.md`](docs/TESTING.md) — automated test coverage, what's been manually
  verified against a real host vs. not verified anywhere yet, and how to run the suite.
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — running it, backups, monitoring,
  upgrade/rollback, troubleshooting.
- [`docs/INSTALLATION.md`](docs/INSTALLATION.md) — local dev setup and a clean-Ubuntu
  production install walkthrough.
- [`docs/SERVERAVATAR_PARITY.md`](docs/SERVERAVATAR_PARITY.md) — feature-level parity
  tracker against ServerAvatar's documented capabilities (functional reference only —
  no ServerAvatar code, copy, or assets are used; see "Non-goals" below).
- [`docs/SERVERAVATAR_DOC_INVENTORY.md`](docs/SERVERAVATAR_DOC_INVENTORY.md) — tracks
  what has (and hasn't yet) been reviewed from ServerAvatar's documentation site.
- [`CHANGELOG.md`](CHANGELOG.md) — dated log of what changed and why.

## Development priority

**Phase 1 — secure working foundation:** central dashboard, auth + 2FA, secure agent
install/registration, multi-server connection, monitoring, Nginx/PHP/MariaDB stack
install, WordPress/PHP/static deployment, system-user isolation, database management,
SSL, basic file manager, local backups, logs, audit trail, basic diagnostics.

**Phase 2 — professional server management:** Git deployment & push-to-deploy, staging
and cloning, cron/process management, firewall & Fail2Ban management, SSH/SFTP
management, automated security updates, advanced monitoring/alerts, remote backups,
cross-server application migration.

**Phase 3 — commercial platform:** teams & granular permissions, white-label customer
panels, reseller system, cloud-provider integrations, billing/subscriptions, additional
stack adapters (Node.js, Laravel, n8n, Mautic), public API, plugin system.

See `docs/product-plan.md` for the full milestone breakdown and rationale for what is
deliberately postponed out of the initial security-focused MVP.

## Non-goals / constraints (by design)

- The agent offers **no arbitrary shell-command execution** RPC — every action is a
  named, allow-listed, versioned capability.
- Core server management never depends on a third-party commercial management API
  (ServerAvatar, Webuzo, or otherwise). The initial VPS connection method works against
  any provider's plain Ubuntu 24.04 VPS with no cloud-provider API required.
- No ServerAvatar (or other vendor) proprietary code, branding, UI, copy, or assets are
  reused anywhere in this project. All designs, protocols, and implementations here are
  original, built on open standards (mTLS, systemd, ACME, etc.) and properly licensed
  dependencies.
