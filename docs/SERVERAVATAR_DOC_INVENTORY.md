# ServerAvatar Documentation Inventory

This is a **functional-specification inventory**, not a copy of ServerAvatar's content.
It records which documentation sections exist at
[serveravatar.com/docs/intro](https://serveravatar.com/docs/intro/) so that
`SERVERAVATAR_PARITY.md` has something concrete to track against, and so a future pass
can detect newly-documented capabilities by diffing against this file. See
`SERVERAVATAR_PARITY.md` §"Ground rules" for what independent implementation means here
— no ServerAvatar code, proprietary API, UI layout, copy, or design asset is used
anywhere in this project; only the *existence and purpose* of a documented capability is
recorded.

## How this was built

A single top-level fetch of the docs' navigation structure (section and page titles
only — no page bodies, no copy) on 2026-08-17. This is a first pass covering the
top-level table of contents; it has not yet recursively walked every sub-page under
each section. A future session should do that recursive walk and extend the table
below with per-page entries, not just per-section ones, before this inventory can be
called complete per the parity-verification process (`SERVERAVATAR_PARITY.md` §6).

## Inventory

| Section | Page(s) seen | Discovery date | Related feature IDs (`SERVERAVATAR_PARITY.md`) | Notes |
|---|---|---|---|---|
| Introduction | (landing) | 2026-08-17 | — | Product overview, not a capability |
| Getting Started | "What is a Server?" | 2026-08-17 | SRV-* | Conceptual onboarding; maps to our server-registration flow |
| Organization | "Introduction" | 2026-08-17 | ORG-* | Multi-user/team/org model |
| Integrations | "What is an Integration?" | 2026-08-17 | INT-* | Git providers, Cloudflare, cloud storage, cloud compute providers |
| Account Management | "Update Account Info" | 2026-08-17 | ACC-* | Profile, 2FA, sessions, API tokens |
| Billing Management | "Wallet" | 2026-08-17 | BILL-* | Wallet/credits, transactions, plans |
| Server Management | "Installation (Direct Method)" | 2026-08-17 | SRV-* | Connect/provision servers, stacks, SSH, firewall, monitoring |
| Application Management | "Deploy Custom PHP" | 2026-08-17 | APP-* | Site lifecycle, domains, SSL, deployments |
| Database Management | "Understanding Database Management" | 2026-08-17 | DB-* | MySQL/MariaDB/MongoDB CRUD, users, remote access |
| Backups | "Getting Started" | 2026-08-17 | BAK-* | Backup/restore, scheduling, storage adapters |
| Add-ons | "Self-Hosted (Outline)" | 2026-08-17 | ADDON-* | Additional one-click app catalog |
| Footer: Connect Server | DigitalOcean, Vultr, Linode, AWS, Hetzner, Custom VPS | 2026-08-17 | PROV-* | Cloud provider adapters |
| Footer: Deploy Apps | Git, WordPress, PHP, Joomla, Mautic, Moodle, PrestaShop | 2026-08-17 | APP-INSTALL-* | One-click installer catalog |
| Footer: Hosting Capabilities | PHP, Node.js, WordPress, n8n, Mautic, Laravel | 2026-08-17 | STACK-*, APP-* | Runtime/stack support matrix |
| Footer: Comparisons | (alternative platforms listed) | 2026-08-17 | — | Marketing content, out of scope per task brief §4 ("do not blindly crawl unrelated marketing/blog content") |

## Sections not yet individually inventoried

The task brief's own baseline list (not sourced from ServerAvatar, but cross-checked
against it) additionally expects coverage of: WordPress Toolkit, Log Monitoring Suite,
White Label, and Reseller/Self-Hosted functionality as distinct documented areas. The
single top-level fetch above did not surface these as separate top-nav entries beyond
"Add-ons"; a follow-up recursive crawl is needed to confirm whether they're documented
as sub-pages under Add-ons/Server Management/Application Management, or under a section
not reached by a shallow fetch. Tracked as open work in `SERVERAVATAR_PARITY.md`.

## Change history

- **2026-08-17**: initial inventory (top-level navigation only). Established this file
  and the parity matrix it feeds. No prior inventory existed to diff against.
