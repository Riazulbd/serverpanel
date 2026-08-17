# ServerAvatar Documentation Inventory

This tracks what has actually been reviewed from ServerAvatar's public product
documentation (starting point: `https://serveravatar.com/docs/intro/`) for the sole
purpose of understanding *documented product capabilities as a functional reference* —
never as a source of code, copy, design assets, or branding to copy. See the root
`README.md` "Non-goals" section and `docs/SYSTEM.md` for what that boundary means in
practice.

## Status of this inventory

**Not yet performed: a full recursive crawl of the documentation site.** This file is
the tracking scaffold for that process, not the completed result of it. A proper
inventory pass needs to:

1. Fetch `https://serveravatar.com/docs/intro/` and enumerate every linked
   documentation section/page (Getting Started, Organization, Integrations, Account
   Management, Billing, Server Management, Application Management, Database
   Management, Backups, Add-ons, White Label, Reseller, WordPress Toolkit, Log
   Monitoring, etc.).
2. Record each page below (section, title, URL, discovery date).
3. For each page, extract the *capabilities* it documents (not its text/copy) and add
   a row to `docs/SERVERAVATAR_PARITY.md` for anything not already tracked there.
4. Re-run periodically and diff against the previous pass to catch newly documented
   capabilities.

This is a genuinely large undertaking (the brief that generated this file lists over
twenty top-level product areas) and was not something a single unattended automated
session should attempt to fabricate the appearance of having completed. The honest
state is: `docs/SYSTEM.md` §2 and `docs/product-plan.md` already contain a
capability-level feature table that was built, at project inception, against the
general shape of ServerAvatar- and Webuzo-style hosting-panel functionality (see
`product-plan.md` §1's architecture comparison) — that table is a reasonable
starting seed for `SERVERAVATAR_PARITY.md`, but it is not the product of a page-by-page
documentation crawl and should not be represented as one.

## Recommended next step

A future session with the time budget to do this properly should:
- Use a web-fetching tool to walk the docs site's navigation tree systematically,
  recording pages in the table below as it goes.
- Keep this file and `SERVERAVATAR_PARITY.md` in sync as that crawl proceeds, rather
  than writing the parity matrix in one pass disconnected from what was actually
  reviewed.

## Page inventory

| Section | Page title | URL | Discovered | Related feature IDs | Status |
|---|---|---|---|---|---|
| _(none yet — see "Status of this inventory" above)_ | | | | | |
