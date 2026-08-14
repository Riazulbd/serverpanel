# Server Agent Security & Trust Model

## 1. Registration flow (bootstrap token → machine identity)

```mermaid
sequenceDiagram
    participant U as User (browser)
    participant CP as Control Plane
    participant VPS as Clean Ubuntu 24.04 VPS
    participant CA as Agent CA

    U->>CP: Create server record
    CP->>CP: Generate bootstrap token (256-bit random)\nstore only Argon2/SHA-256 hash + expiry (~15 min) + single-use flag
    CP-->>U: Show one-time install command\n(token embedded, short-lived)
    U->>VPS: Run install command as root
    VPS->>VPS: Download agent binary (checksum + signature verified)
    VPS->>CP: POST /agents/register {token, csr} over TLS
    CP->>CP: Validate token: exists, unexpired, unused\nHash comparison only, never logged in plaintext
    CP->>CP: Mark token used (single-use enforced atomically)
    CP->>CA: Sign CSR -> short-lived client cert bound to server_id
    CA-->>CP: Client certificate
    CP-->>VPS: Client cert + gateway endpoint
    VPS->>VPS: Store cert + private key (0600, root-only)
    VPS->>CP: Reconnect via mTLS using issued cert
    CP-->>U: Server status: connected, running compatibility checks
```

Properties this guarantees:

- **Single-use**: the token is consumed atomically on first valid exchange; a replay
  with the same token after success (or after expiry) is rejected.
- **Expires quickly**: default 15 minutes from creation; unused tokens are periodically
  purged.
- **Stored securely**: only a salted hash of the token is persisted; the plaintext token
  exists only in the one-time install command shown to the user and in the ephemeral
  process environment on the VPS during registration.
- **Never in permanent logs**: request logging middleware redacts the token field before
  writing structured logs (deny-list is insufficient — use an explicit allow-list of
  loggable fields on the registration endpoint).
- **Exchangeable for identity**: successful registration yields a durable, per-server
  client certificate — the token itself grants no ongoing access.
- **Revocable**: an unused token can be revoked from the dashboard (e.g., user made a
  mistake, wants to reissue); an already-exchanged identity is revoked separately (§3).

## 2. Ongoing authentication: mutual TLS

- All agent ↔ control-plane traffic (registration excluded, which is TLS + token) uses
  **mTLS**: the gateway only accepts connections presenting a valid, non-revoked
  certificate issued by the internal Agent CA, and the agent verifies the gateway's
  certificate/pinned CA to prevent MITM or connecting to a spoofed endpoint.
- Client certs are **short-lived** (e.g. 30–90 days) and **auto-rotated**: before
  expiry, the agent requests renewal authenticated by its current still-valid cert (no
  shared long-lived secret is ever reused for renewal). If a renewal window is missed
  (agent offline past expiry), the agent falls back to a manual re-registration flow
  requiring a fresh bootstrap token from the dashboard — this is an intentional
  fail-closed behavior, not silent re-trust.
- The Agent CA's private key is held in a dedicated, tightly access-controlled service
  (e.g. `step-ca` or HSM-backed KMS in later stages), separate from the general
  application database, so a control-plane app-tier compromise doesn't automatically
  hand over CA signing power.

## 3. Revocation

- Dashboard "Disconnect server" / "Revoke agent" immediately:
  1. Adds the certificate serial to a revocation list checked on every gateway
     handshake (short-TTL cached CRL-equivalent; at this scale a DB-backed check with a
     small in-memory cache is simpler and sufficient versus running full OCSP).
  2. Force-closes any live connection from that server.
  3. Marks the server record disconnected in the dashboard, distinct from
     "offline" (network issue) so users can tell the difference between "agent lost
     network" and "we revoked trust."
- Re-connecting the same physical VPS afterward requires a brand-new bootstrap token and
  full re-registration — there is no path to silently regain trust with an old key.
- Agent binary self-updates are themselves an allow-listed capability (§ architecture
  doc) gated on signature verification of the new binary against the platform's release
  signing key, so a revoked/compromised control plane can't be used to push an arbitrary
  binary — the agent independently verifies the signature before swapping itself out.

## 4. Compromise containment (defense in depth on the VPS)

- Each hosted application runs as its **own Linux system user** with its own PHP-FPM
  pool, `open_basedir`, disabled dangerous PHP functions, and file ownership — a
  compromised app cannot read/write another app's files or crontab.
- Each application's database user has grants scoped to only its own database/schema.
- The agent process itself runs with the minimum privilege it can — where an action
  genuinely requires root (installing packages, editing `/etc/nginx`, managing
  systemd units, UFW rules), it goes through a narrow, explicitly-allow-listed
  privileged helper rather than the whole agent process running unrestricted root for
  its entire lifetime. (Exact privilege-separation approach — e.g. Linux capabilities
  vs. a small root helper invoked via a fixed set of subcommands — is an implementation
  detail to finalize in Phase 1, but "no general shell exec" holds either way.)
- All privileged capability invocations are written to an append-only, tamper-evident
  audit log (server-side, in the control plane — not only on the VPS, so a VPS
  compromise can't erase its own history).

## 5. Safe SSH / firewall changes ("commit-confirm")

Any change that could lock the user out of SSH or break connectivity (SSH port change,
disabling password auth, disabling root login, UFW rule changes, IP allow-listing)
follows a mandatory sequence — the agent never applies such a change as a single
irreversible step:

```mermaid
sequenceDiagram
    participant U as User
    participant CP as Control Plane
    participant AG as Agent

    U->>CP: Request risky change (e.g. new SSH port)
    CP->>AG: task: network.apply_risky_change (validated config)
    AG->>AG: Validate syntax/semantics locally before touching anything
    AG->>AG: Snapshot current config (for rollback)
    AG->>AG: Apply new config\nKEEP existing listener/rule alive in parallel where possible
    AG->>AG: Start rollback timer (e.g. 5 min, via systemd-run/at)
    AG-->>CP: New config applied, awaiting confirmation
    CP-->>U: "Confirm the new setting works" prompt
    alt User confirms within window (new connection succeeds)
        U->>CP: Confirm
        CP->>AG: task: network.confirm_change
        AG->>AG: Cancel rollback timer, remove old config
    else No confirmation before timer expires
        AG->>AG: Automatic rollback to snapshot
        AG-->>CP: Reverted; reports failure reason
        CP-->>U: Notify: change was reverted automatically
    end
```

This mirrors well-established patterns (e.g. `netplan try`) and is a hard product
requirement, not an optional safety net — the rollback timer runs locally on the agent
so it still fires even if the control-plane connection itself is what got cut off by the
bad change.

## 6. Diagnostics and repair are opt-in, never automatic

Diagnostic checks (§ product plan Phase 1) only ever *propose* a fix with a plain-language
explanation, severity, and affected component. Applying a suggested repair requires
explicit user approval and is itself logged as an audited action — the diagnostic engine
has read/inspect capabilities but repairs go through the same allow-listed capability +
audit path as any other change, never a separate "just fix it" backdoor.
