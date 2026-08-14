# Installation

## 1. Local development

Requires Go 1.25+ (see `go.mod`). No other runtime dependency — SQLite is pure Go
(`modernc.org/sqlite`), no cgo, no separate database server to install.

```
git clone <this repo>
cd serverpanel
go build -o controlplane ./apps/controlplane
go build -o agent ./apps/agent
```

**Terminal 1 — control plane:**
```
./controlplane -api-addr=127.0.0.1:8080 -gateway-addr=127.0.0.1:8843 \
  -db=./serverpanel.db -insecure-cookies
```
`-insecure-cookies` is for plain-HTTP local dev only — it disables the session
cookie's `Secure` flag so a browser will actually send it back to
`http://127.0.0.1:8080`. Never pass it when the dashboard is served over real TLS.

Open `http://127.0.0.1:8080/` — create the first account (signup), log in, optionally
enroll TOTP 2FA, then "add a server" to get a one-time install command.

**Terminal 2 — on a real (or disposable container) Ubuntu 24.04 x86_64/aarch64 host,
as root**, using the token/server ID the dashboard showed you (skip the installer
script for local dev and drive the agent binary directly, since the installer expects
a real signed-release download endpoint that doesn't exist for local dev):
```
./agent -api=http://127.0.0.1:8080 -token=<token from the install command> \
  -data-dir=/etc/serverpanel-agent -register-only
./agent -data-dir=/etc/serverpanel-agent   # long-running; Ctrl-C to stop
```
The dashboard should show the server as "connected" within a few seconds. From there,
dispatch `stack.install` (via the dashboard or `POST /api/v1/servers/{id}/tasks` with
`{"capability": "stack.install", "params": {"profile": "phase1-lemp"}}`) before
attempting `site.create` — a site's php-fpm pool and nginx vhost assume the stack is
already installed.

Run the test suite before making changes to confirm your environment is set up
correctly:
```
go test ./...
```
See `TESTING.md` for what's covered and what still needs a real Ubuntu host.

## 2. Production install on a clean Ubuntu 24.04 VPS

This is what the dashboard's generated install command actually runs
(`apps/agent/install.sh`), on a **clean** Ubuntu 24.04 LTS VPS (x86_64 or aarch64),
as root:

```
curl -fsSL https://get.serverpanel.example/install.sh | sudo bash -s -- \
  --server=<server_id> --token=<bootstrap_token> --api=<control_plane_url>
```

**Note on the URLs above**: `get.serverpanel.example` and the
`SERVERPANEL_DOWNLOAD_BASE` default (`https://releases.serverpanel.example`) inside
`install.sh` are illustrative placeholders — there is no real release/CDN pipeline
publishing signed agent binaries yet. Before this can be used against a real VPS, one
of these needs to exist and be wired up:
- Build and host `serverpanel-agent-linux-{amd64,arm64}` + a matching `.sha256`
  checksum file + `serverpanel-agent.service` (the systemd unit) at whatever
  `$SERVERPANEL_DOWNLOAD_BASE` you configure (override the env var at install time),
  or
- Adapt `install.sh` to build/copy the agent binary from this repo directly for a
  self-hosted or closed-beta deployment, skipping the CDN entirely.

What the script does, in order (all fail-closed — any check failing aborts the
install with a clear error, nothing partially applies):
1. Confirms it's running as root.
2. Confirms `/etc/os-release` reports `ID=ubuntu VERSION_ID=24.04` — refuses any other
   OS/version, matching the "clean Ubuntu 24.04 only" scope (`SYSTEM.md` §14).
3. Confirms a supported CPU architecture (`x86_64`/`aarch64`).
4. Checks RAM (≥512MB) and free disk on `/` (≥2GB) — warns and aborts below these
   floors rather than installing into a resource-starved host.
5. Warns (does not abort) if `apache2` or `nginx` is already running — a genuine
   pre-existing-software conflict is left for the dashboard's own pre-install report
   to catch before `stack.install` runs, per `product-plan.md` §10 Q4's "clean VPS
   only" recommendation.
6. Downloads the agent binary + its checksum, verifies the checksum, aborts on
   mismatch.
7. Installs the binary to `/usr/local/bin/serverpanel-agent`.
8. One-shot registers: exchanges the bootstrap token for a certificate identity under
   `/etc/serverpanel-agent` (`0700`), then exits — the token is never written to disk
   or to the systemd unit that runs afterward, only passed as a short-lived process
   argument during this one invocation.
9. Installs and enables the `serverpanel-agent` systemd service.

Once it prints "Done," the dashboard should show the server as connected within a few
seconds. From there, hosting-stack installation, site creation, WordPress deploys,
etc. are all dispatched as ordinary allow-listed tasks from the dashboard — the
installer's job ends at "agent registered and running," matching the design intent
noted in `install.sh`'s own header comment (stack install goes through the same
reviewed, versioned, resumable capability path as every other change, not a separate
bootstrap-time code path).

## 3. What has and hasn't been verified on a real clean VPS

Per `TESTING.md`: agent registration, stack install, site creation, WordPress
deployment, database creation, file operations, and backup creation were manually
verified against a real Ubuntu 24.04 **container** in a prior session (not a VPS —
no public IP/DNS was available). SSL issuance (needs real public DNS),
`systemctl start/stop/restart` (needs real systemd as PID 1, absent in that
container), and a true "clean VPS from a cloud provider, over the public internet, top
to bottom" run have **not** been performed. Do not represent this as VPS-tested until
that gap is closed — see `TESTING.md` §5 item 2 for the recommended next step
(a reproducible cloud-init VM or CI-runnable container pass covering the full
install → register → deploy → backup → upgrade → rollback → revoke checklist).
