#!/usr/bin/env bash
# ServerPanel agent installer.
#
# This is the script referenced by the one-time install command shown in
# the dashboard after creating a server (see apps/controlplane/sites.go and
# handleCreateServer in http.go, which build the actual command from this
# control plane's own -public-url). It is served BY the control plane
# itself at GET /install.sh (apps/controlplane/downloads.go) — there is no
# separate release host to keep in sync. Run exactly once, as root, on a
# clean Ubuntu 24.04 LTS VPS:
#
#   curl -fsSL <your-control-plane-url>/install.sh | sudo bash -s -- \
#     --server=<server_id> --token=<bootstrap_token> --api=<control_plane_url>
#
# It only: (1) sanity-checks the box is compatible, (2) installs the agent
# binary, (3) exchanges the single-use bootstrap token for a durable
# certificate identity, (4) starts the agent as a systemd service. It does
# NOT install the hosting stack itself — that happens afterward as an
# allow-listed task dispatched from the dashboard once the server shows
# "connected", so stack installation goes through the same reviewed,
# versioned, resumable capability path as every other change (see
# docs/architecture.md §3, and stack.install in packages/capabilities).
set -euo pipefail

SERVER_ID=""
TOKEN=""
API_ADDR=""
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/etc/serverpanel-agent"

usage() {
  echo "usage: install.sh --server=<id> --token=<token> --api=<control-plane-url> [--download-base=<url>]" >&2
  exit 1
}

for arg in "$@"; do
  case "$arg" in
    --server=*) SERVER_ID="${arg#*=}" ;;
    --token=*) TOKEN="${arg#*=}" ;;
    --api=*) API_ADDR="${arg#*=}" ;;
    --download-base=*) DOWNLOAD_BASE_OVERRIDE="${arg#*=}" ;;
    *) echo "unknown argument: $arg" >&2; usage ;;
  esac
done

[[ -n "$SERVER_ID" && -n "$TOKEN" && -n "$API_ADDR" ]] || usage

# Agent binaries and the systemd unit are served by this same control
# plane's /downloads/ endpoint by default — the control plane you're
# registering with is also where the installer fetches its payload from,
# so there's nothing else to stand up or keep in sync. Override only if
# you're deliberately hosting release artifacts somewhere else.
DOWNLOAD_BASE="${SERVERPANEL_DOWNLOAD_BASE:-${DOWNLOAD_BASE_OVERRIDE:-${API_ADDR%/}/downloads}}"

if [[ "$EUID" -ne 0 ]]; then
  echo "error: this script must be run as root (e.g. via sudo)." >&2
  exit 1
fi

echo "==> Running compatibility and security checks"

if [[ ! -r /etc/os-release ]]; then
  echo "error: cannot determine OS (missing /etc/os-release)." >&2
  exit 1
fi
# shellcheck source=/dev/null
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
  echo "error: only Ubuntu 24.04 LTS is supported in this release (found: ${PRETTY_NAME:-unknown})." >&2
  echo "       Later releases may add other Ubuntu LTS versions and Debian." >&2
  exit 1
fi

# Map uname's arch names onto Go's GOARCH names, since that's how the
# control plane's build script (scripts/build-agent-releases.sh) names the
# binaries it serves.
UNAME_ARCH="$(uname -m)"
case "$UNAME_ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *) echo "error: unsupported CPU architecture: $UNAME_ARCH" >&2; exit 1 ;;
esac

CPU_COUNT="$(nproc)"
MEM_MB="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)"
DISK_AVAIL_MB="$(df -Pm / | awk 'NR==2 {print $4}')"
echo "    OS: ${PRETTY_NAME}, arch: ${UNAME_ARCH}, CPUs: ${CPU_COUNT}, RAM: ${MEM_MB}MB, free disk on /: ${DISK_AVAIL_MB}MB"

if (( MEM_MB < 512 )); then
  echo "error: at least 512MB RAM is recommended before installing the agent; found ${MEM_MB}MB." >&2
  exit 1
fi
if (( DISK_AVAIL_MB < 2048 )); then
  echo "error: at least 2GB free disk is recommended before installing the agent; found ${DISK_AVAIL_MB}MB." >&2
  exit 1
fi

for svc in apache2 nginx; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    echo "warning: ${svc} is already running on this host. The dashboard will report this as a" >&2
    echo "         pre-installation conflict before any hosting stack install is attempted." >&2
  fi
done

echo "==> Downloading agent (arch: ${ARCH}) from ${DOWNLOAD_BASE}"
TMP_BIN="$(mktemp)"
trap 'rm -f "$TMP_BIN" "${TMP_BIN}.sha256"' EXIT
curl -fsSL "${DOWNLOAD_BASE}/serverpanel-agent-linux-${ARCH}" -o "$TMP_BIN"
curl -fsSL "${DOWNLOAD_BASE}/serverpanel-agent-linux-${ARCH}.sha256" -o "${TMP_BIN}.sha256"
( cd "$(dirname "$TMP_BIN")" && sha256sum -c <(sed "s#.*#& $(basename "$TMP_BIN")#" "${TMP_BIN}.sha256") ) \
  || { echo "error: checksum verification failed, aborting." >&2; exit 1; }

install -m 0755 "$TMP_BIN" "${INSTALL_DIR}/serverpanel-agent"

echo "==> Registering with control plane at ${API_ADDR}"
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"
# One-shot registration run: exchanges the single-use token for a durable
# certificate identity written under $DATA_DIR, then exits. The token is
# passed only as a process argument for this one short-lived invocation and
# is never written to disk or to the systemd unit that runs afterward.
"${INSTALL_DIR}/serverpanel-agent" --api="$API_ADDR" --token="$TOKEN" --data-dir="$DATA_DIR" --register-only

echo "==> Installing systemd service"
curl -fsSL "${DOWNLOAD_BASE}/serverpanel-agent.service" -o /etc/systemd/system/serverpanel-agent.service
systemctl daemon-reload
systemctl enable --now serverpanel-agent

echo "==> Done. The dashboard will show this server as connected within a few seconds."
