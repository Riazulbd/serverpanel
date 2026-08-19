#!/usr/bin/env bash
# Cross-compiles the ServerPanel agent for the architectures install.sh
# knows how to fetch (amd64, arm64), plus a matching sha256 checksum for
# each — the same checksum apps/controlplane/downloads.go serves at
# /downloads/serverpanel-agent-linux-<arch>.sha256 and install.sh verifies
# before installing anything. Run this before starting the control plane
# in a real deployment; -agent-binaries-dir tells it where to look
# (default ./dist, matching this script's default OUT_DIR).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/dist}"

mkdir -p "$OUT_DIR"

for arch in amd64 arm64; do
  out="$OUT_DIR/serverpanel-agent-linux-$arch"
  echo "==> building $out"
  ( cd "$ROOT_DIR" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -o "$out" ./apps/agent )
  sha256sum "$out" | awk '{print $1}' > "$out.sha256"
done

echo "==> done. Binaries + checksums in $OUT_DIR"
