#!/usr/bin/env bash
set -euo pipefail
AGENTSSH_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$AGENTSSH_ROOT"
AGENTSSH_GO=${AGENTSSH_GO:-go}
AGENTSSH_VERSION=$(cat VERSION)
if (($#)); then
  echo 'Usage: scripts/build.sh (builds generic clients; select --server at startup)' >&2
  exit 1
fi
export GOMAXPROCS=${GOMAXPROCS:-2}
export GOMEMLIMIT=${GOMEMLIMIT:-1200MiB}
export GOTMPDIR=${GOTMPDIR:-"$AGENTSSH_ROOT/.cache/go-tmp"}
mkdir -p "$GOTMPDIR" dist
AGENTSSH_LDFLAGS="-s -w -X github.com/sandrauzbmo/ssh_tool/internal/protocol.BuildVersion=$AGENTSSH_VERSION"
for AGENTSSH_ARCH in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$AGENTSSH_ARCH" "$AGENTSSH_GO" build -p 2 -trimpath -buildvcs=false -ldflags="$AGENTSSH_LDFLAGS" -o "dist/agentssh-linux-$AGENTSSH_ARCH" ./cmd/agentssh
done
(cd dist && sha256sum agentssh-linux-amd64 agentssh-linux-arm64 > SHA256SUMS)
echo 'Generic clients are in dist/. Pass --server at startup; no deployment configuration is embedded.'
