#!/usr/bin/env bash
# Build every tool for Linux and Windows (amd64) into bin/.
# Pure Go, no cgo, so this cross-compiles from any host with a Go toolchain.
set -eo pipefail
cd "$(dirname "$0")"

TOOLS=(enum rotatepw revoke backup defaultcreds)
LDFLAGS="-s -w"   # strip symbol/debug info to shrink binaries

build() {
  local goos="$1" goarch="$2" ext="$3"
  local outdir="bin/${goos}-${goarch}"
  mkdir -p "$outdir"
  for t in "${TOOLS[@]}"; do
    echo "  ${goos}/${goarch}: ${t}${ext}"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -trimpath -ldflags "$LDFLAGS" -o "${outdir}/${t}${ext}" "./cmd/${t}"
  done
}

echo "Building Linux (amd64)..."
build linux amd64 ""
echo "Building Windows (amd64)..."
build windows amd64 ".exe"
echo "Done. Binaries are in bin/."
