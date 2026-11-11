#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

version="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
mkdir -p dist
for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
	goos="${target%/*}"
	goarch="${target#*/}"
	out="dist/pipescry-${goos}-${goarch}"
	[ "$goos" = windows ] && out="${out}.exe"
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -ldflags "-s -w -X main.version=${version}" -o "$out" ./cmd/pipescry
	echo "$out"
done
