#!/usr/bin/env bash
# Builds integration test binaries so a Windows lab host needs no Go toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist/tests
for goarch in amd64 arm64; do
	for pkg in local remote; do
		out="dist/tests/pipescry-${pkg}-it-windows-${goarch}.exe"
		CGO_ENABLED=0 GOOS=windows GOARCH="$goarch" go test -c -tags integration -o "$out" "./internal/${pkg}"
		echo "$out"
	done
done
