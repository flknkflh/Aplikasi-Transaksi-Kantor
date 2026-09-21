#!/usr/bin/env bash
# Build the browser client into the directory the server embeds
# (server/internal/api/webapp/): static files from web/src, wasm_exec.js from
# the Go toolchain, and pqcsign.wasm compiled from core/cmd/pqcsign-wasm.
# The generated files are git-ignored; run this before building the server
# (deploy/local/Dockerfile does it for you).
set -euo pipefail
TTD="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$TTD/server/internal/api/webapp}"
mkdir -p "$OUT"

# static sources (index.html, app.js, ...) — anything but a previous build
if [ -d "$TTD/web/src" ]; then cp -R "$TTD/web/src/." "$OUT/"; fi

cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$OUT/wasm_exec.js"

( cd "$TTD/core" && GOWORK=off GOOS=js GOARCH=wasm \
    go build -trimpath -ldflags="-s -w" -o "$OUT/pqcsign.wasm" ./cmd/pqcsign-wasm )

echo "built $OUT ($(wc -c < "$OUT/pqcsign.wasm") bytes wasm)"
