#!/usr/bin/env bash
# Build a browser client into the directory the server embeds
# (server/internal/api/webapp/). The generated files are git-ignored; run this
# before building the server (the Docker images do it for you).
#
#   WEB_APP=arsip (default)  the archive app: web/arsip — plain JavaScript, no wasm.
#   WEB_APP=ttd              the earlier PDF-signing client: web/src + pqcsign.wasm
#                            (wasm_exec.js from the Go toolchain, core/cmd/pqcsign-wasm).
#                            Its e2e tests (web/e2e/run.mjs, office.mjs) need this build.
set -euo pipefail
TTD="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$TTD/server/internal/api/webapp}"
APP="${WEB_APP:-arsip}"
mkdir -p "$OUT"

# Never mix two clients: clear a previous build (keep the .gitkeep the embed needs).
find "$OUT" -mindepth 1 ! -name .gitkeep -delete

case "$APP" in
  arsip)
    cp -R "$TTD/web/arsip/." "$OUT/"
    echo "built $OUT (arsip: $(find "$OUT" -type f ! -name .gitkeep | wc -l) files)"
    ;;
  ttd)
    cp -R "$TTD/web/src/." "$OUT/"
    cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$OUT/wasm_exec.js"
    ( cd "$TTD/core" && GOWORK=off GOOS=js GOARCH=wasm \
        go build -trimpath -ldflags="-s -w" -o "$OUT/pqcsign.wasm" ./cmd/pqcsign-wasm )
    echo "built $OUT (ttd: $(wc -c < "$OUT/pqcsign.wasm") bytes wasm)"
    ;;
  *) echo "unknown WEB_APP=$APP (use arsip or ttd)" >&2; exit 2 ;;
esac
