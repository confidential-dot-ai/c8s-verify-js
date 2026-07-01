#!/usr/bin/env bash
#
# Copy the generated WASM verifier runtime assets next to the compiled loader.
#
# `tsc` only emits the .ts it compiles; the WASM verifier is a generated binary
# (see scripts/build-wasm.sh) that the compiled `wasm-loader.js` loads via the
# relative path `./wasm/…`. So the `wasm/` runtime files must sit as a sibling of
# the compiled `wasm-loader.js`.
#
# Usage: copy-assets.sh [DEST_DIR]
#   DEST_DIR is the directory that will hold `wasm/` (i.e. where wasm-loader.js
#   lands). Defaults to `dist` for the flat library build (rootDir src → dist).
#   The browser-demo build (rootDir . → dist-demo) passes `dist-demo/src`.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
dest="${1:-dist}"
dest="$root/$dest"

if [ ! -f "$root/src/wasm/attestation_wasm.js" ]; then
  echo "error: src/wasm/ not built — run 'npm run build:wasm' first (see src/wasm/README.md)" >&2
  exit 1
fi

mkdir -p "$dest/wasm"
cp "$root/src/wasm/attestation_wasm.js" \
   "$root/src/wasm/attestation_wasm_bg.wasm" \
   "$dest/wasm/"
# Type declarations are optional (only present after a fresh build:wasm).
cp "$root/src/wasm/attestation_wasm.d.ts" "$dest/wasm/" 2>/dev/null || true
cp "$root/src/wasm/attestation_wasm_bg.wasm.d.ts" "$dest/wasm/" 2>/dev/null || true

echo "ok: copied src/wasm/ runtime assets into $dest/wasm/"
