#!/usr/bin/env bash
#
# Copy non-TypeScript runtime assets into the compiled `dist/` tree.
#
# `tsc` only emits the .js/.d.ts it compiles; the WASM verifier is a generated
# binary (see scripts/build-wasm.sh) that the compiled `dist/src/wasm-loader.js`
# loads via the relative path `../wasm/…`. With the nested output layout
# (dist/src, dist/test, dist/demo) that resolves to `dist/wasm`, so mirror the
# generated `wasm/` directory there. Run as part of `npm run build`.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

if [ ! -f "$root/wasm/attestation_wasm.js" ]; then
  echo "error: wasm/ not built — run 'npm run build:wasm' first (see wasm/README.md)" >&2
  exit 1
fi

mkdir -p "$root/dist/wasm"
cp "$root/wasm/attestation_wasm.js" \
   "$root/wasm/attestation_wasm_bg.wasm" \
   "$root/dist/wasm/"
# Type declarations are optional (only present after a fresh build:wasm).
cp "$root/wasm/attestation_wasm.d.ts" "$root/dist/wasm/" 2>/dev/null || true
cp "$root/wasm/attestation_wasm_bg.wasm.d.ts" "$root/dist/wasm/" 2>/dev/null || true

echo "ok: copied wasm/ runtime assets into dist/wasm/"
