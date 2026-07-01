#!/usr/bin/env bash
#
# Regenerate the attestation-rs WASM verifier into ./src/wasm.
#
# This package ships NO prebuilt .wasm in git: the verifier is generated here
# from attestation-rs Rust source, so the verifier in this library is always
# reproducible and auditable from source. The source lives in-tree as the
# `vendor/attestation-rs` git submodule, pinned to an exact commit (the submodule
# gitlink IS the pin) — building stays entirely within this project's boundary.
# Run this once after a fresh checkout (and in CI before tests); see
# src/wasm/README.md.
#
#   git submodule update --init vendor/attestation-rs   # once, after clone
#   npm run build:wasm
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="$root/src/wasm"
src="$root/vendor/attestation-rs"

command -v wasm-pack >/dev/null 2>&1 || {
  echo "error: wasm-pack not found. Install it with: cargo install wasm-pack" >&2
  exit 1
}

# The pinned source is the submodule. Initialise it if a fresh clone skipped it.
if [ ! -e "$src/crates/attestation-wasm/Cargo.toml" ]; then
  echo "vendor/attestation-rs submodule not checked out — initialising it"
  git -C "$root" submodule update --init "$src"
fi

pin="$(git -C "$src" rev-parse --short HEAD)"
echo "building wasm verifier from vendor/attestation-rs @ ${pin} (target: web)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

( cd "$src/crates/attestation-wasm" && wasm-pack build --target web --out-dir "$work/pkg" )

mkdir -p "$out"
# Copy only the runtime artifacts the library imports (see src/wasm-loader.ts).
cp "$work/pkg/attestation_wasm.js" "$work/pkg/attestation_wasm_bg.wasm" "$out/"
[ -f "$work/pkg/attestation_wasm.d.ts" ] &&
  cp "$work/pkg/attestation_wasm.d.ts" "$work/pkg/attestation_wasm_bg.wasm.d.ts" "$out/" 2>/dev/null || true

echo "ok: src/wasm/ rebuilt from vendor/attestation-rs @ ${pin}"
