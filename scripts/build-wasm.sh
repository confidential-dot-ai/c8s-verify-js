#!/usr/bin/env bash
#
# Regenerate the attestation-rs WASM verifier into ./wasm.
#
# This package ships NO prebuilt .wasm in git: the verifier is generated here
# from attestation-rs Rust source at the pinned commit below, so the verifier in
# this library is always reproducible and auditable from source. Run this once
# after a fresh checkout (and in CI before tests); see wasm/README.md.
#
#   npm run build:wasm
#
# Overrides (env):
#   ATTESTATION_RS_REF  commit/branch/tag to build (default: the pin below)
#   ATTESTATION_RS_DIR  path to a local attestation-rs checkout (default: ../attestation-rs)
#   ATTESTATION_RS_REPO clone URL, used only when ATTESTATION_RS_DIR is absent
#
set -euo pipefail

# Pinned attestation-rs commit (origin/main). Bump deliberately, rebuild, and
# update wasm/README.md — this is the single source of truth for the verifier.
PIN="${ATTESTATION_RS_REF:-13039e857e7124a8a8620c6aacaa7217d73a3958}"
REPO="${ATTESTATION_RS_REPO:-https://github.com/confidential-dot-ai/attestation-rs.git}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="$root/wasm"

command -v wasm-pack >/dev/null 2>&1 || {
  echo "error: wasm-pack not found. Install it with: cargo install wasm-pack" >&2
  exit 1
}

work="$(mktemp -d)"
# Resolve the attestation-rs source: explicit override first, then common
# checkout locations relative to this package — a standalone sibling
# (../attestation-rs) or a nested git submodule whose superproject has
# attestation-rs as a sibling (../../attestation-rs). Falls back to a clone.
src="${ATTESTATION_RS_DIR:-}"
if [ -z "$src" ]; then
  for cand in "$root/../attestation-rs" "$root/../../attestation-rs"; do
    if [ -d "$cand/.git" ]; then src="$cand"; break; fi
  done
  src="${src:-$root/../attestation-rs}" # default for the "clone" message below
fi
cleanup() {
  [ -n "${worktree_added:-}" ] && git -C "$src" worktree remove --force "$work/src" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

if [ -d "$src/.git" ]; then
  # Local checkout: build the exact pinned commit via a throwaway worktree,
  # without disturbing the user's working tree or current branch.
  git -C "$src" cat-file -e "${PIN}^{commit}" 2>/dev/null ||
    git -C "$src" fetch --quiet origin "$PIN" 2>/dev/null || true
  git -C "$src" worktree add --detach "$work/src" "$PIN" >/dev/null
  worktree_added=1
  srcdir="$work/src"
else
  # No local checkout (e.g. CI without the sibling repo): clone the pinned ref.
  echo "no attestation-rs checkout at $src — cloning $REPO @ ${PIN:0:12}"
  git clone --quiet "$REPO" "$work/src"
  git -C "$work/src" checkout --quiet --detach "$PIN"
  srcdir="$work/src"
fi

echo "building wasm verifier from attestation-rs @ ${PIN:0:12} (target: web)"
( cd "$srcdir/crates/attestation-wasm" && wasm-pack build --target web --out-dir "$work/pkg" )

mkdir -p "$out"
# Copy only the runtime artifacts the library imports (see src/wasm-loader.js).
cp "$work/pkg/attestation_wasm.js" "$work/pkg/attestation_wasm_bg.wasm" "$out/"
[ -f "$work/pkg/attestation_wasm.d.ts" ] &&
  cp "$work/pkg/attestation_wasm.d.ts" "$work/pkg/attestation_wasm_bg.wasm.d.ts" "$out/" 2>/dev/null || true

echo "ok: wasm/ rebuilt from attestation-rs @ ${PIN:0:12}"
