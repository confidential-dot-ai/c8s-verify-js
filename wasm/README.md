# `wasm/` — the attestation-rs verifier (generated, not committed)

This directory holds the WebAssembly build of the attestation-rs SNP / az-snp
verifier that `src/wasm-loader.js` imports. **The `.wasm`/`.js` artifacts are
generated, not committed** — they are `.gitignore`d. A fresh checkout has no
verifier until you build it:

```sh
npm run build:wasm     # or: bash scripts/build-wasm.sh
```

The library cannot load (`src/wasm-loader.js` imports `./attestation_wasm.js`
and `./attestation_wasm_bg.wasm`) and the test suite will fail until this runs.

## Provenance

The verifier is built from the [`attestation-rs`][attestation-rs] crate
`crates/attestation-wasm` with `wasm-pack build --target web`, pinned to a
specific commit so the verifier is reproducible and auditable from Rust source
rather than shipped as an opaque binary in git history:

| | |
|---|---|
| Source | `confidential-dot-ai/attestation-rs`, `crates/attestation-wasm` |
| Pinned commit | `13039e857e7124a8a8620c6aacaa7217d73a3958` (origin/main) |
| Build | `wasm-pack build --target web` |
| Entry points | `verify_snp`, `verify_az_snp` |

The pin lives in `scripts/build-wasm.sh` (the `PIN` variable). To move to a newer
`attestation-rs`, bump that pin, re-run `npm run build:wasm`, run the tests, and
update the table above in the same change.

> **az-snp contract note.** As of this pin, `verify_az_snp` *fails closed* — it
> **throws** on a freshness (TPM quote `extraData`) mismatch rather than
> returning a non-throwing `report_data_match: false`. The policy layer
> (`src/verify.js`) catches that throw and surfaces it as the `report_data_mismatch`
> error code. Bare `verify_snp` still returns a non-throwing bool. If you bump the
> pin and that contract changes, revisit `isFreshnessMismatch` in `src/verify.js`.

## Build inputs

`scripts/build-wasm.sh` resolves the Rust source in this order:

1. `ATTESTATION_RS_DIR` if set (a local checkout), else
2. the sibling `../attestation-rs` checkout, else
3. a fresh clone of `ATTESTATION_RS_REPO` at the pinned ref.

It always builds the pinned commit via a throwaway `git worktree`, so your local
`attestation-rs` branch/working tree is never disturbed. Requires `wasm-pack`
(`cargo install wasm-pack`).

[attestation-rs]: https://github.com/confidential-dot-ai/attestation-rs
