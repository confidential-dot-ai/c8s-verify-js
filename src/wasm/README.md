# `src/wasm/` — the attestation-rs verifier (generated, not committed)

This directory holds the WebAssembly build of the attestation-rs SNP / TDX
verifier that `src/wasm-loader.ts` imports. **The `.wasm`/`.js` artifacts are
generated, not committed** — they are `.gitignore`d. A fresh checkout has no
verifier until you build it from the in-tree source submodule:

```sh
git submodule update --init vendor/attestation-rs   # once, after clone
npm run build:wasm                                  # or: bash scripts/build-wasm.sh
```

The library cannot load (`src/wasm-loader.ts` imports `./attestation_wasm.js`
and `./attestation_wasm_bg.wasm`) and the test suite will fail until this runs.

## Provenance

The verifier is built from the [`attestation-rs`][attestation-rs] crate
`crates/attestation-wasm` with `wasm-pack build --target web`, pinned to a
specific commit so the verifier is reproducible and auditable from Rust source
rather than shipped as an opaque binary in git history:

| | |
|---|---|
| Source | `vendor/attestation-rs` submodule (`confidential-dot-ai/attestation-rs`), `crates/attestation-wasm` |
| Pinned commit | `ae74953d9aa84b507ae08f4038d8c37dae50d33b` |
| Build | `wasm-pack build --target web` |
| Entry points | `evaluate_snp`, `evaluate_az_snp`, `evaluate_az_tdx`, `evaluate_tdx` (the library calls these; the build also exports the generic `evaluate`) |

The pin is the `vendor/attestation-rs` submodule gitlink — there is no separate
pin variable. To move to a newer `attestation-rs`:

```sh
git -C vendor/attestation-rs fetch origin
git -C vendor/attestation-rs checkout <new-commit>
git add vendor/attestation-rs        # records the new gitlink
npm run build:wasm && npm test    # rebuild + verify
```

Update the table above in the same change.

> **Contract.** Rules are values: each `evaluate_*` entry point returns a result
> with one field per rule (`report_data_match`, `rtmr_match`, `min_tcb_met`,
> `crl_ok`, …) and `passed`, which is true only when every rule held. An entry
> point throws only when the evidence cannot be evaluated (chain, signature,
> malformed input or parameters, collateral that fails its own checks). Read
> `passed`: `src/verify.ts` (`enforceVerifierRules`) accepts only
> `passed === true` and uses the failing fields to choose the error code.

## Build inputs

`scripts/build-wasm.sh` builds directly from the `vendor/attestation-rs`
submodule at its checked-out (pinned) commit — no sibling lookup or network
clone. The script initialises the submodule if a fresh checkout skipped it.
Requires `wasm-pack` (`cargo install wasm-pack`).

[attestation-rs]: https://github.com/confidential-dot-ai/attestation-rs
