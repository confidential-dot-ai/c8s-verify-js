# `src/wasm/` — the attestation-rs verifier (generated, not committed)

This directory holds the WebAssembly build of the attestation-rs SNP / az-snp
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
| Pinned commit | `13039e857e7124a8a8620c6aacaa7217d73a3958` |
| Build | `wasm-pack build --target web` |
| Entry points | `verify_snp`, `verify_az_snp` |

The pin is the `vendor/attestation-rs` submodule gitlink — there is no separate
pin variable. To move to a newer `attestation-rs`:

```sh
git -C vendor/attestation-rs fetch origin
git -C vendor/attestation-rs checkout <new-commit>
git add vendor/attestation-rs        # records the new gitlink
npm run build:wasm && npm test    # rebuild + verify
```

Update the table above in the same change.

> **az-snp contract note.** As of this pin, `verify_az_snp` *fails closed* — it
> **throws** on a freshness (TPM quote `extraData`) mismatch rather than
> returning a non-throwing `report_data_match: false`. The policy layer
> (`src/verify.ts`) catches that throw and surfaces it as the `report_data_mismatch`
> error code. Bare `verify_snp` still returns a non-throwing bool. If you bump the
> pin and that contract changes, revisit `isFreshnessMismatch` in `src/verify.ts`.

## Build inputs

`scripts/build-wasm.sh` builds directly from the `vendor/attestation-rs`
submodule at its checked-out (pinned) commit — no sibling lookup or network
clone. The script initialises the submodule if a fresh checkout skipped it.
Requires `wasm-pack` (`cargo install wasm-pack`).

[attestation-rs]: https://github.com/confidential-dot-ai/attestation-rs
