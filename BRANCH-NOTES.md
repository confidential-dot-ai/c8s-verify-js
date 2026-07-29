# `feat/cds-rollup` — branch notes

_Temporary. Delete before merge._

Base: `origin/main`. Commits: `52a56dd` (RTMR[3]), `438a5f6` (attest CDS),
`ab06416` (export `decodePEM`).

> **Build order matters.** This branch needs
> `attestation-rs@feat/wasm-expected-rtmr3` (`af64799`) — the `vendor/attestation-rs`
> submodule pointer is bumped to it here. The built WASM is **gitignored**, so a
> fresh clone builds from whatever the submodule points at. Land attestation-rs
> first; out of order, `npm run build:wasm` produces a verifier without
> `expected_rtmr3` and every verification fails closed with *"RTMR[3] was not
> checked"* — correct behaviour that looks exactly like a bug.

---

## The problem

`verify.ts` **required** `meshCaPem` and said so in its own error message:
*"verification requires meshCaPem pinned out of band"*. The mesh CA was trusted
because an operator sent you the file, and every downstream check — the LB leaf
chaining to it, the identity proof committing to it — rested on that unverified
anchor.

---

## What changed

**RTMR[3] pinning** (`52a56dd`) — `expectedRtmr3` in `VerifyPolicy`, gated so a
pin the WASM never evaluated is refused rather than reported as enforced:

```ts
if (expectedRtmr3 !== undefined && result.rtmr3_match !== true) fail("rtmr3_denied", …)
```

**Attest CDS** (`438a5f6`) — new `src/cdsidentity.ts`:

| `attestCDSIdentity(pem, policy)` | verify CDS's own RA-TLS cert → claims |
|---|---|
| `verifyMeshCA(id, caDER)` | accept a CA only on a digest match |
| `verifyAllowlist(id, rawBytes)` | hash the **raw** response against the attested digest |
| `cdsIdentityPEM(discoveryDoc)` | pull `cds_identity`; absence is an explicit failure |

**`x509.ts` now parses extensions** — it previously ignored them entirely. Values
are kept as raw `extnValue` bytes because REPORTDATA folds the config-claims DER
in **verbatim**; re-encoding before hashing computes a different value for the
same certificate. The extensions block is located by its `[3]` context tag rather
than by position, so a certificate carrying an `issuerUniqueID` cannot make them
silently read as absent, and a duplicate OID is rejected rather than resolved.

---

## Two fail-opens caught here — both worth reading

Both were found by asking **why** a test passed, not whether it passed.

**1. Neither `signature_valid` nor `report_data_match` was enforced.** The WASM
core only *reports* them. Without the report-data check, the evidence is a
genuine quote from *some* TEE, unconnected to that certificate — an attacker
could pair real evidence with a forged mesh-CA or allowlist digest and have it
read as attested. That is the load-bearing check in the whole design and it was
missing. Both are now required explicitly `true`, so a core that never ran a
check is refused rather than read as success.

**2. Three negative tests passed twice for the wrong reason.** First because the
`{platform, evidence}` envelope was passed where the WASM wants the inner
`{quote, cc_eventlog}` object, so everything failed on a deserialize error. Then
because the measurement was read from `result.measurement` instead of
`result.claims.launch_digest`, making it empty — so *"is not in the allowlist"*
was trivially true. Green assertions throughout.

The failure message of every negative is now confirmed to name its intended
cause:

```
wrong measurement  → real digest 9309eaae… reported, not empty
wrong RTMR[3]      → tdx verify: RTMR[3] does not match expected_rtmr3
tampered cert      → quote base64: Invalid symbol 239, offset 3435
wrong mesh CA      → digest 48c57894… ≠ attested 2aa039a5…
allowlist +1 byte  → digest mismatch
```

---

## How this was tested

`npm test` → **135/135**. `npm run check` (typecheck + eslint + prettier) clean.

Fixtures are **live-captured** from the bare-metal TDX cluster and
self-consistent by construction — the certificate's `meshCADigest` and
`allowlistDigest` are SHA-256 of the other two files, which is the property under
test:

```
test/fixtures/cds-identity.pem     CDS's own RA-TLS cert (config-claims v3)
test/fixtures/cds-mesh-ca.pem      the CA it issues under
test/fixtures/cds-allowlist.json   exact bytes of GET /allowlist at that moment
```

That the REPORTDATA transcript matches c8s **byte for byte** is proven by
verification succeeding against a real quote — a fixture-only test would prove
nothing, since a wrong domain separator or length prefix simply fails closed.

Also driven end to end through the **public demo URL** using the vendored bundle
the browser actually loads (see `c8s-verify-poc`).

---

## Error-code design

`_denied` (a check ran and failed) is kept distinct from `_not_attested` (the
target's claims never carried the field). Conflating them would send an operator
hunting a breach when the cluster is simply older.

---

## What is missing / known-open

- **RTMR[1]/[2] are not pinnable** — the WASM exposes only `expected_rtmr3`, so
  the browser pins firmware (MRTD) and deployment (RTMR[3]) but **not the guest
  image**, while the Go CLI pins all three. Needs an `attestation-rs` change.
- **DCAP collateral is skipped** (`collateral_verified=false`): a revoked or
  TCB-outdated platform passes in-browser. Deliberately out of scope.
- **No caching layer yet.** `CDSIdentity.fingerprint` is the intended cache key
  (CDS re-issues on every allowlist change, so a changed fingerprint is exactly
  when to re-attest), but nothing stores it — callers re-attest each time.
- **Downgrade** — replaying an old, internally consistent (cert, allowlist) pair
  is not blocked; only `notAfter` bounds it.
- `attestCDSIdentity` is TDX-only; SNP would need the same treatment.
