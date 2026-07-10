# C8s Verification in Javascript

This library lets a browser verify that an API is running in an expected C8s
trusted execution environment and establish an encrypted channel to it.

## Background

RA-TLS (Remote Attestation TLS) is designed primarily for machine-to-machine
communication. A native client can inspect a custom X.509 extension, verify its
attestation report, and then complete the TLS handshake.

Browsers simply do not expose APIs to do this.

This library instead establishes an over-encrypted channel whose session keys
are bound to hardware attestation.

## Our design

Instead of putting attestation in the public TLS certificate, the LB exposes a
challenge-response endpoint:

- The client generates a 32-byte random nonce and requests v2 attestation.
- The TEE returns fresh evidence committing the nonce, hybrid session keys, and
  mesh identity, plus proof that it holds the mesh leaf's private key.
- After verifying the evidence, measurement, pinned CA, and identity proof, the
  client completes X25519 + ML-KEM-768 key agreement.

Application traffic then travels inside both ordinary TLS and the attested
AES-256-GCM channel. A malicious outer TLS terminator can relay the exchange but
cannot read or forge the inner traffic.

## Transitive trust

The browser verifies the LB rather than every backend pod. The expected LB
implementation forwards through C8s's in-cluster RA-TLS mesh, so its attested
measurement and cluster identity are the browser's trust boundary. The C8s threat
model documents the separate assumptions and limitations of that internal hop.

## How v2 binds cluster identity

Today the client pins two things out of band: the **LB measurement** allowlist and the
**mesh CA certificate** (see `meshCaPem` in the example below). It is reasonable to ask
why we pin a certificate at all, rather than simply pinning the known-good image hashes
of the CDS and LB and letting attestation carry the rest.

The reason is cluster identity. The CDS and LB images are open source and reproducible—
that is what makes them auditable, but it also means a valid measurement only proves
*"a genuine instance of the audited code, on real AMD silicon"*, not *"my cluster"*. An
attacker can stand up their own genuine LB enclave (same image, valid measurement, real
VCEK chain, a `report_data` that correctly binds their enclave's session key to your
nonce) and proxy you to it. Every measurement and freshness check passes — you would just
end up with a confidential channel to a genuine-but-attacker-operated LB, forwarding to
*their* backend pods. The one value that is unique per cluster is the **mesh CA key**,
which is generated inside the CDS TEE; image hashes are not. So we have to pin *something*
cluster-unique, and today that something is the mesh CA certificate.

The legacy v1 protocol checked that a separately served leaf chained to the pinned
mesh CA, but did not commit that leaf to the attested session key. A genuine
attacker-operated LB could therefore copy the victim cluster's public leaf and CA
bytes and satisfy both independent checks.

V2 closes that gap in two ways:

- Hardware evidence commits to the session keys, client nonce, exact mesh leaf,
  and issuing CA in one domain-separated transcript.
- The mesh leaf signs that transcript, proving possession of the corresponding
  private key. Copying the public certificate chain is no longer sufficient.

The identity signature is ECDSA, so authentication is currently classical. The
channel key combines X25519 and ML-KEM-768; its recorded-traffic confidentiality
is post-quantum as long as ML-KEM-768 remains secure. A future measurement-driven
anchor may replace the pinned CA certificate, but it must still commit to a
cluster-unique value.

## Library

`c8s-verify` is a zero-build ES-module library (browser + Node ≥ 20). Verification
of the LB's hardware evidence runs in your browser via the
[`attestation-rs`](../attestation-rs) AMD SEV-SNP verifier compiled to WebAssembly
(bundled AMD ARK/ASK roots, no network). The only runtime dependency is
[`mlkem-wasm`](https://github.com/dchest/mlkem-wasm) for ML-KEM-768. The exact wire
formats are specified in [`PROTOCOL.md`](./PROTOCOL.md).

```js
import { C8sClient } from "c8s-verify";

const client = new C8sClient({
  baseUrl: "https://lb.example.com",
  measurements: ["<expected hex SHA-384 launch digest>"], // pinned out of band
  meshCaPem: pinnedMeshCaPem,                              // pinned CDS/mesh CA anchor
  // requireClusterIdentity defaults to true and requests the v2 binding.
});

// Generates a nonce, fetches the LB attestation, verifies the SEV-SNP evidence,
// measurement, identity-bound report_data, pinned mesh certificate chain, and
// leaf proof of possession, then runs the X25519+ML-KEM-768 handshake.
const session = await client.connect();
console.log(session.attestation.measurement, session.attestation.cert.sha256);

// All traffic on `session.fetch` is end-to-end encrypted to the LB's enclave,
// underneath whatever TLS terminator sits in front of it.
const res = await session.fetch("/v1/chat", { method: "POST", body: prompt });
console.log(res.text());
```

What is verified, and in what order: nonce echo → response is v2 → served leaf
chains to a mesh CA pinned out of band → SEV-SNP signature + VCEK chain (WASM) →
launch measurement ∈ a non-empty allowlist → `report_data` commits the session
keys, nonce, leaf, and CA → leaf proof-of-possession signature. The same transcript
is the v2 HKDF context. Any failure throws a typed `C8sVerifyError` and no channel
is established.

Old servers can be used only with the explicit
`requireClusterIdentity: false` compatibility downgrade. That accepts v1's
session-to-TEE binding but cannot establish that the TEE belongs to the pinned
cluster. `cdsCertPath` is the legacy fallback for a v1 bundle that omits its leaf.

### Lower-level: verifying bare evidence

If you obtain SNP evidence through your own transport (e.g. a discovery document)
rather than a c8s-verify challenge-response bundle, use `verifyEvidence`.
It runs the same hardware verification + measurement/platform checks, and — when
you pass `expectedReportData` — the `report_data` binding, but requires no bundle,
nonce, session key, or CDS certificate (do any cluster-identity / mesh-CA chaining
yourself). The raw WASM entrypoint `verifySnp` is also exported for full control.

```js
import { verifyEvidence } from "c8s-verify";

const r = await verifyEvidence(evidence /* { attestation_report, cert_chain:{ vcek } } */, {
  generation: "genoa",                 // "milan" | "genoa" | "turin"
  measurements: ["<expected hex SHA-384 launch digest>"],
  expectedReportData,                  // optional Uint8Array; e.g. SHA-384(cert_spki ‖ challenge)
});
console.log(r.measurement, r.reportDataMatch, r.claims);
```

## Demo

A self-contained mock LB lets you run the whole flow offline:

```sh
npm install
npm run build:wasm     # generate the WASM verifier from vendor/attestation-rs (once)
npm run gen-fixtures   # openssl mesh CA + leaf, copies recorded SNP evidence
npm run demo           # compiles TypeScript, then serves the mock LB + demo on http://localhost:8799
```

Open the URL and click **Run verification**. The page walks each step (green/red),
and the *Tamper with evidence* toggle flips a byte of the signed report to show
verification failing closed. The recorded evidence is real hardware-signed SNP
evidence, so the signature, measurement, certificate chain and post-quantum channel
are all genuine; only the live `report_data` key-binding is necessarily simulated
(it requires a real TEE LB to mint a fresh report — see PROTOCOL.md).

## Tests

```sh
npm run build:wasm             # once, if you haven't already (see Demo above)
npm test                       # runs the TypeScript sources via tsx under node:test — crypto, X.509, verification, end-to-end
npm run browser-check          # headless-Chromium run of the demo (needs `npx playwright install chromium`)
```

The library is written in TypeScript (`src/*.ts`) and compiled with `tsc` to a
flat `dist/` (the published `c8s-verify` package points at `dist/index.js` with
bundled `.d.ts` types). `npm run build` runs the compiler. `npm test` and `npm
run demo` run the sources directly via `tsx` (no build step); `npm run
browser-check` compiles a browser bundle first (`npm run build:demo`).

## Status

- **Implemented (client):** the TypeScript library (`src/`), the WASM verifier wiring, the
  PQ over-encryption channel, the mock LB, the browser demo, and the test suite.
- **Implemented (server):** the matching c8s endpoints ship as the `c8s cds-attest`
  sidecar, fronted by the existing tls-lb nginx (chart flag `tlsLb.attest.enabled`):
  it serves `/.well-known/c8s/attestation` + the over-encryption handshake, with
  `cds-cert.pem`/`mesh-ca.pem` served statically by nginx. Go↔JS interop is verified
  end to end (`c8s/pkg/overenc`, `c8s/internal/cmds/cdsattest`).
- **Pending (tracked separately):** the live `--attestation-service-url` binding on a
  real TEE node, routing over-encrypted *application* traffic through nginx to the
  sidecar (today the standalone sidecar handles it directly), and the `TEErminator`
  Flow B/C HTTP clients (Flow A + session caching are done).
