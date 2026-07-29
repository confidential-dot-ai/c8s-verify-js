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

- The client generates a 32-byte random nonce and requests attestation.
- The LB's TEE returns fresh evidence committing the nonce, hybrid session keys,
  and its own mesh identity (each LB holds its own CDS-issued leaf), plus proof
  that it holds that leaf's private key.
- After verifying the evidence, measurement, pinned CA, and identity proof, the
  client completes a hybrid quantum-resistant key agreement.

Application traffic then travels inside both ordinary TLS and the attested
AES-256-GCM channel. A malicious outer TLS terminator can relay the exchange but
cannot read or forge the inner traffic.

## Transitive trust

The browser verifies the LB rather than every backend pod. The attested LB
implementation forwards through C8s's in-cluster RA-TLS mesh, so its attested
measurement and cluster identity are the browser's trust boundary. The C8s threat
model documents the separate assumptions and limitations of that internal hop.

## How the protocol binds cluster identity

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
cluster-unique, and the mesh CA certificate is one such value.

**That pin is no longer mandatory.** CDS's own RA-TLS certificate carries hardware
evidence over a `config-claims` extension that commits the SHA-256 of the mesh CA
it issues under, and those claims are folded into the TDX quote's REPORTDATA. So a
verified CDS identity *authenticates* the mesh CA, and the anchor becomes derived
rather than assumed — see [Deriving the mesh CA](#deriving-the-mesh-ca-attesting-cds).

On Intel TDX there is a second, better one: **RTMR[3]**, pinned via
`expectedRtmr3`. It is a runtime measurement register, extended after launch —
on a c8s node, with the operator public key bound at boot, and with any
per-workload measurements chained on top. That makes it cluster-unique for the
same reason the mesh CA key is, but with two advantages:

| | mesh CA pin | RTMR[3] pin |
|---|---|---|
| cluster-unique | yes | yes |
| survives a reinstall | **no** — regenerated inside the CDS TEE | **yes** |
| survives an image rebuild | no | yes |
| publishable in advance | awkward: it must first be observed | yes — derived offline from a public key |

So the mesh CA has to be re-pinned every time the cluster is reinstalled,
whereas the operator key is chosen by the operator and can be published ahead of
time (the expected register value is `SHA-384(0x00*48 ‖ SHA-384(pubkey))`).
Pinning both is strictly stronger than either alone; `expectedRtmr3` is optional
only for backwards compatibility, and SNP has no equivalent register, so it is
rejected on any platform other than `"tdx"` rather than silently ignored.

The protocol closes the copied-public-chain gap in two ways:

- Hardware evidence commits to the session keys, client nonce, exact mesh leaf,
  and issuing CA in one domain-separated transcript.
- The mesh leaf signs that transcript, proving possession of the corresponding
  private key. Copying the public certificate chain is no longer sufficient.

The identity signature is ECDSA, so authentication is currently classical. The
channel key combines X25519 and ML-KEM-768; its recorded-traffic confidentiality
is post-quantum as long as ML-KEM-768 remains secure. The derived anchor described below is that
measurement-driven replacement: it still commits to a cluster-unique value, but
the commitment is checked rather than trusted.

## Library

`c8s-verify` is a zero-build ES-module library (browser + Node ≥ 20). Verification
of the LB's hardware evidence runs in your browser via the
[`attestation-rs`](https://github.com/confidential-dot-ai/attestation-rs) TEE
verifier compiled to WebAssembly — AMD SEV-SNP and Intel TDX, bare metal or
Azure vTPM-wrapped (bundled AMD/Intel trust roots, no network). The only
runtime dependency is [`mlkem-wasm`](https://github.com/dchest/mlkem-wasm) for
ML-KEM-768. The exact wire formats are specified in [`PROTOCOL.md`](./PROTOCOL.md).

```sh
npm install c8s-verify
```

```js
import { C8sClient } from "c8s-verify";

const client = new C8sClient({
  baseUrl: "https://lb.example.com",
  measurements: ["<expected hex SHA-384 launch digest>"], // pinned out of band
  meshCaPem: pinnedMeshCaPem,                              // pinned CDS/mesh CA anchor
  //   ^ or drop it and pass `cdsIdentity` instead, to derive the anchor from
  //     attested claims. Exactly one of the two is required.
  // Intel TDX only. Pins the deployment, not just the build: RTMR[3] carries the
  // operator key bound at launch, so a genuine-but-someone-else's cluster running
  // the same audited image is rejected. SHA-384(0x00*48 ‖ SHA-384(operator pubkey)).
  platform: "tdx",
  expectedRtmr3: "<expected hex SHA-384 RTMR[3]>",
});

// Generates a nonce, fetches the LB attestation, verifies the TEE evidence,
// measurement, identity-bound report_data, pinned mesh certificate chain, and
// leaf proof of possession, then runs the X25519+ML-KEM-768 handshake.
const session = await client.connect();
console.log(session.attestation.measurement, session.attestation.cert.sha256);

// All traffic on `session.fetch` is end-to-end encrypted to the LB's enclave,
// underneath whatever TLS terminator sits in front of it.
const res = await session.fetch("/v1/chat", { method: "POST", body: prompt });
console.log(res.text());
```

Attestation and the handshake run **once per session**, not per request: the
`Session` holds the derived AES-256-GCM channel and its LB session id, and
every `session.fetch` reuses them. The LB keeps the session for its
`--session-ttl` idle window (default 5 minutes, refreshed on use); after it
expires a tunnel request fails with a typed `channel_error` (HTTP 401), and the
embedding app re-runs `client.connect()` to attest a fresh session.

What is verified, and in what order: nonce echo → response is identity-bound v1 → served leaf
chains to a mesh CA pinned out of band → hardware signature + certificate chain
(WASM; SEV-SNP VCEK or TDX DCAP, per the policy `platform`) →
launch measurement ∈ a non-empty allowlist → `report_data` commits the session
keys, nonce, leaf, and CA → leaf proof-of-possession signature. The same transcript
is the HKDF context. Any failure throws a typed `C8sVerifyError` and no channel
is established.

### Lower-level: verifying bare evidence

If you obtain TEE evidence through your own transport (e.g. a discovery document)
rather than a c8s-verify challenge-response bundle, use `verifyEvidence`
(`platform`: `"snp"` | `"az-snp"` | `"az-tdx"` | `"tdx"`).
It runs the same hardware verification + measurement/platform checks, and — when
you pass `expectedReportData` — the `report_data` binding, but requires no bundle,
nonce, session key, or CDS certificate (do any cluster-identity / mesh-CA chaining
yourself). The raw WASM entrypoints (`verifySnp`, `verifyAzSnp`, `verifyAzTdx`,
`verifyTdx`) are also exported for full control.

```js
import { verifyEvidence } from "c8s-verify";

const r = await verifyEvidence(evidence /* { attestation_report, cert_chain:{ vcek } } */, {
  generation: "genoa",                 // "milan" | "genoa" | "turin"
  measurements: ["<expected hex SHA-384 launch digest>"],
  expectedReportData,                  // optional Uint8Array; e.g. SHA-384(cert_spki ‖ challenge)
});
console.log(r.measurement, r.reportDataMatch, r.claims);
```

## Deriving the mesh CA (attesting CDS)

The mesh CA used to be trusted because an operator sent you the file. It does not
have to be. CDS runs in its own TEE and its RA-TLS certificate carries a
`config-claims` extension (OID `1.3.6.1.4.1.59888.1.3`) committing:

| claim | what it pins |
|---|---|
| `meshCaDigest` | SHA-256 of the mesh CA CDS issues under (claims v2+) |
| `allowlistDigest` | SHA-256 of the allowlist CDS is serving **now** (claims v3+) |
| `operatorKeysDigest` | the operator key set authorized to mutate the allowlist |
| `seedDigest` | the allowlist seed loaded at boot |

Those claim bytes are folded into the TDX quote's REPORTDATA together with the
certificate's public key, so the evidence vouches for *this certificate carrying
exactly these claims*. Verify it once and both the CA and the admission policy
become derived values.

```js
import { C8sClient, attestCDSIdentity, verifyAllowlist, MemoryCDSIdentityCache } from "c8s-verify";

// `cds_identity.certificate_pem` from the front door's discovery document. It is
// safe to fetch from an untrusted front door: it is self-authenticating, so a
// substituted or edited copy simply fails to verify.
const client = new C8sClient({
  baseUrl: "https://lb.example.com",
  measurements: ["<expected LB launch digest>"],
  cdsIdentity: {
    certificatePem: discovery.cds_identity.certificate_pem,
    policy: {
      measurements: ["<expected CDS launch digest>"], // required, and non-empty
      expectedRtmr3: "<expected RTMR[3]>",            // recommended
    },
    cache: new MemoryCDSIdentityCache(),              // optional, see below
  },
});
const session = await client.connect();
```

The client matches the attested `meshCaDigest` against the certificates the server
serves beside its leaf and pins **exactly that one certificate**, re-encoded on its
own. It never pins the served chain: hardware vouched for one certificate, and
trusting the bundle it arrived in would trust every block in it. `meshCaPem` and
`cdsIdentity` are mutually exclusive — pass exactly one.

To check the served allowlist against the same attested claims:

```js
const id = await attestCDSIdentity(discovery.cds_identity.certificate_pem, {
  measurements: ["<expected CDS launch digest>"],
});
const res = await fetch("https://lb.example.com/allowlist");
// The RAW response bytes — CDS commits SHA-256 over the canonical bytes it
// serves, so a re-serialized copy is a different digest.
await verifyAllowlist(id, new Uint8Array(await res.arrayBuffer()));
```

### Caching, and refusing a downgrade

CDS re-issues its certificate whenever the live allowlist changes, so the
certificate fingerprint is an exact invalidation signal — no staleness window to
tune. `attestCDSIdentityCached` uses it, and does one thing plain attestation
cannot: it remembers the last verified `notBefore` and **refuses a certificate
older than one already seen**.

That matters because a single attestation cannot tell yesterday's genuine
certificate from today's. Yesterday's certificate and yesterday's allowlist are
internally consistent and correctly signed by real hardware; the only thing wrong
with the pair is that a newer one exists. Replaying it rolls the admission policy
back. Comparing issuance times turns that into something checkable.

```js
import { attestCDSIdentityCached, StorageCDSIdentityCache } from "c8s-verify";

const cache = new StorageCDSIdentityCache(localStorage); // survives reloads
const id = await attestCDSIdentityCached(pem, policy, cache, "lb.example.com");
if (id.cached) console.log("reused a verified verdict; no WASM ran");
```

A rollback throws `cds_identity_rollback`, naming both fingerprints and both
timestamps. Set `policy.allowRollback` for a deliberate re-bootstrap (cluster
reinstalled, CDS re-keyed).

The comparison is only sound because `attestCDSIdentity` verifies the
certificate's **self-signature** against the SPKI that REPORTDATA binds. The
validity window sits outside the transcript, so without that check `notBefore` is
attacker-chosen — and so was `notAfter`, which meant a genuine certificate could
be given a 2099 expiry and replayed forever.

### Error codes

| code | meaning |
|---|---|
| `cds_identity_missing` | the discovery document carries no `cds_identity` |
| `cds_identity_invalid` | not a parseable CDS RA-TLS certificate |
| `cds_identity_denied` | a check ran and failed (evidence, report-data binding, RTMR[3], measurement) |
| `cds_identity_unsigned` | the certificate body is not signed by the attested key |
| `cds_identity_expired` | outside its validity window at the reference time |
| `cds_identity_rollback` | older than a certificate already verified under this cache key |
| `mesh_ca_denied` / `allowlist_denied` | digest mismatch against the attested claims |
| `mesh_ca_not_attested` / `allowlist_not_attested` | the claims predate the field (v1/v2), so nothing to check against |

`_denied` and `_not_attested` are deliberately distinct: the first is a check that
ran and failed, the second is a cluster older than the claim. Conflating them
would send an operator hunting a breach that is really an upgrade.

> **Server side.** Deriving the mesh CA needs a CDS that emits claims v2+ and
> publishes `cds_identity` in its discovery document. That runtime lives on the
> c8s `feat/cds-identity-claims` branch; against an older cluster
> `cdsIdentity` fails closed with `cds_identity_missing` or
> `mesh_ca_not_attested`, and `meshCaPem` remains the way to anchor.

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
  it serves `/.well-known/c8s/attestation` + the over-encryption handshake and
  returns the exact identity chain in each bundle; a bundle is fetched once per
  session, so the chain does not ride every application request. Go↔JS interop
  is verified end to end (`c8s/pkg/overenc`, `c8s/internal/cmds/cdsattest`).
- **Pending (tracked separately):** the live `--attestation-service-url` binding on a
  real TEE node, routing over-encrypted *application* traffic through nginx to the
  sidecar (today the standalone sidecar handles it directly), and the `TEErminator`
  Flow B/C HTTP clients (Flow A + session caching are done).
