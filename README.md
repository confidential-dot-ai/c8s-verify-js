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

The client pins the **LB measurement** allowlist out of band, plus one of two
anchors: the **mesh CA certificate** (`meshCaPem`), or the **canonical allowlist
document bytes** (`allowlist`) enforced against the mesh leaf's matched-workload
stamp. It is reasonable to ask why measurement pins alone are not enough.

The reason is identity. The CDS and LB images are open source and reproducible—
that is what makes them auditable, but it also means a valid measurement only proves
*"a genuine instance of the audited code, on real silicon"*, not *"my cluster"*. An
attacker can stand up their own genuine LB enclave (same image, valid measurement, real
VCEK chain, a `report_data` that correctly binds their enclave's session key to your
nonce) and proxy you to it. Every measurement and freshness check passes — you would just
end up with a confidential channel to a genuine-but-attacker-operated LB, forwarding to
*their* backend pods.

The two anchors answer that differently, and the result reports which one you got
(`attestation.trustClass`):

- **`meshCaPem` → `"specific-cluster"`.** The mesh CA key is generated inside
  the CDS TEE and unique per cluster; pinning its certificate identifies *your*
  cluster. It must be re-pinned after a reinstall or a no-handoff CDS restart.
- **`allowlist` → `"deployment-class"`.** No CA file is distributed: the mesh CA
  is derived from the identity transcript's hardware-bound commitment, and the
  chain-verified leaf's matched-workload stamp must commit SHA-256 of exactly
  the pinned canonical allowlist bytes, with the stamped name resolving in that
  document. This proves "a genuine instance of this measured deployment running
  an admitted workload" — it cannot distinguish your cluster from a genuine
  clone booted from the same measured images and policy, which is why the
  verdict is named what it is. Pinning both anchors is strictly stronger.

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
rejected on the SNP platforms rather than silently ignored. "TDX" here is the
platform family — `"tdx"`, `"az-tdx"`, `"gcp-tdx"` — as c8s's
`ratls.NormalizePlatform` defines it: Azure TDX carries the same registers, so
it takes the same pins.

TDX also changes what a complete *image* pin looks like. `measurements` pins the
launch digest, which on TDX is MRTD — a measurement of the TDVF firmware only:
the guest kernel lands in RTMR[1] and the guest rootfs in RTMR[2], so two
different guest images built against the same firmware share an MRTD. A
platform-complete image pin is therefore the tuple **mrtd + rtmr1 + rtmr2**,
published in the image build's manifest — pass it as `tdxImage` (or feed the
manifest file to `parseImageManifest`; each field is exactly 96 lowercase hex
chars, all three required). The tuple's `mrtd` joins the `measurements`
allowlist and `rtmr1`/`rtmr2` are compared exactly against the verified claims
(`rtmr_denied` on divergence, failing closed if the claims cannot be compared).
A deployment-class verdict — where the measurement policy is the entire anchor —
rejects an MRTD-only TDX policy with `measurement_incomplete`; with a pinned
mesh CA the gap is a prominent warning instead. On SEV-SNP the launch
measurement already covers the whole image, and the platform has no
runtime-register equivalent by design, so `tdxImage` is TDX-family-only (see
above) and rejected on the SNP platforms.

On SEV-SNP the response also declares its own processor `generation`. That is
the one responder-supplied field reaching a verification decision, and it is
authenticated rather than believed: it selects the VCEK/ASK/ARK chain the
report is verified against, so a wrong value fails that chain instead of
weakening anything. Pin it with `generation: "milan" | "genoa" | "turin"` when
you want a disagreement reported as a policy decision rather than inferred from
a chain failure. `platform: "snp"` only — az-snp detects it from the report
CPUID and TDX has no generation, so a pin elsewhere is rejected rather than
dropped.

The protocol closes the copied-public-chain gap in two ways:

- Hardware evidence commits to the session keys, client nonce, exact mesh leaf,
  and issuing CA in one domain-separated transcript.
- The mesh leaf signs that transcript, proving possession of the corresponding
  private key. Copying the public certificate chain is no longer sufficient.

The identity signature is ECDSA, so authentication is currently classical. The
channel key combines X25519 and ML-KEM-768; its recorded-traffic confidentiality
is post-quantum as long as ML-KEM-768 remains secure.

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
import { C8sClient, parseImageManifest } from "c8s-verify";

const client = new C8sClient({
  baseUrl: "https://lb.example.com",
  measurements: ["<expected hex SHA-384 launch digest>"], // pinned out of band
  meshCaPem: pinnedMeshCaPem,                              // specific-cluster anchor
  //   ^ or/and pass `allowlist` (the exact canonical allowlist bytes) for a
  //     deployment-class anchor enforced against the mesh leaf's
  //     matched-workload stamp. At least one of the two is required.
  workloadName: "sglang-kimi-k3",                          // optional workload pin
  // Intel TDX only. Pins the deployment, not just the build: RTMR[3] carries the
  // operator key bound at launch, so a genuine-but-someone-else's cluster running
  // the same audited image is rejected. SHA-384(0x00*48 ‖ SHA-384(operator pubkey)).
  platform: "tdx",
  expectedRtmr3: "<expected hex SHA-384 RTMR[3]>",
  // Intel TDX only. The complete image pin: MRTD covers just the TDVF firmware,
  // so the guest kernel (rtmr1) and rootfs (rtmr2) are pinned with it as one
  // tuple, taken from the image build's manifest. Required for a
  // deployment-class verdict (no meshCaPem).
  tdxImage: parseImageManifest(imageManifestBytes),
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

What is verified, and in what order: nonce echo → response version is exactly
`c8s/attest-pq/v1` → served leaf chains to the pinned or transcript-derived mesh
CA → hardware signature + certificate chain (WASM; SEV-SNP VCEK or TDX DCAP, per
the policy `platform`) → launch measurement ∈ a non-empty allowlist →
`report_data` commits the session keys, nonce, leaf, and CA → leaf
proof-of-possession signature → matched-workload stamp (only when
`workloadName`/`allowlist` is pinned, and only after everything else passed).
The same transcript is the HKDF context. Any failure throws a typed
`C8sVerifyError` and no channel is established.

**Platform TCB and revocation policy (SEV-SNP).** The hardware verification
enforces the full endorsement-key policy — VEK chain to the bundled AMD
roots, VEK validity period, VMPL/debug rejection, and the VEK's chip-id/TCB
cross-validation against the report — but two checks need caller input,
because measurement pinning cannot provide them:

- `minTcb` pins a minimum SNP TCB (SPLs from AMD security bulletins). Without
  it, a genuine, correctly-measured guest on unpatched platform firmware
  verifies. Below the floor fails with `tcb_denied`.
- `snpCrl` supplies the DER AMD KDS CRL for the deployment's generation
  (`https://kdsintf.amd.com/vcek/v1/<product>/crl`) — the browser cannot
  fetch it itself. The verifier authenticates the CRL against the bundled AMD
  root and rejects stale lists, then requires the VEK to not be revoked
  (`collateral_denied` otherwise). Without it, revocation is not checked: the
  result says so (`collateralVerified: false` plus a warning), and
  `requireCollateral: true` turns that into a `collateral_required` failure
  for production policy.

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

## Verifying the workload (matched-workload stamp)

CDS stamps a mesh leaf with the single allowlist entry whose (digest, argv)
policy the pod's attested container inventory uniquely matched at issuance
(X.509 extension `1.3.6.1.4.1.66378.1.5`). The stamp carries the matched name,
the allowlist store version, and SHA-256 of the canonical allowlist document
the match was decided under.

```js
import { C8sClient } from "c8s-verify";

// The exact canonical allowlist bytes, obtained out of band (or from
// `GET /allowlist`, which serves canonical bytes). Hash-exact: never
// re-serialize the JSON before pinning it.
const allowlist = new Uint8Array(await (await fetch(allowlistUrl)).arrayBuffer());

const client = new C8sClient({
  baseUrl: "https://lb.example.com",
  measurements: ["<expected hex launch digest>"],
  allowlist,                       // deployment-class anchor + policy pin
  workloadName: "sglang-kimi-k3",  // optional: exactly this entry
});
const session = await client.connect();
console.log(session.attestation.trustClass);     // "deployment-class"
console.log(session.attestation.workload?.name); // "sglang-kimi-k3"
```

The checks run only after every identity check has passed, in this order: the
stamp parses (absent → `workload_not_attested`, malformed →
`workload_invalid`), its allowlist digest equals SHA-256 of the pinned bytes
(`allowlist_denied` otherwise), the stamped name equals `workloadName` when
pinned (`workload_denied`), and the stamped name resolves as a key in the
pinned document's `workloads` map (`workload_unresolved`).

An unstamped leaf is a normal lifecycle state — CDS issues membership-only
leaves until a pod's first post-completion renewal resolves the match — so
`workload_not_attested` is distinct from `workload_invalid`: a verifier must
not read damage as absence, and a pinned client fails closed on both.

The lower-level pieces (`parseMatchedWorkload`, `parseAllowlist`,
`resolveWorkload`, `allowlistDigestHex`, `OID_MATCHED_WORKLOAD`) are exported
for callers that obtain certificates through their own transport; the stamp is
CA-vouched, so parse it only off a chain-verified leaf.

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
  it serves `/.well-known/c8s/attest-pq` + the over-encryption handshake and
  returns the exact identity chain in each bundle; a bundle is fetched once per
  session, so the chain does not ride every application request. Go↔JS interop
  is verified end to end (`c8s/pkg/overenc`, `c8s/internal/cmds/cdsattest`).
- **Pending (tracked separately):** the live `--attestation-service-url` binding on a
  real TEE node, routing over-encrypted *application* traffic through nginx to the
  sidecar (today the standalone sidecar handles it directly), and the `TEErminator`
  Flow B/C HTTP clients (Flow A + session caching are done).
