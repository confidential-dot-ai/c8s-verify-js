# C8s Verification in Javascript

This repo provides all the tools required to verify that a given API, or workload is effectively running in a C8s trusted execution backed cluster.

## Background

Sadly, raTLS (Remote Attestation TLS) was designed primarily for backend-to-backend (or machine-to-machine) communication. In those scenarios, you control the client (e.g., a Python script, a Go binary) and can configure it to pause the TLS handshake, extract the custom X.509 extension containing the attestation report, verify the hardware signature, and then complete the handshake.

Browsers simply do not expose APIs to do this.

Instead, we need to establish a secure channel with a remote enclave in a verifiable way within the existing connection we have with a given API or workload. This is done by relying on over-encryption with keys that are attested to have been securely generated in a secure enclave.

## Our design

Instead of putting the attestation in the TLS certificate, you serve it via a standard HTTPS API endpoint through a classical challenge-response mechanism:

- The Challenge: The JavaScript client generates a cryptographically secure random nonce and sends it to the LB: `GET /attestation?nonce=<random_string>`
- The Response: The TEE of the LB includes the client's nonce and its ephemeral public key, asks the hardware to generate a fresh attestation report binding both, and returns the report to the browser as a JSON payload.
- The Key Agreement: the user can now proceed with a key agreement mechanism using their own, locally generated keypair and the attested public key of the LB.

All future communication will now proceed over a doubly-encrypted channel: TLS is used to connect to the LB, and the shared key established above is used to ensure communication to the LB goes to a secure enclave rather than a malicious TLS terminating proxy in front of the real LB, relaying the attestation reports back to the user.

## On the transitivity of Trust

Trust can be transitive in some cases, this is one such cases: as soon as an attested LB has been contacted, the user can be assured that LB will only talk to other attested pods, through raTLS.

This is because both the Load Balancer and the Certificate Delivery Service are open source Confidential.AI products, meaning anyone can verify their code, and their images and trust they are unable to do anything but what they have been designed for, and that includes only talking to other attested pods within a C8s cluster.

Since the LB certificates chains to the CDS CA certifcate and so do all other pods within a given cluster, relying on either the LB or the CDS as a single point of trust to establish trust in the other components of the cluster does not impact the threat model of C8s.

## Why we pin the mesh CA certificate (for now)

Today the client pins two things out of band: the **LB measurement** allowlist and the
**mesh CA certificate** (see `meshCaPem` in the example below). It is reasonable to ask
why we pin a certificate at all, rather than simply pinning the known-good image hashes
of the CDS and LB and letting attestation carry the rest.

The reason is cluster identity. The CDS and LB images are open source and reproducible —
that is what makes them auditable, but it also means a valid measurement only proves
*"a genuine instance of the audited code, on real AMD silicon"*, not *"my cluster"*. An
attacker can stand up their own genuine LB enclave (same image, valid measurement, real
VCEK chain, a `report_data` that correctly binds their enclave's session key to your
nonce) and proxy you to it. Every measurement and freshness check passes — you would just
end up with a confidential channel to a genuine-but-attacker-operated LB, forwarding to
*their* backend pods. The one value that is unique per cluster is the **mesh CA key**,
which is generated inside the CDS TEE; image hashes are not. So we have to pin *something*
cluster-unique, and today that something is the mesh CA certificate.

## Where we're headed: a measurement-driven anchor

Pinning a certificate is operationally awkward (rotation, expiry), and the cluster-unique
value does not actually have to be a PEM — it only has to be a hash we can attest. The
planned direction is:

1. **Bind the LB leaf into the attestation.** Extend the LB's `report_data` (or
   `init_data`) to commit to its mesh-CA-issued leaf certificate, e.g.
   `SHA-384(session_pubkey ‖ nonce ‖ leaf_spki)`, so that "chains to my mesh CA" is welded
   to "this is the enclave that produced the session key" rather than being a separate,
   independently-served check.
2. **Move the cluster-unique anchor into measured config.** Instead of a pinned PEM, pin
   the **CDS measurement plus a per-cluster identity** carried in the CDS's attested
   `init_data` / `host_data` (this could be the mesh CA SPKI hash itself).
3. **Fetch the certificate dynamically.** The LB returns its own evidence *and* a CDS
   attestation binding the current mesh CA public key; the client verifies the CDS
   measurement + config, trusts the freshly fetched mesh CA, and checks the (now
   attestation-bound) LB leaf chains to it.

The result is a "verify attestation, then fetch the right certificate" flow with **no
pinned certificate** and free cert rotation — the only pinned values are hashes. The key
constraint we cannot remove is that exactly one of those hashes must encode a
cluster-unique identity, because the images alone are deliberately fungible across
deployments.

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
  // cdsCertPath defaults to "/.well-known/cds-cert.pem": when the attestation
  // bundle omits cds_cert_pem (nginx serves the leaf statically), the client
  // fetches it from there and chains it to meshCaPem. Set to null to disable.
});

// Generates a nonce, fetches the LB attestation, verifies the SEV-SNP evidence,
// the measurement, the report_data binding and the CDS certificate chain (the
// leaf comes from the bundle, or is fetched from cdsCertPath when absent), then
// runs the X25519+ML-KEM-768 handshake and derives the AES-256-GCM channel.
const session = await client.connect();
console.log(session.attestation.measurement, session.attestation.cert.sha256);

// All traffic on `session.fetch` is end-to-end encrypted to the LB's enclave,
// underneath whatever TLS terminator sits in front of it.
const res = await session.fetch("/v1/chat", { method: "POST", body: prompt });
console.log(res.text());
```

What is verified, and in what order: nonce echo → SEV-SNP signature + VCEK chain
(WASM) → launch measurement ∈ allowlist → `report_data == SHA-384(session_pubkey‖nonce)`
(freshness + key binding) → CDS cert chains to the pinned mesh CA. Any failure throws
a typed `C8sVerifyError` and no channel is established (fail closed).

### Lower-level: verifying bare evidence

If you obtain SNP evidence through your own transport (e.g. a discovery document)
rather than the `c8s-verify/v1` challenge-response bundle, use `verifyEvidence`.
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
