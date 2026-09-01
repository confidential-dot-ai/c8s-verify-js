# c8s-verify wire protocol (`attest-pq`, binding `c8s/attest-pq/v1`)

This document specifies the browser-facing attestation + over-encryption protocol
between a JavaScript client (`c8s-verify-js`) and a C8s **Load Balancer (LB)**.
It is the canonical contract implemented by the Go LB and the JavaScript client.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
**RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be
interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14)
when, and only when, they appear in all capitals.

Conforming implementations MUST reproduce the [interoperability
vectors](#interoperability-vectors) exactly.

## Terminology

| Term | Meaning | c8s component (PLAN.md alias) |
|---|---|---|
| **CDS** | Certificate Distribution Service: verifies TEE evidence, issues EARs, signs leaf certs with an in-process mesh CA | `cert-issuer` / `assam` |
| **mesh CA** | the CA whose key lives only inside the CDS TEE; signs all cluster leaf certs | mesh CA |
| **LB** | the user-facing Load Balancer pod, holding a CDS-issued (TEE-attested) leaf cert | `tls-lb` |
| **measurement / launch digest** | hex SHA-384 of the LB CVM launch state; the user pins an allowlist out of band | — |

## Trust model

The channel used to fetch the bundle (plain HTTPS) is **not trusted** — a malicious
TLS-terminating proxy may sit in front of the real LB. Verification is performed
entirely on the returned payload:

1. The LB returns **raw TEE evidence** (AMD SEV-SNP or Intel TDX, bare metal or
   Azure vTPM-wrapped) whose hardware freshness anchor — `report_data` for the
   bare platforms, the vTPM quote's `extraData` for the Azure ones — binds the
   **complete key exchange** (the client's X-Wing encapsulation key and the
   LB's ciphertext), the session id, the client's nonce, the exact mesh leaf,
   and the issuing mesh CA.
2. The client verifies the evidence **directly in the browser** with the
   `attestation-rs` verifier compiled to WASM (bundled AMD ARK/ASK and Intel
   TDX roots, VCEK/DCAP collateral supplied inline — no network during
   verification).
3. The client checks the measurement against its pinned allowlist, checks that the
   served mesh leaf chains to a **mesh CA** that is either pinned out of band
   (*specific-cluster*) or *derived from the identity transcript's commitment*
   (*deployment-class*, below), and verifies a per-session proof of possession
   made by that leaf key.
4. When a workload policy is pinned, the client then reads the **matched-workload
   stamp** off the chain-verified mesh leaf (see "Matched-workload extension"),
   checks the stamped allowlist digest against its pinned canonical allowlist
   bytes, and resolves the stamped name.
5. Only then does the client decapsulate the attested X-Wing ciphertext and
   derive the **post-quantum hybrid over-encryption channel**, so all
   subsequent application traffic is end-to-end confidential to the LB's TEE
   regardless of the outer TLS terminator. The session is live from the one
   attestation round trip — there is no separate handshake.

The user only verifies the **LB**; C8s's internal RA-TLS mesh transitively vouches for
the backend pods the LB talks to.

### Deriving the mesh CA: deployment-class vs specific-cluster

The mesh CA does not have to be pinned out of band. The identity proof commits
`mesh_ca_sha256`, and that commitment is folded into the hardware-bound identity
transcript and signed by the mesh leaf. With no pin, the client selects from the
served chain (`cds_cert_pem` blocks after the leaf) the certificate whose SHA-256
equals the commitment, and anchors the chain check to exactly that one. Selection
alone trusts nothing; the transcript verification that follows is what
authenticates the choice.

The chain check itself asks more than "does this signature verify". The
responder writes every byte of `cds_cert_pem`, so the selected anchor must also
*be* a certificate that could have issued the leaf: it must carry
`basicConstraints` with `cA=TRUE`, must permit `keyCertSign` if it carries a
`keyUsage` extension at all, must have a subject name byte-identical to the
leaf's issuer name, and must not be the leaf itself. Go's `CheckSignatureFrom`
and `Verify` impose the same rules server-side. Without them, one self-signed
certificate emitted twice would satisfy the chain check and its
matched-workload stamp would be attacker-chosen.

Certificate validity uses the server's window (`certutil.CheckValidity`):
`notBefore` is granted a 5-minute clock-skew allowance, `notAfter` none. CDS
mints leaves at `now` with no backdating and re-reads them per request, so a
verifier whose clock trails the issuing TEE would otherwise reject a leaf that
had just rotated; an expired certificate, by contrast, is simply expired.

The two resulting verdicts are explicitly distinct:

- **Deployment-class** (derived CA): non-empty measurement pins plus exact
  canonical allowlist bytes enforced against the matched-workload stamp. The
  verdict says "a genuine instance of this measured deployment" — public-input
  anchors cannot distinguish "my cluster" from a genuine clone booted from the
  same measured images and serving byte-identical allowlist bytes.
- **Specific-cluster** (pinned CA): the same checks plus `meshCaPem`; the
  committed CA must be one the caller pinned out of band. Optional hardening,
  no longer a requirement.

A verdict from a derived CA MUST never be reported as "my cluster". Deriving the
CA also removes an operational failure mode: a no-handoff CDS restart rotates the
CA, which used to break every external client's pin; a derived CA is simply picked
up at the next session (specific-cluster clients reject until re-pinned, by design).

## Endpoints (LB, plain HTTPS)

All under the `/.well-known/c8s/` namespace.

### `GET /.well-known/c8s/jwks.json`  *(optional)*
Returns the CDS EAR-signing JWKS (ES256, `kid` = RFC 7638 thumbprint), republished from
the CDS, for the optional EAR-verification path.

### `POST /.well-known/c8s/attest-pq`

The client-first attestation + key-exchange request, `application/json`:

```jsonc
{
  "nonce": "<b64url 32-byte fresh random challenge>",
  "xwing_ek": "<b64url 1216-byte X-Wing encapsulation key>"
}
```

Both fields are REQUIRED and exactly sized: the nonce MUST be 32 bytes and
`xwing_ek` MUST be 1216 bytes; anything else is refused with
`400 invalid_request` rather than truncated or padded. Both MUST be fresh per
request; the client MUST NOT reuse a nonce or a keypair across sessions. The
server bounds the request body (8 KiB).

The endpoint takes no other field or parameter — there is **no version, suite,
or binding negotiation and no fallback**: a `GET` (the pre-client-first shape),
the retired two-step `POST /.well-known/c8s/handshake`, and the former
`/.well-known/c8s/attestation` endpoint all return `400 invalid_request`
(no alias, no downgrade).

The response commits the server's X-Wing ciphertext and the minted session id
in the same hardware report as the client's key and nonce, and the session is
established server-side when the response leaves — the exchange completes in
one round trip.

A sibling endpoint, `GET /.well-known/c8s/attest-lb?nonce=…` (binding id
`c8s/attest-lb/v1`), exists for **native clients only**: it binds the exact
outer TLS serving leaf into the hardware evidence and authorizes ordinary TLS
after per-handshake verification. Browsers cannot see peer certificates, so
`c8s-verify-js` neither implements it nor accepts its response shape — a bundle
whose `version` is not exactly `c8s/attest-pq/v1` is rejected even when its
evidence is otherwise valid.

Response is `application/json`:

```jsonc
{
  "version": "c8s/attest-pq/v1",
  "platform": "snp",            // "snp" | "az-snp" | "az-tdx" | "tdx"
  "generation": "genoa",        // AMD gen for the bare-SNP WASM verifier (milan|genoa|turin); empty for the other platforms
  "nonce": "<echoed b64url>",   // MUST equal the request nonce
  "evidence": {                 // attestation-rs SnpEvidence shape (std base64 fields)
    "attestation_report": "<base64 of the 1184-byte SNP report>",
    "cert_chain": { "vcek": "<base64 DER VCEK>" }
  },
  "cds_cert_pem": "-----BEGIN CERTIFICATE-----\n...", // exact mesh leaf + issuing CA
  "ear": "<optional CDS-issued EAR JWT>",             // defined but not yet populated by the LB
  "xwing_ek": "<echoed b64url 1216-byte client encapsulation key>",
  "xwing_ct": "<b64url 1120-byte X-Wing ciphertext>",
  "session_id": "<b64url 16-byte session identifier>",
  "identity_proof": {
    "algorithm": "ecdsa-sha384",
    "leaf_sha256": "<b64url SHA-256 of leaf DER>",
    "mesh_ca_sha256": "<b64url SHA-256 of issuing CA DER>",
    "signature": "<b64url ASN.1 DER ECDSA signature>"
  }
}
```

All `b64url` fields are **unpadded** base64url (RFC 4648 §5 without `=`); the
`signature` is DER — a `SEQUENCE` spanning the whole value, holding exactly two
positive `INTEGER`s without redundant sign padding.

The `evidence` object shape follows the bundle's `platform`: the block above
shows bare `snp`; the vTPM (`az-snp`, `az-tdx`) and bare `tdx` shapes are
specified in their sections below. Everything outside `evidence` (and the
binding recomputation) is platform-independent.

The `version`, `cds_cert_pem`, `xwing_ek`, `xwing_ct`, `session_id`, and
`identity_proof` fields are mandatory. A live client MUST check that `nonce`
and `xwing_ek` exactly echo the values it sent (`xwing_ek` is echoed so a
saved bundle stays verifiable offline; in that offline mode the result is not
a freshness proof). The LB re-reads the TEE-held mesh leaf, private key, and
CA for each request so certificate rotation cannot leave the bundle and proof
on different credential generations. There is no legacy or downgrade path.

#### Report-data and mesh-identity binding

Define `LP(field) = uint32_be(len(field)) || field`, and:

```
leaf_hash = SHA-256(leaf_certificate_DER)
ca_hash   = SHA-256(issuing_mesh_CA_DER)

transcript = LP("c8s-verify/v1")
          || LP(ca_hash(32))
          || LP(leaf_hash(32))
          || LP(xwing_ek(1216))
          || LP(xwing_ct(1120))
          || LP(session_id(16))
          || LP(nonce(32))

transcript_hash = SHA-384(transcript)
report_data      = transcript_hash, then zero-padded from 48 to 64 bytes
```

The transcript commits **both key-exchange messages**: tampering with either
the client's encapsulation key or the server's ciphertext anywhere on the path
changes `transcript_hash` and therefore fails the hardware `report_data`
match, the proof-of-possession signature, and the key schedule (whose salt is
`transcript_hash`) simultaneously.

The transcript's `"c8s-verify/v1"` domain tag is the original protocol name and
is deliberately unchanged by the endpoint move (as are the HKDF info string and
tunnel AADs below): only the bundle's `version` field carries the endpoint
binding id `c8s/attest-pq/v1`.

The 64-byte anchor is identical on every platform: SEV-SNP `report_data` and
the TDX TD-quote `report_data` both carry 64 bytes natively, and the Azure vTPM
platforms carry the same value in the TPM quote's `extraData` (see below).

Most-stable fields come first so an implementation can reuse the hash state up
to the per-session fields.

The LB also signs the transcript hash with the private key for the committed
leaf; the transcript's leading version tag already domain-separates it, so no
second tag is applied:

```
signature = ECDSA-SHA384(leaf_private_key, transcript_hash)
```

The client verifies the hardware evidence against `transcript_hash`, the launch
measurement against its non-empty allowlist, the leaf chain against the pinned
or transcript-derived CA, both certificate fingerprints, and the proof
signature. This defeats
the copied-public-chain attack: a genuine attacker-operated LB can copy the victim
cluster's public certificates, but cannot sign its own session transcript with the
victim leaf's private key.

The identity proof is currently ECDSA, so cluster authentication is **classical**.
The over-encryption key agreement is the X-Wing hybrid KEM (X25519 +
ML-KEM-768): recorded traffic retains post-quantum confidentiality as long as
ML-KEM-768 remains secure, but the protocol does not claim post-quantum
authentication.

> Note: a live LB binds the key exchange into a fresh hardware report per session.
> The demo/mock and the offline test fixtures use **recorded real evidence** with a
> fixed `report_data`; in that mode the client verifies the hardware signature +
> measurement for real and exercises the binding math against the fixture's
> recorded value.

#### `platform: "az-snp"` (Azure Confidential VM, vTPM)

Azure CVMs do not hand back a bare SNP report; the guest receives an **HCL report**
(the SNP report wrapped by the paravisor, with the vTPM AK public key in its runtime
data) plus a **vTPM quote**. The `evidence` object then has the attestation-rs
`AzSnpEvidence` shape (base64url fields):

```jsonc
"evidence": {
  "version": 1,
  "hcl_report": "<base64url HCL report: header + 1184-byte SNP report + runtime data>",
  "vcek":       "<base64url DER VCEK>",
  "tpm_quote": {
    "signature": "<hex RSA-2048 PKCS1v1.5 signature over message>",
    "message":   "<hex TPMS_ATTEST: magic, extraData(=freshness anchor), PCR digest, ...>",
    "pcrs":      ["<hex sha-256>", ... 24 entries]
  }
}
```

For az-snp the identity binding **moves out of the SNP `report_data` into the
vTPM quote's `extraData`**. The SNP `report_data` instead binds the AK to the TEE
(`report_data[..32] == SHA-256(runtime_data)`), and the quote, signed by that AK,
carries the session binding. The client computes the binding specified above and
passes it as `expected_report_data`; the verifier checks it against the quote's
`extraData`. A passing `report_data_match`
therefore proves the same freshness + key-binding property, now rooted in the AK
rather than the bare report. `generation` is auto-detected from the report CPUID and
is not required in the bundle for az-snp.

The `generation` field, the bare-SNP `evidence.attestation_report`/`cert_chain`
shape, and `platform: "az-snp"` are mutually exclusive with the bare-`snp` shape
above: a bundle is one or the other.

#### `platform: "az-tdx"` (Azure Confidential VM, Intel TDX)

Same vTPM construction as az-snp — the `evidence` object has the attestation-rs
`AzTdxEvidence` shape:

```jsonc
"evidence": {
  "version": 1,
  "hcl_report": "<base64url HCL report: header + TD report + runtime data>",
  "td_quote":   "<base64url TD quote from Azure IMDS>",
  "tpm_quote":  { "signature": "<hex>", "message": "<hex TPMS_ATTEST>", "pcrs": [ ... ] }
}
```

The identity binding lives in the vTPM quote's `extraData` exactly as for
az-snp: the client passes the computed binding as `expectedReportData` and the
verifier checks it against the quote `extraData` after binding the AK to the
TD (`td_report.report_data[..32] == SHA-256(runtime_data)`). `generation` is
not applicable and is empty.

#### `platform: "tdx"` (bare-metal Intel TDX)

The `evidence` object has the attestation-rs `TdxEvidence` shape:

```jsonc
"evidence": {
  "quote": "<base64 raw TD quote (v4/v5, embedded PCK chain)>",
  "cc_eventlog": "<optional base64 CCEL event log>"
}
```

The identity binding is carried directly in the TD quote's 64-byte
`report_data`, recomputed exactly as specified above, and the quote signature
is verified against the PCK chain embedded in the quote up to the bundled
Intel root. The async DCAP collateral checks (CRL/TCB/QE identity) are
skipped in the browser (`collateral_verified: false`) — TDX has no
caller-stapled collateral path yet, unlike SNP. `claims.launch_digest` is the TD launch measurement (MRTD);
`generation` is not applicable and is empty. The runtime measurement
registers surface as `claims.platform_data.rtmr_0`…`rtmr_3`, each 96
lowercase hex chars.

**Platform-complete image pinning.** On TDX, MRTD covers only the TDVF
firmware — the guest kernel is measured into RTMR[1] and the guest rootfs
into RTMR[2] — so a complete image pin is the tuple **MRTD + RTMR[1] +
RTMR[2]** from one image-build manifest (a JSON object with `mrtd`, `rtmr1`,
`rtmr2`, each exactly 96 lowercase hex chars; all three required, unknown
extra fields allowed). The policy layer (`tdxImage`, or `parseImageManifest`
over the manifest file) folds the tuple's MRTD into the launch-digest
allowlist and compares `rtmr1`/`rtmr2` exactly against the verified claims,
failing closed on a mismatch or an absent/malformed claim. A
deployment-class verdict rejects an MRTD-only TDX measurement policy; with a
pinned mesh CA the gap is a prominent warning instead. SEV-SNP needs no
equivalent: its launch measurement covers the full image, and the platform
has no runtime measurement registers by design.

## Matched-workload extension (`1.3.6.1.4.1.66378.1.5`)

The mesh leaf MAY carry a non-critical X.509 extension stamping the single
allowlist entry whose (digest, argv) policy the pod's attested container
inventory uniquely matched at issuance:

```
OID 1.3.6.1.4.1.66378.1.5  (matched-workload extension, non-critical)
MatchedWorkload ::= SEQUENCE {
    formatVersion    INTEGER,           -- exactly 1
    name             IA5String,         -- 1..63 bytes, [A-Za-z0-9][A-Za-z0-9._-]*
    allowlistVersion IA5String,         -- 1..20 ASCII decimal digits, no leading zero
    allowlistDigest  OCTET STRING (32)  -- SHA-256 of the canonical allowlist bytes
}
```

The stamp is CA-vouched: it sits in the CA-signed area, so it is meaningful only
on a chain-verified leaf. On the LB's own leaf it is additionally evidence-bound,
because the exact leaf DER is committed by the identity transcript.

Normative parser rules (shared with c8s `pkg/ratls` and TEErminator):

- minimal DER only, with no trailing bytes or fields;
- exactly one extension with this OID — duplicates fail closed;
- `formatVersion == 1`; unknown versions fail closed whenever workload identity
  is requested;
- name and version strings match the grammars above exactly; the digest is
  exactly 32 bytes;
- an unpinned diagnostic may report only that an unparseable extension exists,
  never any unverified field from it.

Cross-implementation golden vector — the one canonical encoding of
`{v1, name "api", allowlistVersion "7", digest 0x11×32}`:

```
302d0201011603617069160137
04201111111111111111111111111111111111111111111111111111111111111111
```

A client pinning a workload policy verifies, only after every identity check
has passed: parse the stamp (absent ⇒ `workload_not_attested`, malformed ⇒
`workload_invalid`), check `allowlistDigest` against SHA-256 of the **exact
canonical allowlist bytes** it holds (mismatch ⇒ `allowlist_denied`; the bytes
are hashed verbatim, never re-serialized), check the stamped name against an
explicit `workloadName` pin (mismatch ⇒ `workload_denied`), and resolve the
stamped name as a key lookup in the held document's `workloads` map (absent ⇒
`workload_unresolved`).

## WASM verifier I/O (`attestation-rs` `verify_snp`)

```
verify_snp(evidenceJson: string, generation: "milan"|"genoa"|"turin",
           expectedReportData?: Uint8Array, minTcbJson?: string,
           crlDer?: Uint8Array) -> string (JSON) | throws
```

- **Throws** (JsError) if any enforced check fails: the VEK chain to the
  bundled AMD roots (ARK → ASK → VCEK, or ARK → ASVK → VLEK, auto-detected),
  the VEK validity period, the report signature, VMPL != 0 or debug policy,
  the VEK's chip-id/TCB certificate-extension cross-validation against the
  report, a reported TCB below the `minTcbJson` floor
  (`{ "bootloader": N, "tee": N, "snp": N, "microcode": N, "fmc"?: N }`), or
  — when `crlDer` is supplied — a CRL whose ARK signature, thisUpdate/
  nextUpdate freshness window, or revocation status rejects the VEK. These
  are the same endorsement and platform-security checks the native SNP
  verifier enforces; only VEK network fetching is out (the VEK is inline).
- On success returns:
  ```jsonc
  {
    "signature_valid": true,
    "platform": "snp",
    "report_version": 3,
    "report_data_match": true,        // bool, or null if no expected provided
    "collateral_verified": false,     // true iff a CRL was supplied and checked
    "claims": {
      "launch_digest": "<hex sha-384>",
      "report_data": "<hex 64 bytes>",
      "signed_data":  "<hex>",
      "init_data":    "<hex>",
      "tcb": { "type": "Snp", "bootloader": N, "tee": N, "snp": N, "microcode": N },
      "platform_data": { ... }
    }
  }
  ```

The JS policy layer treats verification as **passed** iff: `verify_snp` did not throw
(`signature_valid === true`), `report_data_match === true`, `platform` is acceptable, and
`claims.launch_digest` ∈ the caller's measurement allowlist (case-insensitive hex).

**Revocation collateral is caller-supplied.** The browser cannot reach AMD
KDS, so the CRL for the deployment's generation
(`https://kdsintf.amd.com/vcek/v1/<product>/crl`) is fetched or stapled by the
caller and passed as `snpCrl` in the JS policy. The bytes need no transport
trust — the verifier authenticates them against the bundled ARK and rejects
stale or future-dated lists — but *absence* is honest: without a CRL the
result carries `collateral_verified: false`, the JS layer surfaces
`collateralVerified: false` plus a warning, and `requireCollateral` turns
that into a `collateral_required` failure for production policy. A supplied
CRL that cannot be positively verified fails closed (`collateral_denied`),
never as "skipped". A minimum TCB floor (`minTcb`, from AMD security
bulletins) closes the remaining platform gap: measurement pinning alone
accepts a genuine, correctly-measured guest on unpatched firmware.

## WASM verifier I/O (`attestation-rs` `verify_az_snp`)

```
verify_az_snp(evidenceJson: string, expectedReportData?: Uint8Array,
              expectedInitDataHash?: Uint8Array, minTcbJson?: string,
              crlDer?: Uint8Array) -> string (JSON) | throws
```

Full Azure vTPM verification of an `AzSnpEvidence` object (above). Unlike `verify_snp`
it takes no `generation` (auto-detected) and verifies the vTPM quote in addition to the
hardware report:

1. TPM quote signature against the AK extracted from the HCL runtime data.
2. Quote `extraData` == `expectedReportData` (the freshness anchor).
3. PCR digest integrity, and optionally `expectedInitDataHash` bound to PCR[8].
4. AK-to-TEE binding: `snp.report_data[..32] == SHA-256(runtime_data)`.
5. VCEK chain to the bundled AMD roots, VCEK validity period, SNP report
   signature, VMPL/debug/TCB policy, and the optional `minTcbJson` floor.
6. When `crlDer` is supplied: the AMD KDS CRL's ARK signature and freshness,
   then the VCEK's revocation status (same semantics as `verify_snp`).

- **Throws** (JsError) if any check fails.
- On success returns the same shape as `verify_snp` with `platform: "az-snp"`;
  `collateral_verified` is true iff a CRL was supplied and checked, and
  `report_data_match` reflects the quote `extraData`, not the SNP report_data.

The JS policy layer applies the **same** pass/fail rule as for `verify_snp`.

## WASM verifier I/O (`attestation-rs` `verify_az_tdx`, `verify_tdx`)

```
verify_az_tdx(evidenceJson: string, expectedReportData?: Uint8Array,
              expectedInitDataHash?: Uint8Array) -> Promise<string (JSON)> | throws
verify_tdx(evidenceJson: string, expectedReportData?: Uint8Array,
           expectedInitDataHash?: Uint8Array) -> Promise<string (JSON)> | throws
```

`verify_az_tdx` mirrors `verify_az_snp` for an `AzTdxEvidence` object: full
vTPM quote verification with `extraData == expectedReportData` as the
freshness anchor, AK-to-TD binding, and TD-quote signature verification.
`verify_tdx` verifies a bare `TdxEvidence` TD quote (embedded PCK chain to the
bundled Intel root) and checks `expectedReportData` against the quote's
`report_data`. Both fail closed (throw) on a freshness mismatch, take no
`generation`, surface the MRTD as `claims.launch_digest`, and return
`collateral_verified: false` — the browser has no TDX collateral path (the
DCAP CRL/TCB/QE checks need Intel PCS collateral the caller cannot yet
staple), unlike the SNP entry points, which accept a caller-supplied AMD CRL.
The JS layer surfaces the gap as `collateralVerified: false` plus a warning.

The JS policy layer applies the **same** pass/fail rule as for `verify_snp`.

## Over-encryption channel (post-quantum hybrid)

Key agreement is **X-Wing**
([draft-connolly-cfrg-xwing-kem-10](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10)):
X25519 + ML-KEM-768 under the draft's SHA3-256 combiner, which binds the
X25519 ciphertext and recipient key into the shared secret. Byte lengths:
encapsulation key 1216 (ML-KEM-768 ek 1184 ‖ X25519 pk 32), ciphertext 1120
(ML-KEM-768 ct 1088 ‖ X25519 ephemeral pk 32), shared secret 32. An
incompatible X-Wing revision MUST NOT reuse this protocol's identifiers.

1. Client generates a fresh X-Wing keypair and sends `xwing_ek` in the
   attest-pq POST (above).
2. Server encapsulates — `(xwing_ct, ss) = X-Wing.Encaps(xwing_ek)` — and
   commits `xwing_ek`, `xwing_ct`, and the minted `session_id` in the
   transcript.
3. Client verifies the bundle (echoes, evidence, chain, proof), then
   decapsulates: `ss = X-Wing.Decaps(dk, xwing_ct)`. Decapsulation MUST use
   the draft's implicit rejection: an invalid ciphertext yields a
   non-matching secret, never an error, so the divergence surfaces as an AEAD
   failure on the first record rather than as a decapsulation oracle.
4. Both ends derive the key schedule with **HKDF-SHA256**, `ikm = ss`,
   `salt = transcript_hash` (48 bytes), one output per exact `info` string:

   | Output | `info` (exact ASCII) | Length |
   |---|---|---:|
   | `c2s_key` | `c8s-verify/v1/c2s-key` | 32 |
   | `s2c_key` | `c8s-verify/v1/s2c-key` | 32 |
   | `c2s_iv` | `c8s-verify/v1/c2s-iv` | 4 |
   | `s2c_iv` | `c8s-verify/v1/s2c-iv` | 4 |
   | `exporter` | `c8s-verify/v1/exporter` | 32 |

   `c2s_key`/`s2c_key` are AES-256-GCM keys (client-to-server /
   server-to-client); `c2s_iv`/`s2c_iv` are the per-direction nonce prefixes.

**Channel-binding exporter.** `exporter` is derived by both ends and never
sent on the wire; because the HKDF salt is the identity transcript hash, it is
bound to the attested identity and to this exact session. The LB forwards it
to the backend as the `X-C8s-Exporter` header (b64url, stripping any
client-supplied value first), so an application MAY bind bearer credentials to
it: a token bound to one channel's exporter is useless replayed over any other
channel.

## Over-encrypted application tunnel

All application traffic flows through a single endpoint, **`POST /.well-known/c8s/tunnel`**,
with header `X-C8s-Session: <session_id>` and `Content-Type: application/cbor`. The body
and the response are **CBOR** (RFC 8949), not JSON — so the body and the AES-GCM
ciphertext ride as raw byte strings with no base64 inflation. The body is one
AES-256-GCM record, a CBOR map with an unsigned sequence number and a
byte-string ciphertext:

```cbor
{ "seq": <uint ≥ 1>, "ct": h'<ciphertext+tag>' }
```

Record protection, for direction `dir` (`c2s` for requests, `s2c` for
responses) and sequence `seq`:

```
nonce = iv(dir)(4) || be64(seq)                 // deterministic 96-bit GCM nonce
AAD   = tag(dir) || session_id(16) || be64(seq)
        tag(c2s) = "c8s-verify/v1/tunnel-request"
        tag(s2c) = "c8s-verify/v1/tunnel-response"
ct    = AES-256-GCM-Seal(key(dir), nonce, plaintext, AAD)
```

The client allocates request sequences starting at 1, strictly increasing;
sequence 0 is invalid in both directions. **A response record MUST echo its
request's sequence**, and the client MUST reject a response whose sequence
does not equal the request it answers — this is what stops the untrusted
terminator crossing the responses of two concurrent requests. The server
enforces a 64-record sliding replay window over authenticated request
sequences: a duplicate, or a sequence 64 or more positions behind the highest
accepted one, is rejected. Clients SHOULD keep fewer than 64 requests
outstanding so reordered valid requests cannot fall outside the window. A
sequence MUST NOT be reused under one session's keys.

The **entire request** is sealed — method, path, headers, and body — so a
TLS-terminating proxy in front of the LB sees only ciphertext (not even the path or
`Authorization` header). The sealed plaintext is a CBOR envelope (`body` is a CBOR byte
string; absent/empty when there is no body). Headers ride as an ordered array of
`[name, value]` pair arrays, so duplicate fields (`Set-Cookie`) and field order
survive the tunnel:

```cbor
// request
{ "method": "POST", "path": "/v1/chat",
  "headers": [["cookie", "a=1"], ["cookie", "b=2"]],
  "body": h'<raw request body>' }

// response
{ "status": 200, "headers": [["set-cookie", "a=1"], ["set-cookie", "b=2"]],
  "body": h'<raw response body>' }
```

**Session lifetime.** The session (and its key schedule) is established once —
one attest-pq round trip — and reused for every subsequent tunnel record; no
per-request re-attestation. Two independent limits retire it:

- **Idle TTL** (`--session-ttl`, default 5 minutes), refreshed on use.
- **Absolute max age** (`--session-max-age`, default 5 hours), never
  refreshed: however busy a session is, its keys retire this long after
  establishment. Without it, whoever keeps records flowing could keep one
  key schedule alive indefinitely.

A tunnel request on an unknown or expired session returns HTTP 401
`channel_error`, upon which the client establishes a fresh session.

**Termination + forwarding.** The LB (the `c8s cds-attest` sidecar) opens the record,
reconstructs the HTTP request, and forwards it **as plaintext** to the backend — over
the cluster's raTLS mesh, exactly like any other c8s workload (or with explicit mTLS:
CDS-issued client cert + mesh-CA verification, mirroring the tls-lb nginx proxy). It
seals the backend's response back to the client. The over-encryption therefore
terminates inside the LB enclave; the LB↔backend hop rides raTLS; the client gets
end-to-end confidentiality to the enclave regardless of the outer TLS terminator.

## Failure handling

The client MUST fail closed. Typed errors (mirroring c8s error codes) include:
`invalid_request`, `nonce_mismatch`, `verification_failed` (signature/chain/JsError),
`report_data_mismatch`, `measurement_denied`, `measurement_incomplete` (TDX
deployment-class verdict without the platform-complete mrtd+rtmr1+rtmr2 image
tuple), `rtmr_denied` (an RTMR[1]/RTMR[2] image-tuple register differs from the
pin, or the claims carry no comparable value), `rtmr3_denied`, `invalid_cert` /
`cert_chain` (mesh leaf does not chain to the selected CA or is expired),
`identity_binding`, and `key_binding`.

The workload policy adds `workload_not_attested` (no stamp while a
workload/allowlist pin is set), `workload_invalid` (malformed or duplicated
stamp), `workload_denied` (stamped name differs from the pin),
`workload_unresolved` (stamped name absent from the held document) and
`allowlist_denied` (stamped digest differs from the held canonical bytes).
`_denied` means a check ran and failed; `_not_attested` means the leaf never
carried the stamp, which is a lifecycle state rather than an attack.

Any failure aborts before the over-encryption channel is established. The policy
rejects an empty measurement allowlist, the absence of both anchors (a mesh-CA
pin and pinned allowlist bytes), or any version other than `c8s/attest-pq/v1` —
including `c8s/attest-lb/v1` and the retired `c8s-verify/v1`. Freshness
enforcement defaults to true; the recorded-evidence demo explicitly disables it
and reports that downgrade as a warning.

## Interoperability vectors

[`test-vectors/attest_pq_channel_vectors.json`](test-vectors/attest_pq_channel_vectors.json)
is the normative cross-language golden vector, shared verbatim with c8s
`pkg/overenc/testdata/` (regenerated there with `go test ./pkg/overenc -update`
after a deliberate contract change). Given the recorded X-Wing seed and
ciphertext, everything downstream is deterministic; a conforming
implementation MUST reproduce the encapsulation key expanded from the seed,
the decapsulated shared secret, the identity transcript hash, every key-
schedule output (both keys, both IV prefixes, the exporter), and the sealed
request and response records byte for byte. `test/vectors.test.ts` runs this
check here; `TestChannelGoldenVectors` runs it in Go.

The identity-transcript golden value for all-repeated-byte inputs is pinned
by `test/identity.test.ts` and Go's `TestIdentityTranscriptHashBindsEveryField`.
