# c8s-verify wire protocol (`c8s-verify/v1`)

This document specifies the browser-facing attestation + over-encryption protocol
between a JavaScript client (`c8s-verify-js`) and a C8s **Load Balancer (LB)**.
It is the canonical contract implemented by the Go LB and the JavaScript client.

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
   LB's per-session public key, the client's nonce, the exact mesh leaf,
   and the issuing mesh CA.
2. The client verifies the evidence **directly in the browser** with the
   `attestation-rs` verifier compiled to WASM (bundled AMD ARK/ASK and Intel
   TDX roots, VCEK/DCAP collateral supplied inline — no network during
   verification).
3. The client checks the measurement against its pinned allowlist, checks that the
   served mesh leaf chains to a **mesh CA** that is either pinned out of band or
   *derived from attested CDS claims* (see below), and verifies a per-session proof
   of possession made by that leaf key.
4. Only then does the client derive a **post-quantum hybrid over-encryption channel** to
   the attested per-session key, so all subsequent application traffic is end-to-end
   confidential to the LB's TEE regardless of the outer TLS terminator.

The user only verifies **CDS + LB**; C8s's internal RA-TLS mesh transitively vouches for
the backend pods the LB talks to.

### Deriving the mesh CA from CDS config-claims

The mesh CA may be authenticated instead of pinned. CDS's own self-signed RA-TLS
certificate carries two extensions on the `1.3.6.1.4.1.59888.1` arc:

| OID | contents |
|---|---|
| `…1.1` | `SEQUENCE { teeType INTEGER, report OCTET STRING, certChain OCTET STRING }`; for TDX `report` holds a JSON `{platform, evidence}` envelope |
| `…1.3` | `config-claims`, below |

```
C8SConfigClaims ::= SEQUENCE {
    version             INTEGER,        -- 1, 2 or 3
    operatorKeysDigest  OCTET STRING,   -- 32 bytes
    seedDigest          OCTET STRING,
    workloadDigest      OCTET STRING,
    meshCADigest        OCTET STRING,   -- v2+
    allowlistDigest     OCTET STRING }  -- v3+
```

An all-zero digest is the "not applicable" sentinel; it is unreachable as a real
SHA-256 output, so a verifier pinning a real value can never be satisfied by one.
The encoding MUST be the single canonical DER encoding of its version — minimal
lengths, a minimal `version` INTEGER, no trailing bytes — because the binding
below covers the bytes rather than their meaning.

The TD quote's `report_data` commits to those bytes:

```
REPORTDATA = SHA-384( "c8s/config-claims/v1\x00"
                    ‖ uint64be(len(spki))   ‖ spki
                    ‖ uint64be(len(claims)) ‖ claims
                    ‖ uint64be(len(nonce))  ‖ nonce )   -- nonce empty for a
                                                        -- self-signed serving cert
```

zero-padded to 64 bytes. `spki` is the PKIX SubjectPublicKeyInfo DER exactly as it
appears in the certificate; `claims` is the raw `extnValue` of `…1.3`, verbatim.
This is `ReportDataForKeyAndClaims` in c8s `pkg/ratls`.

A client verifying this certificate MUST, in order:

1. verify the TD quote and require `report_data` to equal the transcript above —
   this is what binds the claims to hardware;
2. verify the certificate's **self-signature** over `tbsCertificate` using the SPKI
   the transcript just bound. The validity window, serial and subject are outside
   the transcript, so until this step they are attacker-chosen;
3. enforce the validity window against a reference time;
4. enforce the launch-measurement allowlist, which MUST be non-empty.

The mesh CA is then the certificate whose SHA-256 equals `meshCADigest`. A client
MUST pin that single certificate, not the chain it was served in.

Freshness comes from re-issuance, not from a timestamp: CDS re-issues this
certificate whenever the live allowlist digest changes, so a changed fingerprint is
exactly when to re-attest. Because an old certificate remains internally consistent,
a client SHOULD also refuse one whose `notBefore` precedes that of a certificate it
has already verified.

## Endpoints (LB, plain HTTPS)

All under the `/.well-known/c8s/` namespace.

### `GET /.well-known/c8s/jwks.json`  *(optional)*
Returns the CDS EAR-signing JWKS (ES256, `kid` = RFC 7638 thumbprint), republished from
the CDS, for the optional EAR-verification path.

### `GET /.well-known/c8s/attestation?nonce=<b64url>[&pq=false]`

`nonce` is the client's fresh 32-byte random challenge, base64url (unpadded).
The endpoint takes no other parameter — there is no version or binding
negotiation, and a request carrying a `binding` parameter is rejected with
`400 invalid_request`. `pq=false` selects the separate tls-cert response
(below); the default response is the identity-bound over-encryption bundle.
Response is `application/json`:

```jsonc
{
  "version": "c8s-verify/v1",
  "platform": "snp",            // "snp" | "az-snp" | "az-tdx" | "tdx"
  "generation": "genoa",        // AMD gen for the bare-SNP WASM verifier (milan|genoa|turin); empty for the other platforms
  "nonce": "<echoed b64url>",   // MUST equal the request nonce
  "evidence": {                 // attestation-rs SnpEvidence shape (std base64 fields)
    "attestation_report": "<base64 of the 1184-byte SNP report>",
    "cert_chain": { "vcek": "<base64 DER VCEK>" }
  },
  "cds_cert_pem": "-----BEGIN CERTIFICATE-----\n...", // exact mesh leaf + issuing CA
  "ear": "<optional CDS-issued EAR JWT>",             // defined but not yet populated by the LB
  "session_pubkey": {
    "x25519":   "<b64url 32-byte X25519 public key>",
    "mlkem768": "<b64url 1184-byte ML-KEM-768 encapsulation key>"
  },
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

The `version`, `cds_cert_pem`, and `identity_proof` fields are mandatory in
this default (identity-bound) response; the `?pq=false` response below omits
the identity fields by design.
The LB re-reads the TEE-held mesh leaf, private key, and CA for each request so
certificate rotation cannot leave the bundle and proof on different credential
generations. There is no legacy or downgrade path.

#### Report-data and mesh-identity binding

Define `LP(field) = uint32_be(len(field)) || field`, and:

```
leaf_hash = SHA-256(leaf_certificate_DER)
ca_hash   = SHA-256(issuing_mesh_CA_DER)

transcript = LP("c8s-verify/v1")
          || LP(ca_hash(32))
          || LP(leaf_hash(32))
          || LP(x25519_pub_raw(32))
          || LP(mlkem768_pub_raw(1184))
          || LP(nonce(32))

transcript_hash = SHA-384(transcript)
report_data      = transcript_hash, then zero-padded from 48 to 64 bytes
```

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
measurement against its non-empty allowlist, the leaf chain against a CA pinned
out of band, both certificate fingerprints, and the proof signature. This defeats
the copied-public-chain attack: a genuine attacker-operated LB can copy the victim
cluster's public certificates, but cannot sign its own session transcript with the
victim leaf's private key.

The identity proof is currently ECDSA, so cluster authentication is **classical**.
The over-encryption key agreement remains X25519 + ML-KEM-768 hybrid: recorded
traffic retains post-quantum confidentiality as long as ML-KEM-768 remains secure,
but the protocol does not claim post-quantum authentication.

> Note: a live LB binds the session key into a fresh hardware report per session. The
> demo/mock and the offline test fixtures use **recorded real evidence** with a fixed
> `report_data`; in that mode the client verifies the hardware signature + measurement
> for real and exercises the binding math against the fixture's recorded value.

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
Intel root. As with the other WASM entry points, the async collateral checks
(CRL/TCB/QE identity) are skipped in the browser (`collateral_verified:
false`). `claims.launch_digest` is the TD launch measurement (MRTD);
`generation` is not applicable and is empty.

#### `?pq=false` — the tls-cert response

`pq=false` selects a different trust decision for clients that ride the
LB's validated **outer TLS** instead of the over-encryption tunnel (e.g.
TEErminator Flow B). No session key is minted and no pending session is
stored; the hardware anchor commits the LB's serving TLS leaf instead of a
session transcript:

```
report_data = SHA-384(serving_leaf_spki_DER || nonce), zero-padded to 64 bytes
```

The response is the same bundle shape with `cds_cert_pem` empty and no
`session_pubkey` or `identity_proof`: the client already sees the serving
leaf on its TLS connection, recomputes the binding from that leaf's SPKI and
its nonce, and must validate the leaf against a cluster-specific anchor of
its own (e.g. chain it to the pinned mesh CA). The client knows which shape
it asked for; the response carries no discriminator. The nonce for this
response must be at least 16 bytes (the identity-bound response requires
exactly 32). This mode supplies TEE + TLS-identity binding but **no post-quantum
tunnel** — `c8s-verify-js` implements only the identity-bound default; the
tls-cert response is specified here for other consumers.

## WASM verifier I/O (`attestation-rs` `verify_snp`)

```
verify_snp(evidenceJson: string, generation: "milan"|"genoa"|"turin",
           expectedReportData?: Uint8Array) -> string (JSON) | throws
```

- **Throws** (JsError) if VCEK chain or report signature verification fails.
- On success returns:
  ```jsonc
  {
    "signature_valid": true,
    "platform": "snp",
    "report_version": 3,
    "report_data_match": true,        // bool, or null if no expected provided
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

## WASM verifier I/O (`attestation-rs` `verify_az_snp`)

```
verify_az_snp(evidenceJson: string, expectedReportData?: Uint8Array,
              expectedInitDataHash?: Uint8Array) -> string (JSON) | throws
```

Full Azure vTPM verification of an `AzSnpEvidence` object (above). Unlike `verify_snp`
it takes no `generation` (auto-detected) and verifies the vTPM quote in addition to the
hardware report:

1. TPM quote signature against the AK extracted from the HCL runtime data.
2. Quote `extraData` == `expectedReportData` (the freshness anchor).
3. PCR digest integrity, and optionally `expectedInitDataHash` bound to PCR[8].
4. AK-to-TEE binding: `snp.report_data[..32] == SHA-256(runtime_data)`.
5. VCEK chain to the bundled AMD roots, SNP report signature, and VMPL/debug/TCB policy.

- **Throws** (JsError) if any check fails.
- On success returns the same shape as `verify_snp` with `platform: "az-snp"` and an
  added `collateral_verified: false` (the WASM path skips the async CRL revocation
  check; `report_data_match` reflects the quote `extraData`, not the SNP report_data).

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
`collateral_verified: false` (the WASM path skips the async CRL/TCB/QE
collateral checks, like the other entry points).

The JS policy layer applies the **same** pass/fail rule as for `verify_snp`.

## Over-encryption channel (post-quantum hybrid)

Hybrid KEM = **X25519** (classical, WebCrypto) **+ ML-KEM-768** (post-quantum,
`mlkem-wasm`). Construction follows the TLS `X25519MLKEM768` convention.

1. Client encapsulates against the attested ML-KEM key:
   `(mlkem_ct, mlkem_ss) = ML-KEM-768.Encaps(session_pubkey.mlkem768)`.
2. Client generates ephemeral X25519 keypair; `x25519_ss = ECDH(client_x25519_priv, session_pubkey.x25519)`.
3. Combined secret: `ikm = mlkem_ss (32B) || x25519_ss (32B)`.
4. Derive the **AES-256-GCM** key:
   `HKDF-SHA256(ikm, salt = transcript_hash, info = "c8s-verify/v1/over-encryption", L = 32)`.
5. **Handshake** — `POST /.well-known/c8s/handshake` with
   `{ "nonce": "<b64url>", "client_x25519": "<b64url 32B>", "mlkem_ct": "<b64url 1088B>" }`.
   The LB selects the pending session key by nonce, decapsulates + ECDHs to the same
   AES-256-GCM key, and returns `{ "session_id": "<opaque>" }`.

Byte lengths (ML-KEM-768): encapsulation key 1184, ciphertext 1088, shared secret 32.

## Over-encrypted application tunnel

All application traffic flows through a single endpoint, **`POST /.well-known/c8s/tunnel`**,
with header `X-C8s-Session: <session_id>` and `Content-Type: application/cbor`. The body
and the response are **CBOR** (RFC 8949), not JSON — so the body and the AES-GCM
ciphertext ride as raw byte strings with no base64 inflation. The body is one
AES-256-GCM record, a CBOR map with two byte-string fields (fresh random 12-byte IV per
record):

```cbor
{ "iv": h'<12 bytes>', "ct": h'<ciphertext+tag>' }
```

The **entire request** is sealed — method, path, headers, and body — so a
TLS-terminating proxy in front of the LB sees only ciphertext (not even the path or
`Authorization` header). The sealed plaintext is a CBOR envelope (`body` is a CBOR byte
string; absent/empty when there is no body):

```cbor
// request (AAD = "c8s-verify/v1/tunnel-request")
{ "method": "POST", "path": "/v1/chat", "headers": { "content-type": "application/json" },
  "body": h'<raw request body>' }

// response (AAD = "c8s-verify/v1/tunnel-response")
{ "status": 200, "headers": { ... }, "body": h'<raw response body>' }
```

**Session lifetime.** The session (and its AES key) is established once —
attestation + handshake — and reused for every subsequent tunnel record; no
per-request re-attestation. The LB expires a session after an idle TTL
(refreshed on use; `--session-ttl`, default 5 minutes) and a tunnel request on
an unknown or expired session returns HTTP 401 `channel_error`, upon which the
client establishes a fresh session. The LB also enforces exact-record replay
protection over a bounded set of seen records; a session that somehow exceeds
that bound fails closed and must be re-established.

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
`report_data_mismatch`, `measurement_denied`, `rtmr3_denied`, `invalid_cert` /
`cert_chain` (mesh leaf does not chain to the pinned CA or is expired),
`identity_binding`, and `key_binding`.

CDS attestation adds `cds_identity_missing`, `cds_identity_invalid`,
`cds_identity_denied`, `cds_identity_unsigned`, `cds_identity_expired`,
`cds_identity_rollback`, `mesh_ca_denied`, `mesh_ca_not_attested`,
`allowlist_denied` and `allowlist_not_attested`. `_denied` means a check ran and
failed; `_not_attested` means the claims never carried the field, which is an
upgrade problem rather than an attack.

Any failure aborts before the over-encryption channel is established. The policy
rejects an empty measurement allowlist, an anchor that is neither a mesh-CA pin nor
a CDS identity (or both at once), or any version other than `c8s-verify/v1`. Freshness enforcement defaults to true; the
recorded-evidence demo explicitly disables it and reports that downgrade as a
warning.
