# c8s-verify wire protocol (`c8s-verify/v1`)

This document specifies the browser-facing attestation + over-encryption protocol
between a JavaScript client (`c8s-verify-js`) and a C8s **Load Balancer (LB)**.
It is the canonical contract; the Go LB endpoints (c8s) and the demo mock server both
implement it, and the JS client consumes it.

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

1. The LB returns **raw TEE evidence** (AMD SEV-SNP today) whose hardware `report_data`
   binds the LB's per-session public key and the client's nonce.
2. The client verifies the evidence **directly in the browser** with the
   `attestation-rs` verifier compiled to WASM (bundled AMD ARK/ASK roots, VCEK supplied
   inline — no network during verification).
3. The client checks the measurement against its pinned allowlist and that the served
   **CDS cert** chains to the **mesh CA**.
4. Only then does the client derive a **post-quantum hybrid over-encryption channel** to
   the attested per-session key, so all subsequent application traffic is end-to-end
   confidential to the LB's TEE regardless of the outer TLS terminator.

The user only verifies **CDS + LB**; C8s's internal RA-TLS mesh transitively vouches for
the backend pods the LB talks to.

## Endpoints (LB, plain HTTPS)

All under the `/.well-known/c8s/` namespace.

### `GET /.well-known/c8s/cds-cert.pem`
Returns `Content-Type: application/x-pem-file` — the mesh CA certificate (the pinned
trust anchor). May include the LB leaf chain. Unauthenticated by design; the client
chains it through attested evidence before trusting it.

### `GET /.well-known/c8s/jwks.json`  *(optional)*
Returns the CDS EAR-signing JWKS (ES256, `kid` = RFC 7638 thumbprint), republished from
the CDS, for the optional EAR-verification path.

### `GET /.well-known/c8s/attestation?nonce=<b64url>`
`nonce` is the client's fresh 32-byte random challenge, base64url (unpadded). Response is
`application/json`:

```jsonc
{
  "version": "c8s-verify/v1",
  "platform": "snp",            // "snp" (bare) and "az-snp" (Azure vTPM) supported; "tdx" reserved
  "generation": "genoa",        // AMD processor gen for the WASM verifier: milan|genoa|turin
  "nonce": "<echoed b64url>",   // MUST equal the request nonce
  "evidence": {                 // attestation-rs SnpEvidence shape (std base64 fields)
    "attestation_report": "<base64 of the 1184-byte SNP report>",
    "cert_chain": { "vcek": "<base64 DER VCEK>" }
  },
  "cds_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "ear": "<optional CDS-issued EAR JWT>",
  "session_pubkey": {
    "x25519":   "<b64url 32-byte X25519 public key>",
    "mlkem768": "<b64url 1184-byte ML-KEM-768 encapsulation key>"
  }
}
```

#### Report-data binding (freshness + key binding)

The LB asks the hardware to produce a report whose 64-byte `report_data` is:

```
report_data = SHA-384( x25519_pub_raw(32) || mlkem768_pub_raw(1184) || nonce(32) )
            then zero-padded from 48 to 64 bytes
```

The client recomputes `SHA-384(x25519 || mlkem768 || nonce)` and passes it to the WASM
verifier as `expected_report_data`. A passing `report_data_match` proves in one check
that (a) the evidence is **fresh** (binds our nonce) and (b) the over-encryption
**session key was generated inside the attested TEE**.

> Note: a live LB binds the session key into a fresh hardware report per session. The
> demo/mock and the offline test fixtures use **recorded real evidence** with a fixed
> `report_data`; in that mode the client verifies the hardware signature + measurement
> for real and exercises the binding math against the fixture's recorded value.

**Azure node-as-CVM (`az-snp`).** On Azure the hardware `report_data` binds the vTPM
Attestation Key (it equals `SHA-256(var_data)`), not the session key — so the
`SHA-384(x25519 ‖ mlkem768 ‖ nonce)` binding instead rides in the AK-signed
`tpm_quote`. The evidence carries an `hcl_report` (HCL-wrapped SNP report + var_data)
and a `tpm_quote`, and the client verifies the chain
`report_data == SHA-256(var_data) → AK pub (var_data JWK) → AK-signed quote → quote
extraData == SHA-384(x25519 ‖ mlkem768 ‖ nonce)` (`src/tpmquote.js`). This is a
real freshness check, equivalent to the bare-SNP `report_data_match`.

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

## Over-encryption channel (post-quantum hybrid)

Hybrid KEM = **X25519** (classical, WebCrypto) **+ ML-KEM-768** (post-quantum,
`mlkem-wasm`). Construction follows the TLS `X25519MLKEM768` convention.

1. Client encapsulates against the attested ML-KEM key:
   `(mlkem_ct, mlkem_ss) = ML-KEM-768.Encaps(session_pubkey.mlkem768)`.
2. Client generates ephemeral X25519 keypair; `x25519_ss = ECDH(client_x25519_priv, session_pubkey.x25519)`.
3. Combined secret: `ikm = mlkem_ss (32B) || x25519_ss (32B)`.
4. `key = HKDF-SHA256(ikm, salt = nonce, info = "c8s-verify/over-encryption/v1", L = 32)`
   → **AES-256-GCM**.
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
`report_data_mismatch`, `measurement_denied`, `invalid_cert` / `cert_chain` (CDS cert
does not chain to mesh CA or is expired), `key_binding`. Any failure aborts before the
over-encryption channel is established.
