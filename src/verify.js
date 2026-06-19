// The verification policy layer. Wraps the attestation-rs WASM verifier and the
// X.509 chain check, and turns their raw outputs into a pass/fail decision against
// a caller-supplied policy (expected measurements, platform, freshness binding).

import { subtle } from "./crypto-env.js";
import { verifySnp, verifyAzSnp } from "./wasm-loader.js";
import { verifyCertChain } from "./x509.js";
import { decodePEM } from "./pem.js";
import {
  concatBytes,
  bytesToHex,
  base64UrlToBytes,
  constantTimeEqual,
} from "./base64.js";
import { C8sVerifyError, fail } from "./errors.js";

/**
 * @typedef {{
 *   measurements: string[],            // accepted launch digests (hex sha-384)
 *   platform?: string,                 // default "snp"
 *   requireFreshness?: boolean,        // default true: report_data must bind session key+nonce
 *   meshCaPem?: string,                // pinned CA; if omitted, bundle.cds_cert_pem is the anchor
 *   at?: Date,                         // validity reference time (default now)
 * }} VerifyPolicy
 */

/**
 * @typedef {{
 *   version: string, platform: string, generation: string, nonce: string,
 *   evidence: object, cds_cert_pem?: string, ear?: string,
 *   session_pubkey: { x25519: string, mlkem768: string }
 * }} AttestationBundle
 */

/**
 * Compute the expected hardware report_data binding: SHA-384(x25519 || mlkem768 || nonce).
 * Returns the raw 48-byte digest (the verifier zero-pads to 64).
 * @param {Uint8Array} x25519
 * @param {Uint8Array} mlkem768
 * @param {Uint8Array} nonce
 * @returns {Promise<Uint8Array>}
 */
export async function expectedReportData(x25519, mlkem768, nonce) {
  const digest = await subtle().digest("SHA-384", concatBytes(x25519, mlkem768, nonce));
  return new Uint8Array(digest);
}

// az-snp's verifier (verify_az_snp) binds the freshness anchor in the verifier
// core and FAILS CLOSED — it throws on a mismatch rather than returning a
// non-throwing report_data_match=false (which is what bare `verify_snp` does).
// Recognize that specific failure by message so the policy layer can surface it
// as the precise `report_data_mismatch` code instead of a generic
// `verification_failed`, and so the soft (requireFreshness=false) path can tell
// a freshness mismatch apart from a real hardware/signature failure.
function isFreshnessMismatch(e) {
  const msg = String(e?.message ?? e);
  return /report_data mismatch|TPM nonce (length )?mismatch/i.test(msg);
}

/**
 * Verify an attestation bundle end to end.
 *
 * @param {AttestationBundle} bundle  the LB /attestation response
 * @param {Uint8Array} nonce          the nonce WE generated and sent
 * @param {VerifyPolicy} policy
 * @returns {Promise<{
 *   ok: true,
 *   platform: string,
 *   measurement: string,
 *   reportVersion: number,
 *   reportDataMatch: boolean|null,
 *   sessionPubKey: { x25519: Uint8Array, mlkem768: Uint8Array },
 *   cert: { subjectCN: string|null, issuerCN: string|null, sha256: string,
 *           caSha256: string, notAfter: string } | null,
 *   claims: object,
 *   warnings: string[],
 * }>}
 */
export async function verifyAttestation(bundle, nonce, policy) {
  const warnings = [];
  const wantPlatform = policy.platform ?? "snp";
  const requireFreshness = policy.requireFreshness !== false;

  // 1. Nonce echo — cheap replay guard before any crypto.
  const echoed = base64UrlToBytes(bundle.nonce);
  if (!constantTimeEqual(echoed, nonce)) {
    fail("nonce_mismatch", "attestation bundle nonce does not match the nonce we sent");
  }

  // 2. Session public key shape.
  const sessionPubKey = {
    x25519: base64UrlToBytes(bundle.session_pubkey.x25519),
    mlkem768: base64UrlToBytes(bundle.session_pubkey.mlkem768),
  };

  // 3. Hardware attestation via WASM. report_data binds the session key + nonce.
  const expected = await expectedReportData(
    sessionPubKey.x25519,
    sessionPubKey.mlkem768,
    nonce,
  );

  // az-snp gets full verification (HCL report + vTPM quote), with `expected`
  // checked against the TPM quote's extraData. Bare snp checks the SNP report
  // only, with `expected` checked against report_data. Both return the same
  // result shape, so the policy checks below are platform-agnostic.
  const isAzSnp = wantPlatform === "az-snp";
  // az-snp's verifier fails closed (throws) on a freshness mismatch, so in soft
  // mode (requireFreshness=false) we omit the anchor to get a non-throwing
  // result and warn below; bare snp returns a non-throwing bool either way.
  const azSnpAnchor = requireFreshness ? expected : undefined;
  let result;
  try {
    const out = isAzSnp
      ? await verifyAzSnp(JSON.stringify(bundle.evidence), azSnpAnchor)
      : await verifySnp(JSON.stringify(bundle.evidence), bundle.generation, expected);
    result = JSON.parse(out);
  } catch (e) {
    // az-snp fails closed on a freshness mismatch — surface it as the precise
    // report_data_mismatch code rather than a generic verification_failed.
    if (isAzSnp && requireFreshness && isFreshnessMismatch(e)) {
      fail(
        "report_data_mismatch",
        "report_data does not bind this session's key and nonce (stale or substituted evidence)",
        { details: { expected: bytesToHex(expected) }, cause: e },
      );
    }
    // Otherwise the WASM verifier threw on VCEK chain / report signature failure.
    fail("verification_failed", `hardware attestation failed: ${e.message ?? e}`, { cause: e });
  }

  if (result.signature_valid !== true) {
    fail("verification_failed", "attestation signature is not valid");
  }
  if (result.platform !== wantPlatform) {
    fail("verification_failed", `unexpected platform ${result.platform}, want ${wantPlatform}`);
  }

  // 4. Measurement allowlist (case-insensitive hex).
  const measurement = String(result.claims.launch_digest).toLowerCase();
  const allow = (policy.measurements ?? []).map((m) => m.toLowerCase());
  if (allow.length === 0) {
    warnings.push("no measurement allowlist provided — launch digest was not checked");
  } else if (!allow.includes(measurement)) {
    fail("measurement_denied", `launch digest ${measurement} is not in the allowlist`, {
      details: { measurement, allowed: allow },
    });
  }

  // 5. Freshness / key binding.
  if (result.report_data_match === true) {
    // bound to our session key + nonce — strongest result.
  } else if (requireFreshness) {
    fail(
      "report_data_mismatch",
      "report_data does not bind this session's key and nonce (stale or substituted evidence)",
      { details: { expected: bytesToHex(expected), got: result.claims.report_data } },
    );
  } else {
    warnings.push(
      "freshness binding not enforced (requireFreshness=false): hardware signature and " +
        "measurement are verified, but report_data is not bound to this session key+nonce",
    );
  }

  // 6. CDS / mesh-CA certificate: parse, check validity, chain to the anchor.
  let cert = null;
  if (bundle.cds_cert_pem) {
    const blocks = decodePEM(bundle.cds_cert_pem, "CERTIFICATE");
    if (blocks.length === 0) {
      fail("invalid_cert", "cds_cert_pem contained no certificate");
    }
    const anchorPem = policy.meshCaPem ?? bundle.cds_cert_pem;
    const anchorBlocks = decodePEM(anchorPem, "CERTIFICATE");
    // Anchor is the last cert in the served chain (or the pinned mesh CA).
    const caDer = anchorBlocks[anchorBlocks.length - 1];
    const leafDer = blocks[0];
    const chain = await verifyCertChain(leafDer, caDer, { at: policy.at });
    if (!policy.meshCaPem) {
      warnings.push(
        "no pinned meshCaPem: the served cds_cert_pem was used as its own anchor — " +
          "pin the mesh CA out of band for a stronger guarantee",
      );
    }
    cert = {
      subjectCN: chain.leaf.subjectCN,
      issuerCN: chain.leaf.issuerCN,
      sha256: chain.leafSha256,
      caSha256: chain.caSha256,
      notAfter: chain.leaf.notAfter.toISOString(),
    };
  } else {
    warnings.push("bundle did not include cds_cert_pem; CDS certificate was not verified");
  }

  return {
    ok: true,
    platform: result.platform,
    measurement,
    reportVersion: result.report_version,
    reportDataMatch: result.report_data_match,
    sessionPubKey,
    cert,
    claims: result.claims,
    warnings,
  };
}

/**
 * @typedef {{
 *   generation?: string,                // "milan" | "genoa" | "turin"; required for "snp",
 *                                       //   ignored for "az-snp" (auto-detected from CPUID)
 *   measurements?: string[],            // accepted launch digests (hex sha-384); empty = warn only
 *   expectedReportData?: Uint8Array,    // raw bytes the freshness anchor must equal (e.g.
 *                                       //   SHA-384(pubkey ‖ nonce)); when provided, a mismatch
 *                                       //   fails closed. For "snp" this is the SNP report_data;
 *                                       //   for "az-snp" it is the vTPM quote's extraData.
 *   platform?: string,                  // default "snp"; set "az-snp" for full Azure vTPM verification
 * }} VerifyEvidenceOptions
 */

/**
 * Verify a bare SEV-SNP evidence object: the AMD hardware signature + VCEK chain
 * (in WASM, bundled roots), the launch-measurement allowlist, the platform, and
 * — when the caller supplies one — a `report_data` binding.
 *
 * Unlike {@link verifyAttestation}, this takes the raw `attestation-rs`
 * `SnpEvidence` directly and needs no `c8s-verify/v1` bundle, client nonce,
 * session key, or CDS certificate. Use it when you fetch evidence over your own
 * transport and compute the `report_data` binding yourself (e.g. a discovery
 * document binding `SHA-384(cert_spki ‖ challenge)`). Cluster identity
 * (mesh-CA chaining) must then be checked separately. Fails closed with a typed
 * {@link C8sVerifyError}.
 *
 * @param {object} evidence  attestation-rs SnpEvidence: { attestation_report, cert_chain: { vcek } }
 * @param {VerifyEvidenceOptions} opts
 * @returns {Promise<{ ok: true, platform: string, measurement: string,
 *   reportVersion: number, reportDataMatch: boolean|null, claims: object, warnings: string[] }>}
 */
export async function verifyEvidence(evidence, opts) {
  if (!evidence || typeof evidence !== "object") {
    fail("invalid_request", "evidence object is required");
  }
  const warnings = [];
  const wantPlatform = opts.platform ?? "snp";
  const isAzSnp = wantPlatform === "az-snp";
  // az-snp auto-detects the generation from the report CPUID; bare snp needs it.
  if (!opts || (!isAzSnp && !opts.generation)) {
    fail("invalid_request", 'generation is required ("milan" | "genoa" | "turin")');
  }
  const expected = opts.expectedReportData;

  // Hardware attestation via WASM (throws on VCEK chain / report signature failure).
  let result;
  try {
    const out = isAzSnp
      ? await verifyAzSnp(JSON.stringify(evidence), expected)
      : await verifySnp(JSON.stringify(evidence), opts.generation, expected);
    result = JSON.parse(out);
  } catch (e) {
    // az-snp fails closed (throws) on a freshness mismatch when an anchor is
    // supplied — map it to the precise report_data_mismatch code instead of the
    // generic verification_failed used for chain/signature failures.
    if (isAzSnp && expected !== undefined && isFreshnessMismatch(e)) {
      fail(
        "report_data_mismatch",
        "report_data does not match the expected binding (stale or substituted evidence)",
        { details: { expected: bytesToHex(expected) }, cause: e },
      );
    }
    fail("verification_failed", `hardware attestation failed: ${e.message ?? e}`, { cause: e });
  }

  if (result.signature_valid !== true) {
    fail("verification_failed", "attestation signature is not valid");
  }
  if (result.platform !== wantPlatform) {
    fail("verification_failed", `unexpected platform ${result.platform}, want ${wantPlatform}`);
  }

  // Measurement allowlist (case-insensitive hex).
  const measurement = String(result.claims.launch_digest).toLowerCase();
  const allow = (opts.measurements ?? []).map((m) => m.toLowerCase());
  if (allow.length === 0) {
    warnings.push("no measurement allowlist provided — launch digest was not checked");
  } else if (!allow.includes(measurement)) {
    fail("measurement_denied", `launch digest ${measurement} is not in the allowlist`, {
      details: { measurement, allowed: allow },
    });
  }

  // report_data binding — only enforced when the caller supplies an expected value.
  if (expected !== undefined) {
    if (result.report_data_match !== true) {
      fail(
        "report_data_mismatch",
        "report_data does not match the expected binding (stale or substituted evidence)",
        { details: { expected: bytesToHex(expected), got: result.claims.report_data } },
      );
    }
  } else {
    warnings.push(
      "no expectedReportData provided — report_data freshness/key binding was not verified",
    );
  }

  return {
    ok: true,
    platform: result.platform,
    measurement,
    reportVersion: result.report_version,
    reportDataMatch: result.report_data_match,
    claims: result.claims,
    warnings,
  };
}
