// The verification policy layer. Wraps the attestation-rs WASM verifier and the
// X.509 chain check, and turns their raw outputs into a pass/fail decision against
// a caller-supplied policy (expected measurements, platform, freshness binding).

import { subtle } from "./crypto-env.js";
import { verifyEnvelope } from "./wasm-loader.js";
import { verifyCertChain } from "./x509.js";
import { decodePEM } from "./pem.js";
import { concatBytes, bytesToHex, base64UrlToBytes, constantTimeEqual } from "./base64.js";
import { fail } from "./errors.js";
import { toWasmEvidence, type Evidence } from "./hcl.js";

export interface VerifyPolicy {
  /** accepted launch digests (hex sha-384) */
  measurements: string[];
  /** default "snp"; also "tdx" | "az-snp" | "az-tdx" | "gcp-snp" | "gcp-tdx" */
  platform?: string;
  /** default true: report_data must bind session key+nonce */
  requireFreshness?: boolean;
  /** pinned CA; if omitted, bundle.cds_cert_pem is the anchor */
  meshCaPem?: string;
  /** validity reference time (default now) */
  at?: Date;
}

export interface SessionPubKeyB64 {
  x25519: string;
  mlkem768: string;
}

export interface AttestationBundle {
  version: string;
  platform: string;
  generation: string;
  nonce: string;
  evidence: Evidence;
  cds_cert_pem?: string;
  ear?: string;
  session_pubkey: SessionPubKeyB64;
}

/** Claims block inside the WASM verifier's JSON result. */
export interface WasmClaims {
  launch_digest: string;
  report_data?: string;
  [key: string]: unknown;
}

/** Parsed JSON result returned by the WASM verifier. */
export interface WasmVerifyResult {
  signature_valid: boolean;
  platform: string;
  generation?: string;
  // Present for snp/az-snp; az-tdx has no SNP report version.
  report_version?: number;
  report_data_match: boolean | null;
  collateral_verified?: boolean;
  claims: WasmClaims;
}

export interface CertInfo {
  subjectCN: string | null;
  issuerCN: string | null;
  sha256: string;
  caSha256: string;
  notAfter: string;
}

export interface AttestationResult {
  ok: true;
  platform: string;
  measurement: string;
  reportVersion: number;
  reportDataMatch: boolean | null;
  sessionPubKey: { x25519: Uint8Array; mlkem768: Uint8Array };
  cert: CertInfo | null;
  claims: WasmClaims;
  warnings: string[];
}

/**
 * Compute the expected hardware report_data binding: SHA-384(x25519 || mlkem768 || nonce).
 * Returns the raw 48-byte digest (the verifier zero-pads to 64).
 */
export async function expectedReportData(
  x25519: Uint8Array,
  mlkem768: Uint8Array,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  const digest = await subtle().digest("SHA-384", concatBytes(x25519, mlkem768, nonce));
  return new Uint8Array(digest);
}

// The verifier core binds the freshness anchor and FAILS CLOSED — it throws on
// a mismatch rather than returning report_data_match=false, uniformly across
// platforms. Recognize that specific failure by message so the policy layer can
// surface it as the precise `report_data_mismatch` code instead of a generic
// `verification_failed`, and so the soft (requireFreshness=false) path can tell
// a freshness mismatch apart from a real hardware/signature failure.
function isFreshnessMismatch(e: unknown): boolean {
  const msg = String((e as { message?: unknown })?.message ?? e);
  return /report_data mismatch|TPM nonce (length )?mismatch/i.test(msg);
}

/** Best-effort error message for embedding in a typed failure. */
function errMessage(e: unknown): string {
  return String((e as { message?: unknown })?.message ?? e);
}

/**
 * Verify an attestation bundle end to end.
 *
 * @param bundle the LB /attestation response
 * @param nonce the nonce WE generated and sent
 */
export async function verifyAttestation(
  bundle: AttestationBundle,
  nonce: Uint8Array,
  policy: VerifyPolicy,
): Promise<AttestationResult> {
  const warnings: string[] = [];
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
  const expected = await expectedReportData(sessionPubKey.x25519, sessionPubKey.mlkem768, nonce);

  // Every platform goes through the single generic WASM entry point; platform
  // dispatch and the per-platform freshness semantics (hardware quote
  // report_data for bare-metal, vTPM extraData for the Azure platforms) live in
  // the Rust core. `wantPlatform` is OUR asserted expectation — never the
  // bundle's self-reported tag, which must not be allowed to pick the
  // verification path. Bare snp evidence may arrive HCL-wrapped and is
  // unwrapped to the raw SNP report first.
  //
  // The core fails closed (throws) on a supplied-but-mismatched anchor for
  // every platform, so in soft mode (requireFreshness=false) we omit the
  // anchor to get a non-throwing result and warn below.
  const anchor = requireFreshness ? expected : undefined;
  let result: WasmVerifyResult;
  try {
    const evidence = wantPlatform === "snp" ? toWasmEvidence(bundle.evidence) : bundle.evidence;
    result = JSON.parse(await verifyEnvelope(wantPlatform, evidence, anchor)) as WasmVerifyResult;
  } catch (e) {
    // A freshness mismatch fails closed in the core — surface it as the precise
    // report_data_mismatch code rather than a generic verification_failed.
    if (requireFreshness && isFreshnessMismatch(e)) {
      fail(
        "report_data_mismatch",
        "report_data does not bind this session's key and nonce (stale or substituted evidence)",
        { details: { expected: bytesToHex(expected) }, cause: e },
      );
    }
    // Otherwise the WASM verifier threw on VCEK chain / report signature failure.
    fail("verification_failed", `hardware attestation failed: ${errMessage(e)}`, { cause: e });
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
  let cert: CertInfo | null = null;
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
    reportVersion: result.report_version ?? 0,
    reportDataMatch: result.report_data_match,
    sessionPubKey,
    cert,
    claims: result.claims,
    warnings,
  };
}

export interface VerifyEvidenceOptions {
  /**
   * Deprecated and ignored: the processor generation is auto-detected from
   * the evidence (SNP v3+ report CPUID fields); TDX has no generation concept.
   */
  generation?: string;
  /** accepted launch digests (hex sha-384); empty = warn only */
  measurements?: string[];
  /**
   * raw bytes the freshness anchor must equal (e.g. SHA-384(pubkey ‖ nonce));
   * when provided, a mismatch fails closed. For "snp" and "tdx" this is the
   * hardware quote's report_data; for "az-snp"/"az-tdx" it is the vTPM
   * quote's extraData.
   */
  expectedReportData?: Uint8Array;
  /**
   * default "snp"; set "az-snp"/"az-tdx" for full Azure vTPM verification, or
   * "tdx" for bare-metal Intel TDX DCAP evidence
   */
  platform?: string;
}

export interface EvidenceResult {
  ok: true;
  platform: string;
  measurement: string;
  reportVersion: number;
  reportDataMatch: boolean | null;
  claims: WasmClaims;
  warnings: string[];
}

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
 */
export async function verifyEvidence(
  evidence: Evidence,
  opts: VerifyEvidenceOptions,
): Promise<EvidenceResult> {
  if (!evidence || typeof evidence !== "object") {
    fail("invalid_request", "evidence object is required");
  }
  const warnings: string[] = [];
  const wantPlatform = opts.platform ?? "snp";
  const expected = opts.expectedReportData;

  // Hardware attestation via the single generic WASM entry point (throws on
  // chain/signature failure). Platform dispatch and freshness semantics live in
  // the Rust core; `generation` is accepted for compatibility but ignored — the
  // core auto-detects the SNP processor generation from the report's CPUID
  // fields. Bare snp evidence may arrive HCL-wrapped and is unwrapped first.
  let result: WasmVerifyResult;
  try {
    const ev = wantPlatform === "snp" ? toWasmEvidence(evidence) : evidence;
    result = JSON.parse(await verifyEnvelope(wantPlatform, ev, expected)) as WasmVerifyResult;
  } catch (e) {
    // A freshness mismatch fails closed in the core when an anchor is supplied —
    // map it to the precise report_data_mismatch code instead of the generic
    // verification_failed used for chain/signature failures.
    if (expected !== undefined && isFreshnessMismatch(e)) {
      fail(
        "report_data_mismatch",
        "report_data does not match the expected binding (stale or substituted evidence)",
        { details: { expected: bytesToHex(expected) }, cause: e },
      );
    }
    fail("verification_failed", `hardware attestation failed: ${errMessage(e)}`, { cause: e });
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
    reportVersion: result.report_version ?? 0,
    reportDataMatch: result.report_data_match,
    claims: result.claims,
    warnings,
  };
}
