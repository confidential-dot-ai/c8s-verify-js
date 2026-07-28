// The verification policy layer. Wraps the attestation-rs WASM verifier and the
// X.509 chain check, and turns their raw outputs into a pass/fail decision against
// a caller-supplied policy (expected measurements, platform, freshness binding).

import { verifyEnvelope } from "./wasm-loader.js";
import { verifyCertChain, type ChainResult } from "./x509.js";
import { decodePEM } from "./pem.js";
import { bytesToHex, base64UrlToBytes, constantTimeEqual } from "./base64.js";
import { fail } from "./errors.js";
import { toWasmEvidence, type Evidence } from "./hcl.js";
import {
  PROTOCOL_VERSION,
  identityTranscriptHash,
  selectPinnedCA,
  verifyMeshIdentityProof,
  type MeshIdentityProof,
} from "./identity.js";

export interface VerifyPolicy {
  /** accepted launch digests (hex sha-384) */
  measurements: string[];
  /** default "snp"; also "tdx" | "az-snp" | "az-tdx" | "gcp-snp" | "gcp-tdx" */
  platform?: string;
  /** default true: report_data must bind the selected session transcript */
  requireFreshness?: boolean;
  /** mesh CA pinned out of band */
  meshCaPem: string;
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
  cds_cert_pem: string;
  ear?: string;
  session_pubkey: SessionPubKeyB64;
  identity_proof: MeshIdentityProof;
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
  /** true only when the identity transcript is hardware-bound (report_data matched). */
  identityBound: boolean;
  /**
   * Verified identity transcript hash used as the HKDF context. Hardware-bound
   * only when {@link identityBound} is true.
   */
  keyAgreementContext: Uint8Array;
  sessionPubKey: { x25519: Uint8Array; mlkem768: Uint8Array };
  cert: CertInfo;
  claims: WasmClaims;
  warnings: string[];
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

interface PreparedIdentity {
  chain: ChainResult;
  proof: MeshIdentityProof;
  transcript: Uint8Array;
}

function validatePolicy(policy: VerifyPolicy): void {
  if (!policy || !Array.isArray(policy.measurements) || policy.measurements.length === 0) {
    fail("invalid_request", "verification requires a non-empty measurement allowlist");
  }
  if (!policy.measurements.every((measurement) => typeof measurement === "string")) {
    fail("invalid_request", "measurement allowlist entries must be strings");
  }
  if (typeof policy.meshCaPem !== "string" || policy.meshCaPem.trim() === "") {
    fail("identity_binding", "verification requires meshCaPem pinned out of band");
  }
}

function decodeSessionPublicKey(
  bundle: AttestationBundle,
  nonce: Uint8Array,
): { x25519: Uint8Array; mlkem768: Uint8Array } {
  if (
    typeof bundle?.nonce !== "string" ||
    typeof bundle?.session_pubkey?.x25519 !== "string" ||
    typeof bundle?.session_pubkey?.mlkem768 !== "string"
  ) {
    fail("invalid_request", "attestation bundle is missing nonce or session_pubkey fields");
  }

  let echoed: Uint8Array;
  try {
    echoed = base64UrlToBytes(bundle.nonce);
  } catch (cause) {
    fail("invalid_request", "attestation bundle nonce is not base64url", { cause });
  }
  if (!constantTimeEqual(echoed, nonce)) {
    fail("nonce_mismatch", "attestation bundle nonce does not match the nonce we sent");
  }

  try {
    return {
      x25519: base64UrlToBytes(bundle.session_pubkey.x25519),
      mlkem768: base64UrlToBytes(bundle.session_pubkey.mlkem768),
    };
  } catch (cause) {
    fail("invalid_request", "attestation bundle session_pubkey is not base64url", { cause });
  }
}

function isMeshIdentityProof(proof: MeshIdentityProof | undefined): proof is MeshIdentityProof {
  return (
    proof !== undefined &&
    typeof proof.algorithm === "string" &&
    typeof proof.leaf_sha256 === "string" &&
    typeof proof.mesh_ca_sha256 === "string" &&
    typeof proof.signature === "string"
  );
}

async function prepareIdentity(
  bundle: AttestationBundle,
  sessionPubKey: { x25519: Uint8Array; mlkem768: Uint8Array },
  nonce: Uint8Array,
  policy: VerifyPolicy,
): Promise<PreparedIdentity> {
  if (bundle?.version !== PROTOCOL_VERSION) {
    fail("identity_binding", `attestation response has unexpected version ${bundle?.version}`);
  }
  if (!isMeshIdentityProof(bundle.identity_proof)) {
    fail("identity_binding", "attestation response omitted or malformed identity_proof");
  }
  if (typeof bundle.cds_cert_pem !== "string" || bundle.cds_cert_pem.trim() === "") {
    fail("identity_binding", "attestation response omitted cds_cert_pem");
  }

  const leafBlocks = decodePEM(bundle.cds_cert_pem, "CERTIFICATE");
  const pinnedCAs = decodePEM(policy.meshCaPem, "CERTIFICATE");
  if (leafBlocks.length === 0 || pinnedCAs.length === 0) {
    fail("invalid_cert", "identity verification requires a leaf and pinned mesh CA");
  }
  const selectedCA = await selectPinnedCA(bundle.identity_proof, pinnedCAs);
  if (!selectedCA) {
    fail("identity_binding", "identity proof does not name any pinned mesh CA");
  }
  const chain = await verifyCertChain(leafBlocks[0], selectedCA, { at: policy.at });
  const transcript = await identityTranscriptHash(
    sessionPubKey,
    nonce,
    chain.leaf.der,
    chain.ca.der,
  );
  return { chain, proof: bundle.identity_proof, transcript };
}

async function verifyHardwareAttestation(
  bundle: AttestationBundle,
  expected: Uint8Array,
  wantPlatform: string,
  requireFreshness: boolean,
): Promise<WasmVerifyResult> {
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
  // anchor to get a non-throwing result and warn later.
  const anchor = requireFreshness ? expected : undefined;
  let result: WasmVerifyResult;
  try {
    const evidence = wantPlatform === "snp" ? toWasmEvidence(bundle.evidence) : bundle.evidence;
    result = JSON.parse(await verifyEnvelope(wantPlatform, evidence, anchor)) as WasmVerifyResult;
  } catch (e) {
    if (requireFreshness && isFreshnessMismatch(e)) {
      fail(
        "report_data_mismatch",
        "report_data does not bind this session transcript (stale or substituted evidence)",
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
  return result;
}

function verifyMeasurement(result: WasmVerifyResult, allowlist: string[]): string {
  const measurement = String(result.claims.launch_digest).toLowerCase();
  const allowed = allowlist.map((entry) => entry.toLowerCase());
  if (!allowed.includes(measurement)) {
    fail("measurement_denied", `launch digest ${measurement} is not in the allowlist`, {
      details: { measurement, allowed },
    });
  }
  return measurement;
}

function verifyFreshness(
  result: WasmVerifyResult,
  expected: Uint8Array,
  requireFreshness: boolean,
  warnings: string[],
): void {
  if (result.report_data_match === true) return;
  if (requireFreshness) {
    fail(
      "report_data_mismatch",
      "report_data does not bind the expected session and identity transcript",
      { details: { expected: bytesToHex(expected), got: result.claims.report_data } },
    );
  }
  warnings.push(
    "freshness binding not enforced (requireFreshness=false): hardware signature and " +
      "measurement are verified, but report_data is not bound to this session transcript",
  );
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
  validatePolicy(policy);
  const warnings: string[] = [];
  const wantPlatform = policy.platform ?? "snp";
  const requireFreshness = policy.requireFreshness !== false;
  const sessionPubKey = decodeSessionPublicKey(bundle, nonce);
  const identity = await prepareIdentity(bundle, sessionPubKey, nonce, policy);
  const result = await verifyHardwareAttestation(
    bundle,
    identity.transcript,
    wantPlatform,
    requireFreshness,
  );
  const measurement = verifyMeasurement(result, policy.measurements);
  verifyFreshness(result, identity.transcript, requireFreshness, warnings);
  await verifyMeshIdentityProof(
    identity.proof,
    identity.transcript,
    identity.chain.leaf,
    identity.chain.ca,
  );

  return {
    ok: true,
    platform: result.platform,
    measurement,
    reportVersion: result.report_version ?? 0,
    reportDataMatch: result.report_data_match,
    identityBound: result.report_data_match === true,
    keyAgreementContext: identity.transcript,
    sessionPubKey,
    cert: certInfo(identity.chain),
    claims: result.claims,
    warnings,
  };
}

function certInfo(chain: ChainResult): CertInfo {
  return {
    subjectCN: chain.leaf.subjectCN,
    issuerCN: chain.leaf.issuerCN,
    sha256: chain.leafSha256,
    caSha256: chain.caSha256,
    notAfter: chain.leaf.notAfter.toISOString(),
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
  if (!opts) {
    fail("invalid_request", "verification options are required");
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
