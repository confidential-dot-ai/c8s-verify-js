// The verification policy layer. Wraps the attestation-rs WASM verifier and the
// X.509 chain check, and turns their raw outputs into a pass/fail decision against
// a caller-supplied policy (expected measurements, platform, freshness binding).

import { verifySnp, verifyAzSnp, verifyAzTdx, verifyTdx } from "./wasm-loader.js";
import { verifyCertChain, type Certificate, type ChainResult } from "./x509.js";
import { decodePEM } from "./pem.js";
import { bytesToHex, base64UrlToBytes, constantTimeEqual } from "./base64.js";
import { fail } from "./errors.js";
import type { Evidence } from "./hcl.js";
import {
  BINDING_ATTEST_PQ,
  identityTranscriptHash,
  selectPinnedCA,
  verifyMeshIdentityProof,
  type MeshIdentityProof,
} from "./identity.js";
import {
  OID_MATCHED_WORKLOAD,
  allowlistDigestHex,
  parseAllowlist,
  parseMatchedWorkload,
  resolveWorkload,
} from "./workload.js";
import { requireTdxImage, type TdxImage } from "./manifest.js";

export interface VerifyPolicy {
  /** accepted launch digests (hex sha-384) */
  measurements: string[];
  /** default "snp"; also "az-snp" | "az-tdx" | "tdx" (bare-metal Intel TDX) */
  platform?: string;
  /** default true: report_data must bind the selected session transcript */
  requireFreshness?: boolean;
  /**
   * Mesh CA pinned out of band. Optional: the required anchor is this pin OR
   * `allowlist`. When absent, the anchor is the transcript-committed CA
   * selected from the served chain — the identity transcript authenticates
   * the choice, and the verdict is deployment-class rather than
   * specific-cluster (see {@link AttestationResult.trustClass}).
   */
  meshCaPem?: string;
  /**
   * Exact canonical allowlist bytes (`GET /allowlist` response, or the output
   * of the canonicalization tool), pinned out of band. A string is
   * UTF-8-encoded verbatim, never parsed-and-reserialized — the stamp commits
   * SHA-256 over these exact bytes.
   *
   * Pinning it requires the mesh leaf to carry a matched-workload stamp whose
   * allowlist digest equals SHA-256 of these bytes, and resolves the stamped
   * name in this document. Serves as the trust anchor when `meshCaPem` is
   * absent.
   */
  allowlist?: Uint8Array | string;
  /**
   * Expected matched-workload name. Requires the mesh leaf to carry a stamp
   * naming exactly this workload. The stamp is CA-vouched, so this is
   * enforced only after the chain check — which either anchor provides.
   */
  workloadName?: string;
  /** validity reference time (default now) */
  at?: Date;
  /**
   * Expected TDX RTMR[3] (96 hex chars), pinned out of band. Optional.
   *
   * `measurements` pins the *code*, but the c8s images are open source and
   * reproducible, so a valid launch digest only proves "a genuine instance of
   * the audited build on real silicon" — which an attacker can also stand up
   * and proxy you to. RTMR[3] is extended after launch with the operator key
   * bound at boot (and any per-workload measurements chained onto it), so it
   * is unique to a deployment. Pinning it is what makes the verdict "this
   * operator's cluster" rather than "some genuine cluster".
   *
   * Complements `meshCaPem`, which is also cluster-unique but is regenerated
   * inside the CDS TEE on every install; the operator key survives reinstalls
   * and image rebuilds, so it can be published in advance.
   *
   * TDX only — the register does not exist on SNP, and the verifier consults
   * it only on the TDX path. Combining it with any other platform is rejected
   * rather than silently ignored.
   */
  expectedRtmr3?: string;
  /**
   * The complete TDX guest-image pin: MRTD + RTMR[1] + RTMR[2] as one tuple,
   * each exactly 96 lowercase hex chars, published with the image build (feed
   * a manifest file to {@link parseImageManifest}). `measurements` alone pins
   * only MRTD, which covers the TDVF firmware — the guest kernel and rootfs
   * land in RTMR[1]/RTMR[2], so only the tuple identifies the image. The
   * tuple's `mrtd` joins the `measurements` allowlist and `rtmr1`/`rtmr2` are
   * compared exactly against the verified claims. All three registers or
   * none: a partial tuple is rejected rather than partially enforced.
   *
   * Required for a TDX deployment-class verdict (no `meshCaPem`), where the
   * measurement policy is the entire anchor; with a pinned mesh CA it is
   * strongly recommended, and its absence is a prominent warning.
   *
   * TDX only — SNP's launch measurement already covers the full image and has
   * no runtime-register equivalent, so combining this with any other platform
   * is rejected rather than silently ignored.
   */
  tdxImage?: TdxImage;
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
  /**
   * RTMR[3] comparison result, present only when a pin was supplied. The
   * verifier core omits the field entirely when it never performed the
   * comparison, so `undefined` means "not checked" — never "fine".
   */
  rtmr3_match?: boolean | null;
  claims: WasmClaims;
}

export interface CertInfo {
  subjectCN: string | null;
  issuerCN: string | null;
  sha256: string;
  caSha256: string;
  notAfter: string;
}

/** A verified matched-workload stamp, surfaced on the result. */
export interface WorkloadInfo {
  /** The stamped (and, when pinned, matched) workload name. */
  name: string;
  /** Allowlist store version the stamp's match was decided under. */
  allowlistVersion: string;
  /** Hex SHA-256 of the canonical allowlist bytes the stamp commits to. */
  allowlistDigestHex: string;
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
  /**
   * The mesh leaf's verified matched-workload stamp. Present only when a
   * workload policy (`workloadName` and/or `allowlist`) was pinned and every
   * check passed; without a pin the stamp is not read at all.
   */
  workload?: WorkloadInfo;
  /**
   * What the verdict identifies. `"specific-cluster"` iff `meshCaPem` was
   * pinned: the chain anchors to a CA the caller chose out of band.
   * `"deployment-class"` means the CA was derived from the transcript
   * commitment — the verdict says "a genuine instance of this measured
   * deployment", never "my cluster"; a genuine clone cluster booted from the
   * same measured images and policy is indistinguishable by public inputs.
   */
  trustClass: "deployment-class" | "specific-cluster";
  /**
   * The TDX runtime measurement registers this verdict compared exactly, as
   * "<index>:<expected hex>" (e.g. "1:<rtmr1>", "2:<rtmr2>" from the
   * `tdxImage` tuple, "3:<rtmr3>" from `expectedRtmr3`). Present only when at
   * least one register pin was enforced — absent means only the launch digest
   * was pinned.
   */
  rtmrsPinned?: string[];
  warnings: string[];
}

// The vTPM (az-snp, az-tdx) and bare-tdx verifiers bind the freshness anchor in
// the verifier core and FAIL CLOSED — they throw on a mismatch rather than
// returning a non-throwing report_data_match=false (which is what bare
// `verify_snp` does). Recognize that specific failure by message so the policy
// layer can surface it as the precise `report_data_mismatch` code instead of a
// generic `verification_failed`, and so the soft (requireFreshness=false) path
// can tell a freshness mismatch apart from a real hardware/signature failure.
function isFreshnessMismatch(e: unknown): boolean {
  const msg = String((e as { message?: unknown })?.message ?? e);
  return /report_data mismatch|TPM nonce (length )?mismatch/i.test(msg);
}

/** Best-effort error message for embedding in a typed failure. */
function errMessage(e: unknown): string {
  return String((e as { message?: unknown })?.message ?? e);
}

/** The TDX verifier reports the registers under claims.platform_data. */
function rtmrFromClaims(result: WasmVerifyResult, idx: number): unknown {
  const pd = result.claims.platform_data as Record<string, unknown> | undefined;
  return pd?.[`rtmr_${idx}`];
}

function rtmr3FromClaims(result: WasmVerifyResult): string {
  const rtmr3 = rtmrFromClaims(result, 3);
  return typeof rtmr3 === "string" ? rtmr3 : "";
}

/** The exact register encoding the claims carry: 96 lowercase hex chars. */
const CLAIM_REGISTER_HEX = /^[0-9a-f]{96}$/;

/**
 * Enforce the RTMR[1]/RTMR[2] half of a TDX image pin against the VERIFIED
 * claims (the tuple's MRTD is enforced through the launch-digest allowlist
 * instead). Register-exact lowercase-hex comparison; an absent or malformed
 * claim fails closed — a claim that cannot be compared must never read as a
 * pin that held. Returns the `rtmrsPinned` entries ("<idx>:<hex>") recorded on
 * the result. Exported for direct testing of the fail-closed paths; callers
 * go through {@link verifyAttestation} / {@link verifyEvidence}.
 */
export function enforceTdxImagePins(result: WasmVerifyResult, image: TdxImage): string[] {
  const pinned: string[] = [];
  for (const [idx, meaning, want] of [
    [1, "guest kernel", image.rtmr1],
    [2, "guest rootfs", image.rtmr2],
  ] as const) {
    const got = rtmrFromClaims(result, idx);
    if (typeof got !== "string" || !CLAIM_REGISTER_HEX.test(got)) {
      fail(
        "rtmr_denied",
        `cannot enforce the RTMR[${idx}] pin: the verified claims carry no well-formed ` +
          `rtmr_${idx} — refusing to report a pin that was never compared`,
        { details: { register: `rtmr_${idx}`, expected: want, got } },
      );
    }
    if (got !== want) {
      fail(
        "rtmr_denied",
        `RTMR[${idx}] (${meaning}) is ${got}, expected ${want}: the TD is not running the ` +
          "pinned guest image, even though its launch digest may match",
        { details: { register: `rtmr_${idx}`, expected: want, got } },
      );
    }
    pinned.push(`${idx}:${want}`);
  }
  return pinned;
}

/**
 * The TDX verifier throws on an RTMR[3] mismatch (it fails closed rather than
 * only reporting), so recognise that specific throw and surface it as
 * rtmr3_denied instead of the generic verification_failed used for chain and
 * signature failures. A caller distinguishing "wrong cluster" from "broken
 * evidence" needs the codes to differ.
 */
function isRtmr3Mismatch(e: unknown): boolean {
  return /RTMR\[3\] does not match/i.test(errMessage(e));
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
  // The required anchor: a mesh CA pinned out of band, OR canonical allowlist
  // bytes enforced against the stamp on the derived-CA chain. Both together is
  // fine (specific-cluster plus policy skew detection); neither leaves the
  // measurement pins anchoring nothing cluster- or deployment-specific.
  if (policy.meshCaPem !== undefined) {
    if (typeof policy.meshCaPem !== "string" || policy.meshCaPem.trim() === "") {
      fail("identity_binding", "meshCaPem must be a non-empty PEM string when set");
    }
  }
  if (policy.allowlist !== undefined) {
    const empty =
      typeof policy.allowlist === "string"
        ? policy.allowlist.length === 0
        : !(policy.allowlist instanceof Uint8Array) || policy.allowlist.length === 0;
    if (empty) {
      fail(
        "invalid_request",
        "allowlist must be the non-empty exact canonical document bytes (or the same as a " +
          "verbatim UTF-8 string)",
      );
    }
  }
  if (policy.meshCaPem === undefined && policy.allowlist === undefined) {
    fail(
      "identity_binding",
      "verification requires an anchor: pin meshCaPem out of band (specific-cluster), or pin " +
        "the exact canonical allowlist bytes to enforce against the mesh leaf's " +
        "matched-workload stamp (deployment-class)",
    );
  }
  if (policy.workloadName !== undefined) {
    if (typeof policy.workloadName !== "string" || policy.workloadName === "") {
      fail(
        "invalid_request",
        "workloadName must be a non-empty workload entry name — an empty pin that enforces " +
          "nothing is worse than no pin",
      );
    }
  }
  if (policy.expectedRtmr3 !== undefined) {
    // Reject here rather than at verification time: a pin the verifier would
    // silently drop is worse than no pin, because the caller believes it is
    // enforcing deployment identity.
    const platform = policy.platform ?? "snp";
    if (platform !== "tdx") {
      fail(
        "invalid_request",
        `expectedRtmr3 requires platform "tdx" (got ${JSON.stringify(platform)}): the runtime measurement register is TDX-only, so the pin could not be enforced`,
      );
    }
    if (
      typeof policy.expectedRtmr3 !== "string" ||
      !/^[0-9a-fA-F]{96}$/.test(policy.expectedRtmr3)
    ) {
      fail("invalid_request", "expectedRtmr3 must be 96 hex characters (48 bytes, SHA-384)");
    }
  }
  if (policy.tdxImage !== undefined) {
    // Same platform rule as expectedRtmr3: a pin the verifier would silently
    // drop is worse than no pin.
    const platform = policy.platform ?? "snp";
    if (platform !== "tdx") {
      fail(
        "invalid_request",
        `tdxImage requires platform "tdx" (got ${JSON.stringify(platform)}): SNP's launch measurement already covers the full image and has no runtime-register equivalent, so the pin could not be enforced`,
      );
    }
    requireTdxImage("tdxImage", policy.tdxImage);
  }
}

/** Decode a 96-hex-char RTMR[3] pin. Callers validate the shape first. */
function decodeRtmr3(hex: string): Uint8Array {
  const out = new Uint8Array(48);
  for (let i = 0; i < 48; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
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
  warnings: string[],
): Promise<PreparedIdentity> {
  // Exactly the attest-pq binding id: an attest-lb response (native-client
  // sibling protocol) or a stale pre-cutover c8s-verify/v1 bundle carries
  // otherwise-valid evidence for a DIFFERENT trust decision, so both are
  // rejected here rather than adapted to.
  if (bundle?.version !== BINDING_ATTEST_PQ) {
    fail(
      "identity_binding",
      `attestation response has version ${JSON.stringify(bundle?.version)}, ` +
        `want ${BINDING_ATTEST_PQ}`,
    );
  }
  if (!isMeshIdentityProof(bundle.identity_proof)) {
    fail("identity_binding", "attestation response omitted or malformed identity_proof");
  }
  if (typeof bundle.cds_cert_pem !== "string" || bundle.cds_cert_pem.trim() === "") {
    fail("identity_binding", "attestation response omitted cds_cert_pem");
  }

  const leafBlocks = decodePEM(bundle.cds_cert_pem, "CERTIFICATE");
  if (leafBlocks.length === 0) {
    fail("invalid_cert", "identity verification requires a served leaf certificate");
  }

  let selectedCA: Uint8Array | undefined;
  if (policy.meshCaPem !== undefined) {
    const pinnedCAs = decodePEM(policy.meshCaPem, "CERTIFICATE");
    if (pinnedCAs.length === 0) {
      fail("invalid_cert", "meshCaPem contains no PEM CERTIFICATE block");
    }
    // Multi-block meshCaPem means "every block in here is independently
    // trusted", and selectPinnedCA will happily anchor to whichever one the
    // proof names. That is the documented contract, but it is also what a
    // caller gets by accident if they pass a chain the *server* handed them —
    // at which point the pin is not a pin.
    if (pinnedCAs.length > 1) {
      warnings.push(
        `meshCaPem pins ${pinnedCAs.length} certificates and each is independently trusted as ` +
          "an anchor; pass a single CA",
      );
    }
    selectedCA = await selectPinnedCA(bundle.identity_proof, pinnedCAs);
    if (!selectedCA) {
      fail("identity_binding", "identity proof does not name any pinned mesh CA");
    }
  } else {
    // No pin: derive the anchor from the SERVED chain (blocks after the leaf)
    // by the proof's mesh_ca_sha256 commitment. Selection alone trusts
    // nothing — the transcript verification that follows binds the selected
    // CA's digest into hardware-signed report_data and the leaf's proof of
    // possession, which is what authenticates the choice. The verdict is
    // deployment-class: the CA identifies the deployment the evidence came
    // from, not a cluster the caller chose (see AttestationResult.trustClass).
    selectedCA = await selectPinnedCA(bundle.identity_proof, leafBlocks.slice(1));
    if (!selectedCA) {
      fail(
        "identity_binding",
        "no served CA certificate matches the identity proof's mesh CA commitment, so the " +
          "anchor cannot be derived from this response",
      );
    }
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
  expectedRtmr3?: Uint8Array,
): Promise<WasmVerifyResult> {
  // The Azure vTPM platforms (az-snp, az-tdx) get full verification (HCL report
  // + vTPM quote + hardware quote), with the transcript checked against the TPM
  // quote's extraData. Bare tdx verifies the TD quote + DCAP chain directly,
  // and bare snp the SNP report only, each checking the transcript against the
  // quote's report_data. All return the same result shape, so the policy checks
  // stay platform-agnostic.
  const isAzSnp = wantPlatform === "az-snp";
  const isAzTdx = wantPlatform === "az-tdx";
  const isTdx = wantPlatform === "tdx";
  // These verifiers fail closed (throw) on a freshness mismatch, so in soft
  // mode (requireFreshness=false) we omit the anchor to get a non-throwing
  // result and warn later; bare snp returns a non-throwing bool either way.
  const failsClosedOnMismatch = isAzSnp || isAzTdx || isTdx;
  const hardAnchor = requireFreshness ? expected : undefined;
  let result: WasmVerifyResult;
  try {
    let out: string;
    if (isAzSnp) out = await verifyAzSnp(JSON.stringify(bundle.evidence), hardAnchor);
    else if (isAzTdx) out = await verifyAzTdx(JSON.stringify(bundle.evidence), hardAnchor);
    else if (isTdx)
      out = await verifyTdx(JSON.stringify(bundle.evidence), hardAnchor, undefined, expectedRtmr3);
    else out = await verifySnp(bundle.evidence, bundle.generation, expected);
    result = JSON.parse(out) as WasmVerifyResult;
  } catch (e) {
    if (failsClosedOnMismatch && requireFreshness && isFreshnessMismatch(e)) {
      fail(
        "report_data_mismatch",
        "report_data does not bind this session transcript (stale or substituted evidence)",
        { details: { expected: bytesToHex(expected) }, cause: e },
      );
    }
    if (expectedRtmr3 !== undefined && isRtmr3Mismatch(e)) {
      fail(
        "rtmr3_denied",
        "RTMR[3] does not match the pinned value: this is a genuine TEE, but not the deployment the pin was taken from",
        { details: { expected: bytesToHex(expectedRtmr3) }, cause: e },
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
  // The WASM entry point already throws on a mismatch, but do not rely on that
  // alone: the verifier core only *records* the comparison, and an older or
  // substituted verifier build that ignored the argument would return a
  // perfectly valid-looking result with the field absent. Require an explicit
  // true — `undefined` means the comparison never ran, which is a failure, not
  // an absence.
  if (expectedRtmr3 !== undefined && result.rtmr3_match !== true) {
    fail(
      "rtmr3_denied",
      result.rtmr3_match === false
        ? "RTMR[3] does not match the pinned value: this is a genuine TEE, but not the deployment the pin was taken from"
        : "RTMR[3] was not checked by the verifier (no rtmr3_match in the result) — refusing to report a pin that was never enforced",
      {
        details: {
          expected: bytesToHex(expectedRtmr3),
          got: rtmr3FromClaims(result),
        },
      },
    );
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
 * Enforce the workload policy against the CHAIN-VERIFIED mesh leaf. The stamp
 * is placed by CDS in the CA-signed area, so the chain — not the hardware
 * evidence — is what vouches for it; verifyAttestation calls this only after
 * every identity check has passed. Order: parse → digest check (when the
 * allowlist is pinned) → name-pin check → name resolution.
 */
async function verifyWorkloadPolicy(
  leaf: Certificate,
  policy: VerifyPolicy,
): Promise<WorkloadInfo | undefined> {
  if (policy.workloadName === undefined && policy.allowlist === undefined) {
    return undefined;
  }
  const extnValue = leaf.extensions.get(OID_MATCHED_WORKLOAD);
  if (extnValue === undefined) {
    // Absence is a real lifecycle state (a leaf issued before the pod's match
    // resolved carries no stamp), not damage — hence _not_attested, not
    // _denied. A pinned client still fails closed on it.
    fail(
      "workload_not_attested",
      "a workload/allowlist pin is set but the mesh leaf carries no matched-workload " +
        `extension (${OID_MATCHED_WORKLOAD}): the pod has no verified workload identity ` +
        "(unnamed leaves are issued mid-lifecycle by design)",
    );
  }
  const stamp = parseMatchedWorkload(extnValue);
  const stampDigestHex = bytesToHex(stamp.allowlistDigest);

  if (policy.allowlist !== undefined) {
    const pinnedDigestHex = await allowlistDigestHex(policy.allowlist);
    if (stampDigestHex !== pinnedDigestHex) {
      fail(
        "allowlist_denied",
        `the stamp's allowlist digest ${stampDigestHex} does not match the pinned canonical ` +
          `bytes (${pinnedDigestHex}): CDS decided this match under a different policy ` +
          "document than the one pinned (hash the exact canonical bytes, never a " +
          "re-serialized copy)",
        { details: { stamped: stampDigestHex, pinned: pinnedDigestHex } },
      );
    }
  }
  if (policy.workloadName !== undefined && stamp.name !== policy.workloadName) {
    fail(
      "workload_denied",
      `mesh leaf is stamped for workload ${JSON.stringify(stamp.name)}, not the pinned ` +
        JSON.stringify(policy.workloadName),
      { details: { stamped: stamp.name, pinned: policy.workloadName } },
    );
  }
  if (policy.allowlist !== undefined) {
    resolveWorkload(parseAllowlist(policy.allowlist), stamp.name);
  }

  return {
    name: stamp.name,
    allowlistVersion: stamp.allowlistVersion,
    allowlistDigestHex: stampDigestHex,
  };
}

/**
 * Verify an attestation bundle end to end.
 *
 * @param bundle the LB attest-pq response
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
  const identity = await prepareIdentity(bundle, sessionPubKey, nonce, policy, warnings);
  const result = await verifyHardwareAttestation(
    bundle,
    identity.transcript,
    wantPlatform,
    requireFreshness,
    policy.expectedRtmr3 === undefined ? undefined : decodeRtmr3(policy.expectedRtmr3),
  );
  // The image tuple's MRTD is an accepted launch digest alongside the
  // explicit allowlist; RTMR[1]/[2] are compared exactly below.
  const measurement = verifyMeasurement(
    result,
    policy.tdxImage === undefined
      ? policy.measurements
      : [...policy.measurements, policy.tdxImage.mrtd],
  );
  const rtmrsPinned: string[] = [];
  if (policy.tdxImage !== undefined) {
    rtmrsPinned.push(...enforceTdxImagePins(result, policy.tdxImage));
  }
  if (policy.expectedRtmr3 !== undefined) {
    // Enforced above by verifyHardwareAttestation (rtmr3_match must be true);
    // recorded here so the result reports every register the verdict pinned.
    rtmrsPinned.push(`3:${policy.expectedRtmr3.toLowerCase()}`);
  }
  verifyFreshness(result, identity.transcript, requireFreshness, warnings);
  await verifyMeshIdentityProof(
    identity.proof,
    identity.transcript,
    identity.chain.leaf,
    identity.chain.ca,
  );
  // Workload policy runs LAST: the stamp is CA-vouched, so it is meaningful
  // only once steps 1–5 (versions, evidence, measurement, transcript, proof,
  // chain) have all passed.
  const workload = await verifyWorkloadPolicy(identity.chain.leaf, policy);

  // On TDX, MRTD covers only the TDVF firmware — the guest kernel and rootfs
  // live in RTMR[1]/RTMR[2] — so without the tdxImage tuple the measurement
  // policy is not platform-complete. A derived-CA (deployment-class) verdict
  // rests entirely on the measurement policy identifying the deployment, so
  // there the incomplete policy is rejected outright; with a pinned mesh CA
  // cluster identity does not depend on the measurement pins, so the gap is a
  // prominent warning instead.
  if (wantPlatform === "tdx" && policy.tdxImage === undefined) {
    if (policy.meshCaPem === undefined) {
      fail(
        "measurement_incomplete",
        "TDX deployment-class verdict requires a platform-complete image pin: MRTD alone " +
          "covers only the TDVF firmware, leaving the guest kernel and rootfs (RTMR[1]/" +
          "RTMR[2]) unmeasured, so `measurements` is not a complete TDX image policy. Pass " +
          "tdxImage with the mrtd+rtmr1+rtmr2 tuple from the image build's manifest (see " +
          "parseImageManifest), or pin meshCaPem for a specific-cluster verdict",
      );
    }
    warnings.push(
      "TDX measurement policy is not platform-complete: only MRTD (and optionally RTMR[3]) " +
        "is pinned, not RTMR[1]/RTMR[2], so the guest kernel and rootfs are not covered by " +
        "the image pin; cluster identity rests on the meshCaPem pin alone. Pass tdxImage " +
        "with the mrtd+rtmr1+rtmr2 tuple from the image build's manifest to close the gap",
    );
  }

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
    workload,
    trustClass: policy.meshCaPem !== undefined ? "specific-cluster" : "deployment-class",
    ...(rtmrsPinned.length > 0 ? { rtmrsPinned } : {}),
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
   * "milan" | "genoa" | "turin"; required for "snp", ignored for "az-snp"
   * (auto-detected from CPUID) and the TDX platforms
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
  /**
   * expected TDX RTMR[3] (96 hex chars), pinned out of band; a mismatch fails
   * closed. Where `measurements` pins the build, this pins the deployment —
   * RTMR[3] carries the operator key bound at launch, which a reproducible
   * image digest cannot. Requires `platform: "tdx"`.
   */
  expectedRtmr3?: string;
  /**
   * The complete TDX guest-image pin (mrtd + rtmr1 + rtmr2, each 96 lowercase
   * hex chars; see {@link VerifyPolicy.tdxImage} and `parseImageManifest`).
   * The tuple's `mrtd` joins the `measurements` allowlist and `rtmr1`/`rtmr2`
   * are compared exactly; a mismatch or an uncomparable claim fails closed.
   * Requires `platform: "tdx"`.
   */
  tdxImage?: TdxImage;
}

export interface EvidenceResult {
  ok: true;
  platform: string;
  measurement: string;
  reportVersion: number;
  reportDataMatch: boolean | null;
  claims: WasmClaims;
  /** Register pins this verdict compared exactly; see {@link AttestationResult.rtmrsPinned}. */
  rtmrsPinned?: string[];
  warnings: string[];
}

/**
 * Verify a bare SEV-SNP evidence object: the AMD hardware signature + VCEK chain
 * (in WASM, bundled roots), the launch-measurement allowlist, the platform, and
 * — when the caller supplies one — a `report_data` binding.
 *
 * Unlike {@link verifyAttestation}, this takes the raw `attestation-rs`
 * `SnpEvidence` directly and needs no `attest-pq` bundle, client nonce,
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
  const isAzSnp = wantPlatform === "az-snp";
  const isAzTdx = wantPlatform === "az-tdx";
  const isTdx = wantPlatform === "tdx";
  const isVtpm = isAzSnp || isAzTdx;
  // The vTPM platforms auto-detect the generation from the report, and TDX has
  // no generation concept; bare snp needs it.
  if (!isVtpm && !isTdx && !opts.generation) {
    fail("invalid_request", 'generation is required ("milan" | "genoa" | "turin")');
  }
  let wantRtmr3: Uint8Array | undefined;
  if (opts.expectedRtmr3 !== undefined) {
    if (!isTdx) {
      fail(
        "invalid_request",
        `expectedRtmr3 requires platform "tdx" (got ${JSON.stringify(wantPlatform)}): the runtime measurement register is TDX-only, so the pin could not be enforced`,
      );
    }
    if (typeof opts.expectedRtmr3 !== "string" || !/^[0-9a-fA-F]{96}$/.test(opts.expectedRtmr3)) {
      fail("invalid_request", "expectedRtmr3 must be 96 hex characters (48 bytes, SHA-384)");
    }
    wantRtmr3 = decodeRtmr3(opts.expectedRtmr3);
  }
  if (opts.tdxImage !== undefined) {
    // Same platform rule as expectedRtmr3: a pin the verifier would silently
    // drop is worse than no pin.
    if (!isTdx) {
      fail(
        "invalid_request",
        `tdxImage requires platform "tdx" (got ${JSON.stringify(wantPlatform)}): SNP's launch measurement already covers the full image and has no runtime-register equivalent, so the pin could not be enforced`,
      );
    }
    requireTdxImage("tdxImage", opts.tdxImage);
  }
  const expected = opts.expectedReportData;

  // Hardware attestation via WASM (throws on VCEK chain / report signature failure).
  let result: WasmVerifyResult;
  try {
    let out: string;
    if (isAzSnp) out = await verifyAzSnp(JSON.stringify(evidence), expected);
    else if (isAzTdx) out = await verifyAzTdx(JSON.stringify(evidence), expected);
    else if (isTdx) out = await verifyTdx(JSON.stringify(evidence), expected, undefined, wantRtmr3);
    else out = await verifySnp(evidence, opts.generation!, expected);
    result = JSON.parse(out) as WasmVerifyResult;
  } catch (e) {
    // The vTPM/tdx verifiers fail closed (throw) on a freshness mismatch when an
    // anchor is supplied — map it to the precise report_data_mismatch code
    // instead of the generic verification_failed used for chain/signature failures.
    if (wantRtmr3 !== undefined && isRtmr3Mismatch(e)) {
      fail(
        "rtmr3_denied",
        "RTMR[3] does not match the pinned value: this is a genuine TEE, but not the deployment the pin was taken from",
        { details: { expected: bytesToHex(wantRtmr3) }, cause: e },
      );
    }
    if ((isVtpm || isTdx) && expected !== undefined && isFreshnessMismatch(e)) {
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

  // Same reasoning as verifyAttestation: the WASM entry point throws on a
  // mismatch, but an older or substituted verifier build that ignored the
  // argument would return a valid-looking result with the field absent.
  // Require an explicit true.
  if (wantRtmr3 !== undefined && result.rtmr3_match !== true) {
    fail(
      "rtmr3_denied",
      result.rtmr3_match === false
        ? "RTMR[3] does not match the pinned value: this is a genuine TEE, but not the deployment the pin was taken from"
        : "RTMR[3] was not checked by the verifier (no rtmr3_match in the result) — refusing to report a pin that was never enforced",
      { details: { expected: bytesToHex(wantRtmr3), got: rtmr3FromClaims(result) } },
    );
  }

  // Measurement allowlist (case-insensitive hex). The image tuple's MRTD is
  // an accepted launch digest alongside the explicit allowlist.
  const measurement = String(result.claims.launch_digest).toLowerCase();
  const allow = (opts.measurements ?? []).map((m) => m.toLowerCase());
  if (opts.tdxImage !== undefined) allow.push(opts.tdxImage.mrtd);
  if (allow.length === 0) {
    warnings.push("no measurement allowlist provided — launch digest was not checked");
  } else if (!allow.includes(measurement)) {
    fail("measurement_denied", `launch digest ${measurement} is not in the allowlist`, {
      details: { measurement, allowed: allow },
    });
  }
  const rtmrsPinned: string[] = [];
  if (opts.tdxImage !== undefined) {
    rtmrsPinned.push(...enforceTdxImagePins(result, opts.tdxImage));
  }
  if (opts.expectedRtmr3 !== undefined) {
    rtmrsPinned.push(`3:${opts.expectedRtmr3.toLowerCase()}`);
  }
  if (isTdx && allow.length > 0 && opts.tdxImage === undefined) {
    warnings.push(
      "TDX measurement policy is not platform-complete: only MRTD (and optionally RTMR[3]) " +
        "is pinned, not RTMR[1]/RTMR[2], so the guest kernel and rootfs are not covered by " +
        "the image pin. Pass tdxImage with the mrtd+rtmr1+rtmr2 tuple from the image " +
        "build's manifest",
    );
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
    ...(rtmrsPinned.length > 0 ? { rtmrsPinned } : {}),
    warnings,
  };
}
