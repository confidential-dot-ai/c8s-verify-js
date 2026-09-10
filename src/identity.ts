import { subtle } from "./crypto-env.js";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatBytes,
  constantTimeEqual,
  utf8ToBytes,
} from "./base64.js";
import { C8sVerifyError, fail } from "./errors.js";
import { NONCE_BYTES } from "./nonce.js";
import { verifyECDSASignature, type Certificate } from "./x509.js";
import { XWING_CT_BYTES, XWING_EK_BYTES } from "./xwing.js";
import { SESSION_ID_BYTES } from "./channel.js";

/**
 * Binding identifier of the `attest-pq` response bundle. Each endpoint's
 * response carries its own identifier and a client requires the one selected
 * by its endpoint — `c8s/attest-lb/v1` (a native-client sibling protocol this
 * browser library cannot implement) and the retired `c8s-verify/v1` bundle
 * are rejected even when their evidence is otherwise valid.
 */
export const BINDING_ATTEST_PQ = "c8s/attest-pq/v1";
/**
 * Identity-transcript domain tag, shared with c8s pkg/overenc. Deliberately
 * NOT the bundle binding id above: the transcript construction (and the HKDF
 * info derived from it) is unchanged from the original protocol, only the
 * endpoint and its bundle version moved.
 */
export const TRANSCRIPT_DOMAIN_TAG = "c8s-verify/v1";
export const IDENTITY_PROOF_ALGORITHM = "ecdsa-sha384";
/** SHA-384 transcript hash length; also the v1 HKDF context length. */
export const IDENTITY_TRANSCRIPT_BYTES = 48;

const TRANSCRIPT_DOMAIN = utf8ToBytes(TRANSCRIPT_DOMAIN_TAG);

export interface MeshIdentityProof {
  algorithm: string;
  leaf_sha256: string;
  mesh_ca_sha256: string;
  signature: string;
}

function lengthPrefixed(field: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + field.length);
  new DataView(out.buffer, out.byteOffset, 4).setUint32(0, field.length, false);
  out.set(field, 4);
  return out;
}

async function sha256(input: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", input));
}

/**
 * Compute the v1 report_data transcript shared with c8s/pkg/overenc. It
 * commits the front-door mode and the complete key exchange — the client's
 * X-Wing encapsulation key, the server's ciphertext, the session id, and the
 * nonce — plus the exact mesh leaf and issuing mesh CA.
 */
export async function identityTranscriptHash(
  frontDoorMode: string,
  xwingEk: Uint8Array,
  xwingCt: Uint8Array,
  sessionId: Uint8Array,
  nonce: Uint8Array,
  leafDer: Uint8Array,
  caDer: Uint8Array,
): Promise<Uint8Array> {
  if (frontDoorMode === "") {
    fail("identity_binding", "identity transcript requires a front-door mode");
  }
  if (xwingEk.length !== XWING_EK_BYTES) {
    fail(
      "key_binding",
      `identity transcript X-Wing key must be ${XWING_EK_BYTES} bytes, got ${xwingEk.length}`,
    );
  }
  if (xwingCt.length !== XWING_CT_BYTES) {
    fail(
      "key_binding",
      `identity transcript X-Wing ciphertext must be ${XWING_CT_BYTES} bytes, got ${xwingCt.length}`,
    );
  }
  if (sessionId.length !== SESSION_ID_BYTES) {
    fail(
      "key_binding",
      `identity transcript session id must be ${SESSION_ID_BYTES} bytes, got ${sessionId.length}`,
    );
  }
  if (nonce.length !== NONCE_BYTES) {
    fail(
      "identity_binding",
      `identity-bound PQ requires a ${NONCE_BYTES}-byte nonce, got ${nonce.length}`,
    );
  }
  if (leafDer.length === 0 || caDer.length === 0) {
    fail("identity_binding", "identity transcript requires leaf and CA certificates");
  }

  // Most-stable fields first so a signer can reuse the hash state across sessions.
  const encoded = concatBytes(
    lengthPrefixed(TRANSCRIPT_DOMAIN),
    lengthPrefixed(utf8ToBytes(frontDoorMode)),
    lengthPrefixed(await sha256(caDer)),
    lengthPrefixed(await sha256(leafDer)),
    lengthPrefixed(xwingEk),
    lengthPrefixed(xwingCt),
    lengthPrefixed(sessionId),
    lengthPrefixed(nonce),
  );
  return new Uint8Array(await subtle().digest("SHA-384", encoded));
}

/** Reject anything that is not a SHA-384 transcript hash. */
export function assertTranscriptLength(transcriptHash: Uint8Array): void {
  if (transcriptHash.length !== IDENTITY_TRANSCRIPT_BYTES) {
    fail(
      "identity_binding",
      `identity transcript hash must be ${IDENTITY_TRANSCRIPT_BYTES} bytes, got ${transcriptHash.length}`,
    );
  }
}

function decodeProofField(value: string): Uint8Array {
  try {
    return base64UrlToBytes(value);
  } catch (cause) {
    fail("identity_binding", "mesh identity proof fields must be base64url", { cause });
  }
}

/**
 * Select the pinned CA the proof commits to, comparing decoded hash bytes so
 * selection accepts exactly the encodings {@link verifyMeshIdentityProof}
 * accepts. Returns undefined when the proof names none of the pinned CAs.
 */
export async function selectPinnedCA(
  proof: MeshIdentityProof,
  pinnedCADers: Uint8Array[],
): Promise<Uint8Array | undefined> {
  const want = decodeProofField(proof.mesh_ca_sha256);
  for (const candidate of pinnedCADers) {
    if (constantTimeEqual(await sha256(candidate), want)) return candidate;
  }
  return undefined;
}

/** Verify certificate fingerprints and proof of possession for a v1 transcript. */
export async function verifyMeshIdentityProof(
  proof: MeshIdentityProof,
  transcriptHash: Uint8Array,
  leaf: Certificate,
  ca: Certificate,
): Promise<void> {
  assertTranscriptLength(transcriptHash);
  if (proof.algorithm !== IDENTITY_PROOF_ALGORITHM) {
    fail("identity_binding", `unsupported mesh identity proof algorithm ${proof.algorithm}`);
  }

  if (!constantTimeEqual(decodeProofField(proof.leaf_sha256), await sha256(leaf.der))) {
    fail("identity_binding", "mesh identity proof does not commit to the served leaf");
  }
  if (!constantTimeEqual(decodeProofField(proof.mesh_ca_sha256), await sha256(ca.der))) {
    fail("identity_binding", "mesh identity proof does not commit to the pinned mesh CA");
  }

  // The transcript's leading version tag domain-separates this signature.
  let ok: boolean;
  try {
    ok = await verifyECDSASignature(
      leaf,
      transcriptHash,
      decodeProofField(proof.signature),
      "SHA-384",
    );
  } catch (e) {
    // ecdsaDerToRaw / curve checks throw invalid_cert; the certificate itself
    // already verified, so surface a malformed proof under the precise code.
    if (e instanceof C8sVerifyError && e.code === "invalid_cert") {
      fail("identity_binding", "mesh identity proof signature is malformed", { cause: e });
    }
    throw e;
  }
  if (!ok) {
    fail("identity_binding", "mesh identity proof-of-possession signature is invalid");
  }
}

export async function certificateHashBase64Url(der: Uint8Array): Promise<string> {
  return bytesToBase64Url(await sha256(der));
}
