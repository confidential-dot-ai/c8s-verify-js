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
import type { PublicHalves } from "./keyagreement.js";

export const PROTOCOL_VERSION = "c8s-verify/v1";
export const IDENTITY_BINDING = "over-encryption";
export const IDENTITY_PROOF_ALGORITHM = "ecdsa-sha384";
/** SHA-384 transcript hash length; also the v1 HKDF context length. */
export const IDENTITY_TRANSCRIPT_BYTES = 48;

const TRANSCRIPT_DOMAIN = utf8ToBytes("c8s-verify/pq-mesh-identity/v1");
const PROOF_DOMAIN = utf8ToBytes("c8s-verify/pq-mesh-identity-proof/v1");

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
 * Compute the v1 report_data transcript shared with c8s/pkg/overenc.
 */
export async function identityTranscriptHash(
  pub: PublicHalves,
  nonce: Uint8Array,
  leafDer: Uint8Array,
  caDer: Uint8Array,
): Promise<Uint8Array> {
  if (pub.x25519.length !== 32) {
    fail(
      "key_binding",
      `identity transcript X25519 key must be 32 bytes, got ${pub.x25519.length}`,
    );
  }
  if (pub.mlkem768.length !== 1184) {
    fail(
      "key_binding",
      `identity transcript ML-KEM key must be 1184 bytes, got ${pub.mlkem768.length}`,
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

  const encoded = concatBytes(
    lengthPrefixed(TRANSCRIPT_DOMAIN),
    lengthPrefixed(pub.x25519),
    lengthPrefixed(pub.mlkem768),
    lengthPrefixed(nonce),
    lengthPrefixed(await sha256(leafDer)),
    lengthPrefixed(await sha256(caDer)),
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

export function identityProofMessage(transcriptHash: Uint8Array): Uint8Array {
  assertTranscriptLength(transcriptHash);
  return concatBytes(lengthPrefixed(PROOF_DOMAIN), lengthPrefixed(transcriptHash));
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
  if (proof.algorithm !== IDENTITY_PROOF_ALGORITHM) {
    fail("identity_binding", `unsupported mesh identity proof algorithm ${proof.algorithm}`);
  }

  if (!constantTimeEqual(decodeProofField(proof.leaf_sha256), await sha256(leaf.der))) {
    fail("identity_binding", "mesh identity proof does not commit to the served leaf");
  }
  if (!constantTimeEqual(decodeProofField(proof.mesh_ca_sha256), await sha256(ca.der))) {
    fail("identity_binding", "mesh identity proof does not commit to the pinned mesh CA");
  }

  let ok: boolean;
  try {
    ok = await verifyECDSASignature(
      leaf,
      identityProofMessage(transcriptHash),
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
