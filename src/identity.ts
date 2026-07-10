import { subtle } from "./crypto-env.js";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatBytes,
  constantTimeEqual,
  utf8ToBytes,
} from "./base64.js";
import { fail } from "./errors.js";
import { verifyECDSASignature, type Certificate } from "./x509.js";
import type { PublicHalves } from "./keyagreement.js";

export const IDENTITY_BINDING_V2 = "over-encryption+mesh-identity-v2";
export const IDENTITY_PROOF_ALGORITHM = "ecdsa-sha384";

const TRANSCRIPT_DOMAIN = utf8ToBytes("c8s-verify/pq-mesh-identity/v2");
const PROOF_DOMAIN = utf8ToBytes("c8s-verify/pq-mesh-identity-proof/v2");
const IDENTITY_NONCE_BYTES = 32;

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
 * Compute the v2 report_data transcript shared with c8s/pkg/overenc.
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
  if (nonce.length !== IDENTITY_NONCE_BYTES) {
    fail(
      "identity_binding",
      `identity-bound PQ requires a ${IDENTITY_NONCE_BYTES}-byte nonce, got ${nonce.length}`,
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

export function identityProofMessage(transcriptHash: Uint8Array): Uint8Array {
  if (transcriptHash.length !== 48) {
    fail(
      "identity_binding",
      `identity transcript hash must be 48 bytes, got ${transcriptHash.length}`,
    );
  }
  return concatBytes(lengthPrefixed(PROOF_DOMAIN), lengthPrefixed(transcriptHash));
}

/** Verify certificate fingerprints and proof of possession for a v2 transcript. */
export async function verifyMeshIdentityProof(
  proof: MeshIdentityProof,
  transcriptHash: Uint8Array,
  leaf: Certificate,
  ca: Certificate,
): Promise<void> {
  if (proof.algorithm !== IDENTITY_PROOF_ALGORITHM) {
    fail("identity_binding", `unsupported mesh identity proof algorithm ${proof.algorithm}`);
  }

  const wantLeafHash = await sha256(leaf.der);
  const wantCAHash = await sha256(ca.der);
  let gotLeafHash: Uint8Array;
  let gotCAHash: Uint8Array;
  let signature: Uint8Array;
  try {
    gotLeafHash = base64UrlToBytes(proof.leaf_sha256);
    gotCAHash = base64UrlToBytes(proof.mesh_ca_sha256);
    signature = base64UrlToBytes(proof.signature);
  } catch (cause) {
    fail("identity_binding", "mesh identity proof fields must be base64url", { cause });
  }
  if (!constantTimeEqual(gotLeafHash, wantLeafHash)) {
    fail("identity_binding", "mesh identity proof does not commit to the served leaf");
  }
  if (!constantTimeEqual(gotCAHash, wantCAHash)) {
    fail("identity_binding", "mesh identity proof does not commit to the pinned mesh CA");
  }

  const ok = await verifyECDSASignature(
    leaf,
    identityProofMessage(transcriptHash),
    signature,
    "SHA-384",
  );
  if (!ok) {
    fail("identity_binding", "mesh identity proof-of-possession signature is invalid");
  }
}

export async function certificateHashBase64Url(der: Uint8Array): Promise<string> {
  return bytesToBase64Url(await sha256(der));
}
