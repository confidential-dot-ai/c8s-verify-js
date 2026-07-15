// Node-side minting of the mesh identity proof — the server half of the
// protocol (see ../PROTOCOL.md), shared by the tests and the demo mock LB so
// both validate the same wire shape. Uses node:crypto signing, so it must
// never be imported from src/ (browser code only verifies).

import { sign } from "node:crypto";

import { bytesToBase64Url } from "../src/base64.js";
import {
  certificateHashBase64Url,
  IDENTITY_PROOF_ALGORITHM,
  PROTOCOL_VERSION,
  identityProofMessage,
  identityTranscriptHash,
  type MeshIdentityProof,
} from "../src/identity.js";
import type { PublicHalves } from "../src/keyagreement.js";

export interface IdentityBundleFields {
  version: string;
  identity_proof: MeshIdentityProof;
}

export interface MintedIdentityProof {
  transcript: Uint8Array;
  proof: MeshIdentityProof;
  bundleFields: IdentityBundleFields;
}

/**
 * Compute the transcript for a session and sign it with the mesh leaf key,
 * exactly as a real LB does. `bundleFields` is the ready-to-assign response
 * stamp, so the mock LB and test fixtures cannot drift apart.
 */
export async function mintIdentityProof(
  pub: PublicHalves,
  nonce: Uint8Array,
  leafDer: Uint8Array,
  caDer: Uint8Array,
  leafKeyPem: string,
): Promise<MintedIdentityProof> {
  const transcript = await identityTranscriptHash(pub, nonce, leafDer, caDer);
  const proof: MeshIdentityProof = {
    algorithm: IDENTITY_PROOF_ALGORITHM,
    leaf_sha256: await certificateHashBase64Url(leafDer),
    mesh_ca_sha256: await certificateHashBase64Url(caDer),
    signature: bytesToBase64Url(
      sign("sha384", identityProofMessage(transcript), {
        key: leafKeyPem,
        dsaEncoding: "der",
      }),
    ),
  };
  return {
    transcript,
    proof,
    bundleFields: {
      version: PROTOCOL_VERSION,
      identity_proof: proof,
    },
  };
}
