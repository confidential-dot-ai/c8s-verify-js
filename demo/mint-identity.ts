// Node-side minting of the v2 mesh identity proof — the server half of the
// protocol (see ../PROTOCOL.md), shared by the mock LB and the test fixtures so
// e2e and unit tests validate the same wire shape. Uses node:crypto signing, so
// it must never be imported from src/ (browser code only verifies).

import { sign } from "node:crypto";

import { bytesToBase64Url } from "../src/base64.js";
import {
  certificateHashBase64Url,
  IDENTITY_BINDING_V2,
  IDENTITY_BUNDLE_VERSION,
  IDENTITY_PROOF_ALGORITHM,
  identityProofMessage,
  identityTranscriptHash,
  type MeshIdentityProof,
} from "../src/identity.js";
import type { PublicHalves } from "../src/keyagreement.js";

/** The v2 response fields a bundle gains over v1 — the single owner of that shape. */
export interface IdentityBundleFields {
  version: string;
  binding: string;
  identity_proof: MeshIdentityProof;
}

/**
 * Compute the v2 transcript for a session and sign it with the mesh leaf key,
 * exactly as a real LB does. `bundleFields` is the ready-to-assign v2 response
 * stamp, so the mock LB and test fixtures cannot drift apart.
 */
export async function mintIdentityProof(
  pub: PublicHalves,
  nonce: Uint8Array,
  leafDer: Uint8Array,
  caDer: Uint8Array,
  leafKeyPem: string,
): Promise<{ transcript: Uint8Array; proof: MeshIdentityProof; bundleFields: IdentityBundleFields }> {
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
      version: IDENTITY_BUNDLE_VERSION,
      binding: IDENTITY_BINDING_V2,
      identity_proof: proof,
    },
  };
}
