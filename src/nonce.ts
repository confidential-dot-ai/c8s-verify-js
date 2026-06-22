// Fresh challenge nonce generation. The nonce binds the attestation evidence to
// this session: the LB's hardware report_data is SHA-384(session_pubkey || nonce),
// so a verifier that recomputes it rejects replayed reports.

import { randomBytes } from "./crypto-env.js";

/** Default nonce length in bytes. 32 matches the c8s CDS challenge size. */
export const NONCE_BYTES = 32;

/**
 * Generate a cryptographically secure random nonce.
 */
export function generateNonce(len: number = NONCE_BYTES): Uint8Array {
  if (!Number.isInteger(len) || len <= 0) {
    throw new Error("nonce length must be a positive integer");
  }
  return randomBytes(len);
}
