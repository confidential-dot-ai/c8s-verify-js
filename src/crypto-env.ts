// Resolves the WebCrypto SubtleCrypto implementation in both the browser and
// Node.js (>=20 exposes globalThis.crypto). Centralised so the rest of the
// library never reaches for an environment-specific global directly.

import { C8sVerifyError } from "./errors.js";

export function getCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new C8sVerifyError(
      "unsupported",
      "WebCrypto (globalThis.crypto.subtle) is not available in this environment",
    );
  }
  return c;
}

export function subtle(): SubtleCrypto {
  return getCrypto().subtle;
}

/**
 * Fill a Uint8Array with cryptographically secure random bytes.
 */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  getCrypto().getRandomValues(out);
  return out;
}
