// The over-encryption channel: AES-256-GCM records on top of the hybrid-derived
// session key. Each record carries a fresh 12-byte IV. AAD binds requests to their
// method+path so a record cannot be replayed against a different route.

import { subtle, randomBytes } from "./crypto-env.js";
import {
  bytesToBase64Url,
  base64UrlToBytes,
  utf8ToBytes,
  bytesToUtf8,
} from "./base64.js";
import { C8sVerifyError } from "./errors.js";

const IV_BYTES = 12;

/**
 * @typedef {{ iv: string, ct: string }} WireRecord  // both base64url
 */

// The method and path are sealed inside the request envelope, so the record AAD
// is a fixed domain separator rather than per-route. Must match Go overenc.
const REQUEST_AAD = utf8ToBytes("c8s-verify/v1/tunnel-request");
const RESPONSE_AAD = utf8ToBytes("c8s-verify/v1/tunnel-response");

/** AAD for a request record. */
export function requestAAD() {
  return REQUEST_AAD;
}

/** AAD for a response record. */
export function responseAAD() {
  return RESPONSE_AAD;
}

/**
 * A symmetric over-encryption channel. Both client and LB hold one after the
 * hybrid handshake; the AES key is identical on both ends.
 */
export class Channel {
  /** @param {CryptoKey} key AES-256-GCM key */
  constructor(key) {
    /** @type {CryptoKey} */
    this.key = key;
  }

  /**
   * Encrypt a plaintext record.
   * @param {Uint8Array} plaintext
   * @param {Uint8Array} aad
   * @returns {Promise<WireRecord>}
   */
  async seal(plaintext, aad) {
    const iv = randomBytes(IV_BYTES);
    const ct = await subtle().encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      this.key,
      plaintext,
    );
    return { iv: bytesToBase64Url(iv), ct: bytesToBase64Url(new Uint8Array(ct)) };
  }

  /**
   * Decrypt a record. Throws channel_error on authentication failure.
   * @param {WireRecord} record
   * @param {Uint8Array} aad
   * @returns {Promise<Uint8Array>}
   */
  async open(record, aad) {
    let iv, ct;
    try {
      iv = base64UrlToBytes(record.iv);
      ct = base64UrlToBytes(record.ct);
    } catch (e) {
      throw new C8sVerifyError("channel_error", "malformed over-encryption record", {
        cause: e,
      });
    }
    if (iv.length !== IV_BYTES) {
      throw new C8sVerifyError("channel_error", `record IV must be ${IV_BYTES} bytes`);
    }
    try {
      const pt = await subtle().decrypt(
        { name: "AES-GCM", iv, additionalData: aad },
        this.key,
        ct,
      );
      return new Uint8Array(pt);
    } catch (e) {
      throw new C8sVerifyError(
        "channel_error",
        "over-encryption record failed authentication (AES-GCM)",
        { cause: e },
      );
    }
  }

  /** Convenience: seal a UTF-8 string. */
  async sealText(text, aad) {
    return this.seal(utf8ToBytes(text), aad);
  }

  /** Convenience: open to a UTF-8 string. */
  async openText(record, aad) {
    return bytesToUtf8(await this.open(record, aad));
  }
}
