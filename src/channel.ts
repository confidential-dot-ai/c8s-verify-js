// The over-encryption channel: AES-256-GCM records on top of the hybrid-derived
// session key. Each record carries a fresh 12-byte IV. AAD binds requests to their
// method+path so a record cannot be replayed against a different route.

import { subtle, randomBytes } from "./crypto-env.js";
import { utf8ToBytes, bytesToUtf8 } from "./base64.js";
import { C8sVerifyError } from "./errors.js";

const IV_BYTES = 12;

/**
 * Raw AES-GCM record; the tunnel transport carries iv/ct as CBOR byte strings.
 */
export interface WireRecord {
  iv: Uint8Array;
  ct: Uint8Array;
}

// The method and path are sealed inside the request envelope, so the record AAD
// is a fixed domain separator rather than per-route. Must match Go overenc.
const REQUEST_AAD = utf8ToBytes("c8s-verify/v1/tunnel-request");
const RESPONSE_AAD = utf8ToBytes("c8s-verify/v1/tunnel-response");

/** AAD for a request record. */
export function requestAAD(): Uint8Array {
  return REQUEST_AAD;
}

/** AAD for a response record. */
export function responseAAD(): Uint8Array {
  return RESPONSE_AAD;
}

/**
 * A symmetric over-encryption channel. Both client and LB hold one after the
 * hybrid handshake; the AES key is identical on both ends.
 */
export class Channel {
  readonly key: CryptoKey;

  /** @param key AES-256-GCM key */
  constructor(key: CryptoKey) {
    this.key = key;
  }

  /**
   * Encrypt a plaintext record.
   */
  async seal(plaintext: Uint8Array, aad: Uint8Array): Promise<WireRecord> {
    const iv = randomBytes(IV_BYTES);
    const ct = await subtle().encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      this.key,
      plaintext,
    );
    return { iv, ct: new Uint8Array(ct) };
  }

  /**
   * Decrypt a record. Throws channel_error on authentication failure.
   */
  async open(record: WireRecord, aad: Uint8Array): Promise<Uint8Array> {
    const iv = record?.iv;
    const ct = record?.ct;
    if (!(iv instanceof Uint8Array) || !(ct instanceof Uint8Array)) {
      throw new C8sVerifyError("channel_error", "malformed over-encryption record");
    }
    if (iv.length !== IV_BYTES) {
      throw new C8sVerifyError("channel_error", `record IV must be ${IV_BYTES} bytes`);
    }
    try {
      const pt = await subtle().decrypt({ name: "AES-GCM", iv, additionalData: aad }, this.key, ct);
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
  async sealText(text: string, aad: Uint8Array): Promise<WireRecord> {
    return this.seal(utf8ToBytes(text), aad);
  }

  /** Convenience: open to a UTF-8 string. */
  async openText(record: WireRecord, aad: Uint8Array): Promise<string> {
    return bytesToUtf8(await this.open(record, aad));
  }
}
