// The channel key schedule: HKDF-SHA256 over the X-Wing shared secret, salted
// with the verified identity transcript hash so every output — including the
// channel-binding exporter — is bound to the attested identity. Must match Go
// pkg/overenc.

import { subtle } from "./crypto-env.js";
import { utf8ToBytes } from "./base64.js";
import { newChannel, type Channel, type ChannelKeys, type ChannelRole } from "./channel.js";
// Runtime-safe: identity.js only type-imports from this module, so no cycle.
import { assertTranscriptLength } from "./identity.js";
import { C8sVerifyError } from "./errors.js";

export {
  XWING_EK_BYTES,
  XWING_CT_BYTES,
  XWING_SS_BYTES,
  generateXWingKeyPair,
  xwingKeyPairFromSeed,
  xwingDecapsulate,
  xwingEncapsulate,
} from "./xwing.js";
export type { XWingKeyPair } from "./xwing.js";

const KEY_BYTES = 32;
const IV_PREFIX_BYTES = 4;
const EXPORTER_BYTES = 32;
const SS_BYTES = 32;

const INFO_C2S_KEY = utf8ToBytes("c8s-verify/v1/c2s-key");
const INFO_S2C_KEY = utf8ToBytes("c8s-verify/v1/s2c-key");
const INFO_C2S_IV = utf8ToBytes("c8s-verify/v1/c2s-iv");
const INFO_S2C_IV = utf8ToBytes("c8s-verify/v1/s2c-iv");
const INFO_EXPORTER = utf8ToBytes("c8s-verify/v1/exporter");

async function hkdfExpand(
  hkdfKey: CryptoKey,
  salt: Uint8Array,
  info: Uint8Array,
  bytes: number,
): Promise<Uint8Array> {
  const bits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    hkdfKey,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle().importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Derive the full channel key schedule and assemble this end's Channel.
 *
 * @param role which end this is: the browser client, or the server half used
 *   by the mock LB and tests
 * @param sharedSecret 32-byte X-Wing shared secret
 * @param identityTranscript verified 48-byte identity transcript hash (salt)
 * @param sessionId 16-byte session id, committed by the transcript
 */
export async function deriveChannel(
  role: ChannelRole,
  sharedSecret: Uint8Array,
  identityTranscript: Uint8Array,
  sessionId: Uint8Array,
): Promise<Channel> {
  assertTranscriptLength(identityTranscript);
  if (sharedSecret.length !== SS_BYTES) {
    throw new C8sVerifyError(
      "key_binding",
      `shared secret must be ${SS_BYTES} bytes, got ${sharedSecret.length}`,
    );
  }
  const hkdfKey = await subtle().importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
  const keys: ChannelKeys = {
    c2sKey: await importAesKey(
      await hkdfExpand(hkdfKey, identityTranscript, INFO_C2S_KEY, KEY_BYTES),
    ),
    s2cKey: await importAesKey(
      await hkdfExpand(hkdfKey, identityTranscript, INFO_S2C_KEY, KEY_BYTES),
    ),
    c2sIv: await hkdfExpand(hkdfKey, identityTranscript, INFO_C2S_IV, IV_PREFIX_BYTES),
    s2cIv: await hkdfExpand(hkdfKey, identityTranscript, INFO_S2C_IV, IV_PREFIX_BYTES),
    exporter: await hkdfExpand(hkdfKey, identityTranscript, INFO_EXPORTER, EXPORTER_BYTES),
  };
  return newChannel(role, keys, sessionId);
}

/**
 * Derive the raw key-schedule outputs without importing them into AEAD
 * handles. For the interoperability-vector tests, which compare the bytes.
 */
export async function deriveRawKeySchedule(
  sharedSecret: Uint8Array,
  identityTranscript: Uint8Array,
): Promise<{
  c2sKey: Uint8Array;
  s2cKey: Uint8Array;
  c2sIv: Uint8Array;
  s2cIv: Uint8Array;
  exporter: Uint8Array;
}> {
  const hkdfKey = await subtle().importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
  return {
    c2sKey: await hkdfExpand(hkdfKey, identityTranscript, INFO_C2S_KEY, KEY_BYTES),
    s2cKey: await hkdfExpand(hkdfKey, identityTranscript, INFO_S2C_KEY, KEY_BYTES),
    c2sIv: await hkdfExpand(hkdfKey, identityTranscript, INFO_C2S_IV, IV_PREFIX_BYTES),
    s2cIv: await hkdfExpand(hkdfKey, identityTranscript, INFO_S2C_IV, IV_PREFIX_BYTES),
    exporter: await hkdfExpand(hkdfKey, identityTranscript, INFO_EXPORTER, EXPORTER_BYTES),
  };
}
