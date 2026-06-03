// Post-quantum hybrid key agreement: X25519 (classical, WebCrypto) + ML-KEM-768
// (post-quantum, mlkem-wasm), combined per the TLS X25519MLKEM768 convention and
// run through HKDF-SHA256 to an AES-256-GCM key.
//
// The LB publishes a per-session hybrid public key (attested via report_data).
// The client *encapsulates* against it; the LB *decapsulates*. Both sides derive
// the same AES key. The classical and PQ halves are concatenated so the channel
// stays secure as long as EITHER primitive holds.

import mlkem from "mlkem-wasm";
import { subtle } from "./crypto-env.js";
import { concatBytes, utf8ToBytes } from "./base64.js";
import { C8sVerifyError } from "./errors.js";

const ML_KEM = { name: "ML-KEM-768" };

// ML-KEM-768 fixed sizes (bytes).
export const MLKEM768_EK_BYTES = 1184; // encapsulation (public) key
export const MLKEM768_CT_BYTES = 1088; // ciphertext
export const X25519_PUB_BYTES = 32;

const HKDF_INFO = utf8ToBytes("c8s-verify/over-encryption/v1");

/** @param {ArrayBuffer|Uint8Array} b @returns {Uint8Array} */
function u8(b) {
  return b instanceof Uint8Array ? b : new Uint8Array(b);
}

/**
 * Derive the AES-256-GCM session key from the two shared secrets and the nonce.
 * @param {Uint8Array} mlkemSecret 32-byte ML-KEM shared secret
 * @param {Uint8Array} x25519Secret 32-byte X25519 shared secret
 * @param {Uint8Array} nonce session nonce (HKDF salt)
 * @returns {Promise<CryptoKey>} AES-256-GCM key (non-extractable)
 */
export async function deriveSessionKey(mlkemSecret, x25519Secret, nonce) {
  const ikm = concatBytes(mlkemSecret, x25519Secret);
  const hkdfKey = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: nonce, info: HKDF_INFO },
    hkdfKey,
    256,
  );
  return subtle().importKey("raw", bits, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Client side: encapsulate against the LB's attested hybrid public key and derive
 * the session key.
 *
 * @param {{ x25519: Uint8Array, mlkem768: Uint8Array }} peerPub raw public halves
 * @param {Uint8Array} nonce session nonce
 * @returns {Promise<{
 *   key: CryptoKey,
 *   handshake: { clientX25519: Uint8Array, mlkemCiphertext: Uint8Array }
 * }>}
 */
export async function clientKeyAgreement(peerPub, nonce) {
  if (peerPub.mlkem768.length !== MLKEM768_EK_BYTES) {
    throw new C8sVerifyError(
      "key_binding",
      `ML-KEM encapsulation key must be ${MLKEM768_EK_BYTES} bytes, got ${peerPub.mlkem768.length}`,
    );
  }
  if (peerPub.x25519.length !== X25519_PUB_BYTES) {
    throw new C8sVerifyError(
      "key_binding",
      `X25519 public key must be ${X25519_PUB_BYTES} bytes, got ${peerPub.x25519.length}`,
    );
  }

  // PQ half: import the LB's ML-KEM encapsulation key and encapsulate.
  const ek = await mlkem.importKey("raw-public", peerPub.mlkem768, ML_KEM, true, [
    "encapsulateBits",
  ]);
  const { sharedKey: mlkemSecret, ciphertext: mlkemCt } = await mlkem.encapsulateBits(
    ML_KEM,
    ek,
  );

  // Classical half: ephemeral X25519, ECDH against the LB's X25519 key.
  const clientPair = await subtle().generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const clientX25519 = u8(await subtle().exportKey("raw", clientPair.publicKey));
  const peerX25519 = await subtle().importKey(
    "raw",
    peerPub.x25519,
    { name: "X25519" },
    false,
    [],
  );
  const x25519Secret = u8(
    await subtle().deriveBits({ name: "X25519", public: peerX25519 }, clientPair.privateKey, 256),
  );

  const key = await deriveSessionKey(u8(mlkemSecret), x25519Secret, nonce);
  return { key, handshake: { clientX25519, mlkemCiphertext: u8(mlkemCt) } };
}

/**
 * LB / server side: decapsulate the client's ciphertext and ECDH against the
 * client's X25519 public key to derive the same session key. Used by the mock LB
 * and by tests.
 *
 * @param {{ x25519Priv: CryptoKey, mlkemPriv: any }} serverKeys
 * @param {{ clientX25519: Uint8Array, mlkemCiphertext: Uint8Array }} handshake
 * @param {Uint8Array} nonce
 * @returns {Promise<CryptoKey>}
 */
export async function serverKeyAgreement(serverKeys, handshake, nonce) {
  const mlkemSecret = u8(
    await mlkem.decapsulateBits(ML_KEM, serverKeys.mlkemPriv, handshake.mlkemCiphertext),
  );
  const clientPub = await subtle().importKey(
    "raw",
    handshake.clientX25519,
    { name: "X25519" },
    false,
    [],
  );
  const x25519Secret = u8(
    await subtle().deriveBits({ name: "X25519", public: clientPub }, serverKeys.x25519Priv, 256),
  );
  return deriveSessionKey(mlkemSecret, x25519Secret, nonce);
}

/**
 * Generate a fresh LB-side hybrid keypair and return both the private handles and
 * the raw public halves to publish. Used by the mock LB.
 *
 * @returns {Promise<{
 *   priv: { x25519Priv: CryptoKey, mlkemPriv: any },
 *   pub: { x25519: Uint8Array, mlkem768: Uint8Array }
 * }>}
 */
export async function generateServerHybridKey() {
  const x = await subtle().generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const x25519 = u8(await subtle().exportKey("raw", x.publicKey));

  const m = await mlkem.generateKey(ML_KEM, true, ["encapsulateBits", "decapsulateBits"]);
  const mlkem768 = u8(await mlkem.exportKey("raw-public", m.publicKey));

  return {
    priv: { x25519Priv: x.privateKey, mlkemPriv: m.privateKey },
    pub: { x25519, mlkem768 },
  };
}
