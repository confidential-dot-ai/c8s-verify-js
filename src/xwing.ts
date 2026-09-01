// X-Wing (draft-connolly-cfrg-xwing-kem-10): the hybrid post-quantum KEM the
// over-encryption channel keys on. ML-KEM-768 comes from mlkem-wasm, X25519
// from WebCrypto, and the SHA3-256 combiner from @noble/hashes. The combiner
// binds the X25519 ciphertext and recipient key into the shared secret, so the
// hybrid is IND-CCA secure as long as EITHER component holds.
//
// Wire layout (draft §5):
//   encapsulation key = ML-KEM-768 ek (1184) || X25519 pk (32)   = 1216 bytes
//   ciphertext        = ML-KEM-768 ct (1088) || X25519 eph pk (32) = 1120 bytes
//   shared secret     = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)

import mlkem from "mlkem-wasm";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { shake256 } from "@noble/hashes/sha3.js";
import { subtle } from "./crypto-env.js";
import { concatBytes } from "./base64.js";
import { C8sVerifyError } from "./errors.js";

const ML_KEM = { name: "ML-KEM-768" } as const;

const MLKEM768_EK_BYTES = 1184;
const MLKEM768_CT_BYTES = 1088;
const X25519_PUB_BYTES = 32;

export const XWING_EK_BYTES = MLKEM768_EK_BYTES + X25519_PUB_BYTES; // 1216
export const XWING_CT_BYTES = MLKEM768_CT_BYTES + X25519_PUB_BYTES; // 1120
export const XWING_SS_BYTES = 32;
export const XWING_SEED_BYTES = 32;

// The draft's 6-byte combiner label, "\.//^\".
const XWING_LABEL = new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);

/** An X-Wing decapsulation keypair: component private handles plus the wire ek. */
export interface XWingKeyPair {
  /** 1216-byte encapsulation key sent in the attestation request. */
  ek: Uint8Array;
  mlkemPriv: CryptoKey;
  x25519Priv: CryptoKey;
}

function u8(b: ArrayBuffer | Uint8Array): Uint8Array {
  return b instanceof Uint8Array ? b : new Uint8Array(b);
}

// PKCS#8 wrapper for a raw X25519 private scalar: WebCrypto imports X25519
// private keys only in this encoding. The prefix is the fixed DER header for
// { version 0, OID 1.3.101.110, OCTET STRING(OCTET STRING(32)) }.
const PKCS8_X25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

async function importX25519Scalar(scalar: Uint8Array): Promise<CryptoKey> {
  return subtle().importKey(
    "pkcs8",
    concatBytes(PKCS8_X25519_PREFIX, scalar),
    { name: "X25519" },
    false,
    ["deriveBits"],
  );
}

// X25519 base point: deriveBits against it turns a private handle into its
// public key, which WebCrypto cannot export directly from a PKCS#8 import.
const X25519_BASEPOINT = (() => {
  const g = new Uint8Array(32);
  g[0] = 9;
  return g;
})();

async function x25519Multiply(priv: CryptoKey, peerPub: Uint8Array): Promise<Uint8Array> {
  const pub = await subtle().importKey("raw", peerPub, { name: "X25519" }, false, []);
  return u8(await subtle().deriveBits({ name: "X25519", public: pub }, priv, 256));
}

function combiner(
  mlkemSecret: Uint8Array,
  x25519Secret: Uint8Array,
  x25519Ciphertext: Uint8Array,
  x25519Recipient: Uint8Array,
): Uint8Array {
  return sha3_256(
    concatBytes(mlkemSecret, x25519Secret, x25519Ciphertext, x25519Recipient, XWING_LABEL),
  );
}

/** Generate a fresh X-Wing keypair from system randomness. */
export async function generateXWingKeyPair(): Promise<XWingKeyPair> {
  const m = await mlkem.generateKey(ML_KEM, true, ["encapsulateBits", "decapsulateBits"]);
  const mlkemEk = u8(await mlkem.exportKey("raw-public", m.publicKey));
  const x = (await subtle().generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const xPk = u8(await subtle().exportKey("raw", x.publicKey));
  return { ek: concatBytes(mlkemEk, xPk), mlkemPriv: m.privateKey, x25519Priv: x.privateKey };
}

/**
 * Rebuild an X-Wing keypair from its 32-byte seed (draft §5.2: the seed
 * expands via SHAKE-256 to the ML-KEM d||z coins and the X25519 scalar). Used
 * by the interoperability vectors; sessions use {@link generateXWingKeyPair}.
 */
export async function xwingKeyPairFromSeed(seed: Uint8Array): Promise<XWingKeyPair> {
  if (seed.length !== XWING_SEED_BYTES) {
    throw new C8sVerifyError(
      "key_binding",
      `X-Wing seed must be ${XWING_SEED_BYTES} bytes, got ${seed.length}`,
    );
  }
  const expanded = shake256(seed, { dkLen: 96 });
  const mlkemSeed = expanded.slice(0, 64); // d || z
  const scalar = expanded.slice(64, 96);

  const mlkemPriv = await mlkem.importKey("raw-seed", mlkemSeed, ML_KEM, true, ["decapsulateBits"]);
  const mlkemPub = await mlkem.getPublicKey(mlkemPriv, ["encapsulateBits"]);
  const mlkemEk = u8(await mlkem.exportKey("raw-public", mlkemPub));

  const x25519Priv = await importX25519Scalar(scalar);
  const xPk = await x25519Multiply(x25519Priv, X25519_BASEPOINT);
  return { ek: concatBytes(mlkemEk, xPk), mlkemPriv, x25519Priv };
}

/**
 * Decapsulate the server's ciphertext to the 32-byte shared secret. An
 * ML-KEM-invalid ciphertext yields the implicit-rejection secret rather than
 * an error, so a tampered exchange surfaces as an AEAD failure on the first
 * record — never as a decapsulation oracle.
 */
export async function xwingDecapsulate(kp: XWingKeyPair, ct: Uint8Array): Promise<Uint8Array> {
  if (ct.length !== XWING_CT_BYTES) {
    throw new C8sVerifyError(
      "key_binding",
      `X-Wing ciphertext must be ${XWING_CT_BYTES} bytes, got ${ct.length}`,
    );
  }
  const ctM = ct.slice(0, MLKEM768_CT_BYTES);
  const ctX = ct.slice(MLKEM768_CT_BYTES);
  const pkX = kp.ek.slice(MLKEM768_EK_BYTES);
  const ssM = u8(await mlkem.decapsulateBits(ML_KEM, kp.mlkemPriv, ctM));
  const ssX = await x25519Multiply(kp.x25519Priv, ctX);
  return combiner(ssM, ssX, ctX, pkX);
}

/**
 * Encapsulate to an X-Wing encapsulation key. The server side of the exchange;
 * in this library it serves the mock LB and tests.
 */
export async function xwingEncapsulate(
  ek: Uint8Array,
): Promise<{ ct: Uint8Array; sharedSecret: Uint8Array }> {
  if (ek.length !== XWING_EK_BYTES) {
    throw new C8sVerifyError(
      "key_binding",
      `X-Wing encapsulation key must be ${XWING_EK_BYTES} bytes, got ${ek.length}`,
    );
  }
  const ekM = ek.slice(0, MLKEM768_EK_BYTES);
  const pkX = ek.slice(MLKEM768_EK_BYTES);

  const mlkemEk = await mlkem.importKey("raw-public", ekM, ML_KEM, true, ["encapsulateBits"]);
  const { sharedKey: ssM, ciphertext: ctM } = await mlkem.encapsulateBits(ML_KEM, mlkemEk);

  const eph = (await subtle().generateKey({ name: "X25519" }, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const ctX = u8(await subtle().exportKey("raw", eph.publicKey));
  const ssX = await x25519Multiply(eph.privateKey, pkX);

  const ct = concatBytes(u8(ctM), ctX);
  return { ct, sharedSecret: combiner(u8(ssM), ssX, ctX, pkX) };
}
