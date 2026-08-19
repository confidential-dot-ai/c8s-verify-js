import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateServerHybridKey,
  clientKeyAgreement,
  serverKeyAgreement,
  deriveChannelKey,
  MLKEM768_EK_BYTES,
  MLKEM768_CT_BYTES,
  X25519_PUB_BYTES,
} from "../src/keyagreement.js";
import { Channel, requestAAD, responseAAD } from "../src/channel.js";
import { utf8ToBytes, bytesToUtf8, hexToBytes } from "../src/base64.js";
import { subtle } from "../src/crypto-env.js";
import { C8sVerifyError } from "../src/errors.js";

test("hybrid KEM produces an identical key on both sides", async () => {
  const transcript = new Uint8Array(48).fill(0x33);
  const { priv, pub } = await generateServerHybridKey();
  assert.equal(pub.mlkem768.length, MLKEM768_EK_BYTES);
  assert.equal(pub.x25519.length, X25519_PUB_BYTES);

  const { key: clientKey, handshake } = await clientKeyAgreement(pub, transcript);
  assert.equal(handshake.mlkemCiphertext.length, MLKEM768_CT_BYTES);
  assert.equal(handshake.clientX25519.length, X25519_PUB_BYTES);

  const serverKey = await serverKeyAgreement(priv, handshake, transcript);

  // Prove equality by encrypting on one side and decrypting on the other.
  const c = new Channel(clientKey);
  const s = new Channel(serverKey);
  const aad = requestAAD();
  const rec = await c.seal(utf8ToBytes("ping"), aad);
  assert.equal(bytesToUtf8(await s.open(rec, aad)), "ping");
});

// The cross-repo golden vector: inputs and output MUST stay byte-identical to
// TestChannelKeyGoldenVector in c8s pkg/overenc/overenc_test.go.
const GOLDEN_MLKEM_SS = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const GOLDEN_X25519_SS = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const GOLDEN_TRANSCRIPT =
  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f";
const GOLDEN_KEY = "f631405a5e117f1ff53e36c527782a3a1b97186007f277bd494db5d825dc08ab";

test("the key schedule reproduces the Go golden vector", async () => {
  const probe = "vector";
  const derived = await deriveChannelKey(
    hexToBytes(GOLDEN_MLKEM_SS),
    hexToBytes(GOLDEN_X25519_SS),
    hexToBytes(GOLDEN_TRANSCRIPT),
  );
  const golden = await subtle().importKey(
    "raw",
    hexToBytes(GOLDEN_KEY),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  // The derived key is non-extractable, so seal with it and open with the vector;
  // a rejection becomes null so the assertion message survives the drift.
  const aad = requestAAD();
  const rec = await new Channel(derived).seal(utf8ToBytes(probe), aad);
  const opened = await new Channel(golden).open(rec, aad).then(bytesToUtf8, () => null);
  assert.equal(
    opened,
    probe,
    `derived key != ${GOLDEN_KEY}: the key schedule drifted from c8s pkg/overenc ` +
      `TestChannelKeyGoldenVector (HKDF-SHA256, ikm = mlkem||x25519, salt = transcript, ` +
      `info = "c8s-verify/v1/over-encryption", L=32)`,
  );
});

test("the key schedule rejects an empty transcript", async () => {
  await assert.rejects(
    () => deriveChannelKey(new Uint8Array(32), new Uint8Array(32), new Uint8Array(0)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("the key schedule rejects a nonce-shaped transcript", async () => {
  await assert.rejects(
    () => deriveChannelKey(new Uint8Array(32), new Uint8Array(32), new Uint8Array(32)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("the key schedule rejects a truncated shared secret", async () => {
  await assert.rejects(
    () => deriveChannelKey(new Uint8Array(1), new Uint8Array(32), new Uint8Array(48)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "key_binding",
  );
});

test("identity-bound KEM uses the transcript as HKDF context", async () => {
  const { priv, pub } = await generateServerHybridKey();
  const transcript = new Uint8Array(48).fill(0x33);
  const client = await clientKeyAgreement(pub, transcript);
  const serverKey = await serverKeyAgreement(priv, client.handshake, transcript);
  const c = new Channel(client.key);
  const s = new Channel(serverKey);
  const record = await c.seal(new TextEncoder().encode("bound"), requestAAD());
  assert.equal(new TextDecoder().decode(await s.open(record, requestAAD())), "bound");
});

test("identity-bound KEM rejects a mismatched transcript", async () => {
  const { priv, pub } = await generateServerHybridKey();
  const client = await clientKeyAgreement(pub, new Uint8Array(48).fill(0x11));
  const serverKey = await serverKeyAgreement(priv, client.handshake, new Uint8Array(48).fill(0x22));
  const record = await new Channel(client.key).seal(
    new TextEncoder().encode("bound"),
    requestAAD(),
  );
  await assert.rejects(() => new Channel(serverKey).open(record, requestAAD()));
});

test("a different identity transcript derives a different key", async () => {
  const { priv, pub } = await generateServerHybridKey();
  const { key: clientKey, handshake } = await clientKeyAgreement(
    pub,
    new Uint8Array(48).fill(0x44),
  );
  const serverKey = await serverKeyAgreement(priv, handshake, new Uint8Array(48).fill(0x55));

  const c = new Channel(clientKey);
  const s = new Channel(serverKey);
  const aad = responseAAD();
  const rec = await c.seal(utf8ToBytes("secret"), aad);
  await assert.rejects(
    () => s.open(rec, aad),
    (e: unknown) => e instanceof C8sVerifyError,
  );
});

test("AES-GCM open rejects a tampered AAD", async () => {
  const transcript = new Uint8Array(48).fill(0x66);
  const { priv, pub } = await generateServerHybridKey();
  const { key, handshake } = await clientKeyAgreement(pub, transcript);
  await serverKeyAgreement(priv, handshake, transcript);
  const c = new Channel(key);
  const rec = await c.seal(utf8ToBytes("payload"), requestAAD());
  await assert.rejects(
    () => c.open(rec, responseAAD()),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "channel_error",
  );
});

test("rejects an ML-KEM key of the wrong size", async () => {
  await assert.rejects(
    () =>
      clientKeyAgreement(
        { x25519: new Uint8Array(32), mlkem768: new Uint8Array(10) },
        new Uint8Array(48),
      ),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "key_binding",
  );
});

test("rejects a non-SHA-384 transcript before key agreement", async () => {
  const { pub } = await generateServerHybridKey();
  await assert.rejects(
    () => clientKeyAgreement(pub, new Uint8Array(32)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});
