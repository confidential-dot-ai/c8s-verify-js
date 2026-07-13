import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateServerHybridKey,
  clientKeyAgreement,
  serverKeyAgreement,
  MLKEM768_EK_BYTES,
  MLKEM768_CT_BYTES,
  X25519_PUB_BYTES,
} from "../src/keyagreement.js";
import { Channel, requestAAD, responseAAD } from "../src/channel.js";
import { utf8ToBytes, bytesToUtf8 } from "../src/base64.js";
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
