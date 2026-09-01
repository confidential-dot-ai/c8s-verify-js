import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateXWingKeyPair,
  xwingEncapsulate,
  xwingDecapsulate,
  deriveChannel,
  XWING_EK_BYTES,
  XWING_CT_BYTES,
  XWING_SS_BYTES,
} from "../src/keyagreement.js";
import { utf8ToBytes, bytesToUtf8 } from "../src/base64.js";
import { C8sVerifyError } from "../src/errors.js";

const transcript = (fill: number): Uint8Array => new Uint8Array(48).fill(fill);
const sessionId = (fill: number): Uint8Array => new Uint8Array(16).fill(fill);

async function agreedChannels(fill = 0x33) {
  const kp = await generateXWingKeyPair();
  const { ct, sharedSecret } = await xwingEncapsulate(kp.ek);
  const clientSecret = await xwingDecapsulate(kp, ct);
  const client = await deriveChannel("client", clientSecret, transcript(fill), sessionId(0x0f));
  const server = await deriveChannel("server", sharedSecret, transcript(fill), sessionId(0x0f));
  return { client, server };
}

test("X-Wing produces an identical secret on both sides", async () => {
  const kp = await generateXWingKeyPair();
  assert.equal(kp.ek.length, XWING_EK_BYTES);
  const { ct, sharedSecret } = await xwingEncapsulate(kp.ek);
  assert.equal(ct.length, XWING_CT_BYTES);
  assert.equal(sharedSecret.length, XWING_SS_BYTES);
  assert.deepEqual(await xwingDecapsulate(kp, ct), sharedSecret);
});

test("the channel round-trips a request and a seq-echoing response", async () => {
  const { client, server } = await agreedChannels();
  const rec = await client.sealRequest(utf8ToBytes("ping"));
  assert.equal(rec.seq, 1);
  assert.equal(bytesToUtf8(await server.openRequest(rec)), "ping");
  const resp = await server.sealResponse(utf8ToBytes("pong"), rec.seq);
  assert.equal(bytesToUtf8(await client.openResponse(resp, rec.seq)), "pong");
  assert.deepEqual(client.exporter, server.exporter);
  assert.equal(client.exporter.length, 32);
});

test("a tampered ciphertext decapsulates to a different secret, not an error", async () => {
  // Implicit rejection: the divergence must surface as AEAD failure, never as
  // a decapsulation oracle.
  const kp = await generateXWingKeyPair();
  const { ct, sharedSecret } = await xwingEncapsulate(kp.ek);
  const tampered = new Uint8Array(ct);
  tampered[0] ^= 0xff;
  const clientSecret = await xwingDecapsulate(kp, tampered);
  assert.notDeepEqual(clientSecret, sharedSecret);
  const client = await deriveChannel("client", clientSecret, transcript(0x33), sessionId(0x0f));
  const server = await deriveChannel("server", sharedSecret, transcript(0x33), sessionId(0x0f));
  const rec = await client.sealRequest(utf8ToBytes("bound"));
  await assert.rejects(
    () => server.openRequest(rec),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "channel_error",
  );
});

test("a mismatched transcript derives a different key schedule", async () => {
  const kp = await generateXWingKeyPair();
  const { ct, sharedSecret } = await xwingEncapsulate(kp.ek);
  const clientSecret = await xwingDecapsulate(kp, ct);
  const client = await deriveChannel("client", clientSecret, transcript(0x11), sessionId(0x0f));
  const server = await deriveChannel("server", sharedSecret, transcript(0x22), sessionId(0x0f));
  const rec = await client.sealRequest(utf8ToBytes("bound"));
  await assert.rejects(
    () => server.openRequest(rec),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "channel_error",
  );
});

test("a replayed request record is rejected", async () => {
  const { client, server } = await agreedChannels();
  const rec = await client.sealRequest(utf8ToBytes("transfer $100"));
  await server.openRequest(rec);
  await assert.rejects(
    () => server.openRequest(rec),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "channel_error",
  );
  // A fresh record from the same channel still opens.
  const rec2 = await client.sealRequest(utf8ToBytes("transfer $200"));
  assert.equal(bytesToUtf8(await server.openRequest(rec2)), "transfer $200");
});

test("a response must echo its request's sequence", async () => {
  const { client, server } = await agreedChannels();
  const recA = await client.sealRequest(utf8ToBytes("request A"));
  const recB = await client.sealRequest(utf8ToBytes("request B"));
  await server.openRequest(recA);
  await server.openRequest(recB);
  const respA = await server.sealResponse(utf8ToBytes("response A"), recA.seq);
  const respB = await server.sealResponse(utf8ToBytes("response B"), recB.seq);

  // Swapped wholesale: the echoed sequence exposes it before decryption.
  await assert.rejects(() => client.openResponse(respB, recA.seq));
  // Swapped with the seq field forged to match: the AAD kills it.
  await assert.rejects(() => client.openResponse({ seq: recA.seq, ct: respB.ct }, recA.seq));
  // The honest pairings still open.
  assert.equal(bytesToUtf8(await client.openResponse(respA, recA.seq)), "response A");
  assert.equal(bytesToUtf8(await client.openResponse(respB, recB.seq)), "response B");
});

test("a request record reflected back is not a valid response", async () => {
  const { client } = await agreedChannels();
  const rec = await client.sealRequest(utf8ToBytes("request"));
  await assert.rejects(
    () => client.openResponse(rec, rec.seq),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "channel_error",
  );
});

test("rejects an encapsulation key of the wrong size", async () => {
  await assert.rejects(
    () => xwingEncapsulate(new Uint8Array(10)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "key_binding",
  );
});

test("rejects a ciphertext of the wrong size", async () => {
  const kp = await generateXWingKeyPair();
  await assert.rejects(
    () => xwingDecapsulate(kp, new Uint8Array(10)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "key_binding",
  );
});

test("rejects a non-SHA-384 transcript before key derivation", async () => {
  await assert.rejects(
    () => deriveChannel("client", new Uint8Array(32), new Uint8Array(32), sessionId(0x0f)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("rejects a session id of the wrong size", async () => {
  await assert.rejects(
    () => deriveChannel("client", new Uint8Array(32), transcript(0x33), new Uint8Array(8)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "channel_error",
  );
});
