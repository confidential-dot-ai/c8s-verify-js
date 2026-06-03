import { test } from "node:test";
import assert from "node:assert/strict";

import {
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  bytesToHex,
  hexToBytes,
  concatBytes,
  constantTimeEqual,
  utf8ToBytes,
  bytesToUtf8,
} from "../src/base64.js";

test("base64 std round-trips arbitrary bytes", () => {
  for (let len = 0; len < 40; len++) {
    const b = new Uint8Array(len);
    for (let i = 0; i < len; i++) b[i] = (i * 37 + 11) & 0xff;
    assert.deepEqual(base64ToBytes(bytesToBase64(b)), b);
  }
});

test("base64url has no padding and round-trips", () => {
  const b = new Uint8Array([251, 255, 0, 1, 2, 250]);
  const s = bytesToBase64Url(b);
  assert.ok(!s.includes("="));
  assert.ok(!s.includes("+") && !s.includes("/"));
  assert.deepEqual(base64UrlToBytes(s), b);
});

test("base64 matches Node Buffer reference", () => {
  const b = utf8ToBytes("the quick brown fox 🦊");
  assert.equal(bytesToBase64(b), Buffer.from(b).toString("base64"));
  assert.deepEqual(base64ToBytes(Buffer.from(b).toString("base64")), b);
});

test("hex round-trips", () => {
  const b = new Uint8Array([0, 15, 16, 255, 128]);
  assert.equal(bytesToHex(b), "000f10ff80");
  assert.deepEqual(hexToBytes("000f10ff80"), b);
});

test("utf8 round-trips", () => {
  const s = "héllo wörld ✓";
  assert.equal(bytesToUtf8(utf8ToBytes(s)), s);
});

test("concatBytes joins in order", () => {
  assert.deepEqual(
    concatBytes(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3])),
    new Uint8Array([1, 2, 3]),
  );
});

test("constantTimeEqual is correct", () => {
  assert.ok(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])));
  assert.ok(!constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])));
  assert.ok(!constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])));
});

test("base64 rejects invalid characters", () => {
  assert.throws(() => base64ToBytes("!!!!"));
});
