import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";

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

// RFC 4648 §10 test vectors — the canonical padding cases. A mistake in the
// tail/padding logic is exactly the kind of silent corruption that would break
// the wire format, so pin the exact strings.
const RFC4648: [string, string][] = [
  ["", ""],
  ["f", "Zg=="],
  ["fo", "Zm8="],
  ["foo", "Zm9v"],
  ["foob", "Zm9vYg=="],
  ["fooba", "Zm9vYmE="],
  ["foobar", "Zm9vYmFy"],
];

test("base64 std matches RFC 4648 vectors (with padding)", () => {
  for (const [plain, b64] of RFC4648) {
    assert.equal(bytesToBase64(utf8ToBytes(plain)), b64, `encode ${JSON.stringify(plain)}`);
    assert.equal(bytesToUtf8(base64ToBytes(b64)), plain, `decode ${b64}`);
  }
});

test("base64url matches RFC 4648 vectors (no padding)", () => {
  for (const [plain, b64] of RFC4648) {
    const url = b64.replace(/=+$/, "");
    assert.equal(bytesToBase64Url(utf8ToBytes(plain)), url, `encode ${JSON.stringify(plain)}`);
    assert.equal(bytesToUtf8(base64UrlToBytes(url)), plain, `decode ${url}`);
  }
});

test("empty inputs round-trip for every codec", () => {
  const empty = new Uint8Array(0);
  assert.equal(bytesToBase64(empty), "");
  assert.equal(bytesToBase64Url(empty), "");
  assert.deepEqual(base64ToBytes(""), empty);
  assert.deepEqual(base64UrlToBytes(""), empty);
  assert.equal(bytesToHex(empty), "");
  assert.deepEqual(hexToBytes(""), empty);
});

test("base64 decode tolerates padding, spaces and newlines", () => {
  assert.deepEqual(base64ToBytes("Zm9v YmFy"), utf8ToBytes("foobar"));
  assert.deepEqual(base64ToBytes("Zm9v\nYmFy\n"), utf8ToBytes("foobar"));
  assert.deepEqual(base64ToBytes("Zm8="), utf8ToBytes("fo"));
  // base64url decode also accepts padding even though the encoder omits it.
  assert.deepEqual(base64UrlToBytes("Zm8="), utf8ToBytes("fo"));
});

test("each alphabet rejects the other's distinctive characters", () => {
  assert.throws(() => base64UrlToBytes("ab+/"), /invalid character/); // std-only + and /
  assert.throws(() => base64ToBytes("ab-_"), /invalid character/); // url-only - and _
});

test("hex accepts a 0x prefix and rejects malformed input", () => {
  assert.deepEqual(hexToBytes("0xdeadbeef"), hexToBytes("deadbeef"));
  assert.throws(() => hexToBytes("abc"), /odd length/);
  assert.throws(() => hexToBytes("zz"), /invalid characters/);
});

test("constantTimeEqual treats two empty arrays as equal", () => {
  assert.ok(constantTimeEqual(new Uint8Array(0), new Uint8Array(0)));
});

test("concatBytes with no arguments yields an empty array", () => {
  assert.deepEqual(concatBytes(), new Uint8Array(0));
});
