import { test } from "node:test";
import assert from "node:assert/strict";

import { cborEncode, cborDecode } from "../src/cbor.js";
import { bytesToHex, hexToBytes } from "../src/base64.js";

// RFC 8949 Appendix A vectors for the subset we implement.
const VECTORS = [
  [0, "00"],
  [1, "01"],
  [10, "0a"],
  [23, "17"],
  [24, "1818"],
  [100, "1864"],
  [1000, "1903e8"],
  [1000000, "1a000f4240"],
  [-1, "20"],
  [-100, "3863"],
  [-1000, "3903e7"],
  [false, "f4"],
  [true, "f5"],
  [null, "f6"],
  ["", "60"],
  ["a", "6161"],
  ["IETF", "6449455446"],
  [[], "80"],
  [[1, 2, 3], "83010203"],
];

test("encodes RFC 8949 vectors", () => {
  for (const [value, hex] of VECTORS) {
    assert.equal(bytesToHex(cborEncode(value)), hex, `encode ${JSON.stringify(value)}`);
  }
});

test("decodes RFC 8949 vectors", () => {
  for (const [value, hex] of VECTORS) {
    assert.deepEqual(cborDecode(hexToBytes(hex)), value, `decode ${hex}`);
  }
});

test("byte strings round-trip as Uint8Array", () => {
  const bytes = hexToBytes("0102030405");
  const enc = cborEncode(bytes);
  assert.equal(bytesToHex(enc), "450102030405"); // major 2, len 5
  const dec = cborDecode(enc);
  assert.ok(dec instanceof Uint8Array);
  assert.deepEqual(dec, bytes);
});

test("tunnel envelope round-trips with a raw byte body", () => {
  const body = new Uint8Array([0x00, 0xff, 0x10, 0x80]); // not valid UTF-8
  const env = {
    method: "POST",
    path: "/v1/chat",
    headers: { "content-type": "application/json" },
    body,
  };
  const dec = cborDecode(cborEncode(env));
  assert.equal(dec.method, "POST");
  assert.equal(dec.path, "/v1/chat");
  assert.deepEqual(dec.headers, { "content-type": "application/json" });
  assert.deepEqual(dec.body, body);
});

test("record map round-trips", () => {
  const rec = { iv: hexToBytes("0102030405060708090a0b0c"), ct: hexToBytes("deadbeef") };
  const dec = cborDecode(cborEncode(rec));
  assert.deepEqual(dec.iv, rec.iv);
  assert.deepEqual(dec.ct, rec.ct);
});

test("large byte string crosses the 2-byte length boundary", () => {
  const big = new Uint8Array(70000).fill(7);
  const dec = cborDecode(cborEncode(big));
  assert.deepEqual(dec, big);
});

test("undefined object fields are dropped (omitempty parity)", () => {
  const dec = cborDecode(cborEncode({ a: 1, b: undefined, c: "x" }));
  assert.deepEqual(dec, { a: 1, c: "x" });
});

test("truncated input throws", () => {
  assert.throws(() => cborDecode(hexToBytes("1a000f42"))); // 4-byte int, only 3 bytes
});
