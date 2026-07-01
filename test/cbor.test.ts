import { test } from "node:test";
import assert from "node:assert/strict";

import { cborEncode, cborDecode } from "../src/cbor.js";
import { bytesToHex, hexToBytes } from "../src/base64.js";

// RFC 8949 Appendix A vectors for the subset we implement.
const VECTORS: [unknown, string][] = [
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
  const dec = cborDecode(cborEncode(env)) as Record<string, unknown>;
  assert.equal(dec.method, "POST");
  assert.equal(dec.path, "/v1/chat");
  assert.deepEqual(dec.headers, { "content-type": "application/json" });
  assert.deepEqual(dec.body, body);
});

test("record map round-trips", () => {
  const rec = { iv: hexToBytes("0102030405060708090a0b0c"), ct: hexToBytes("deadbeef") };
  const dec = cborDecode(cborEncode(rec)) as Record<string, unknown>;
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

// Integer encodings at each width boundary (RFC 8949 §3 head sizes).
const INT_VECTORS: [number, string][] = [
  [23, "17"], // last 1-byte
  [24, "1818"], // first 2-byte
  [255, "18ff"],
  [256, "190100"], // first 3-byte
  [65535, "19ffff"],
  [65536, "1a00010000"], // first 5-byte
  [4294967295, "1affffffff"],
  [4294967296, "1b0000000100000000"], // first 9-byte (64-bit length)
  [-24, "37"],
  [-25, "3818"],
  [-256, "38ff"],
  [-257, "390100"],
];

test("integers round-trip at every head-width boundary", () => {
  for (const [value, hex] of INT_VECTORS) {
    assert.equal(bytesToHex(cborEncode(value)), hex, `encode ${value}`);
    assert.equal(cborDecode(hexToBytes(hex)), value, `decode ${hex}`);
  }
});

test("string-keyed maps encode in insertion order", () => {
  // The Go side is deterministic; our encoder must preserve given key order.
  assert.equal(bytesToHex(cborEncode({ a: 1, b: 2 })), "a2616101616202");
});

test("nested arrays and maps round-trip", () => {
  const value = { a: [1, { b: 2 }, [true, null]], z: "end" };
  assert.deepEqual(cborDecode(cborEncode(value)), value);
});

test("decodes float32 and float64 (major 7) even though the encoder emits only integers", () => {
  assert.equal(cborDecode(hexToBytes("fa3fc00000")), 1.5); // float32 1.5
  assert.equal(cborDecode(hexToBytes("fb3ff8000000000000")), 1.5); // float64 1.5
});

test("encoding a non-integer number throws", () => {
  assert.throws(() => cborEncode(1.5), /only integer numbers/);
});

test("encoding an unsupported value type throws", () => {
  assert.throws(() => cborEncode(() => 0), /unsupported value type/);
  assert.throws(() => cborEncode(10n), /unsupported value type/);
});

test("decoding a non-string map key throws", () => {
  // map(1){ 1: 0 } — integer key, which the codec refuses.
  assert.throws(() => cborDecode(hexToBytes("a10100")), /only string map keys/);
});

test("decoding an unsupported major type (tag) throws", () => {
  assert.throws(() => cborDecode(hexToBytes("c0")), /unsupported major type/); // major 6, tag
});

test("decoding indefinite-length items throws", () => {
  assert.throws(() => cborDecode(hexToBytes("5f")), /indefinite lengths not supported/); // bstr, ai 31
});

test("decoding an unassigned simple value throws", () => {
  assert.throws(() => cborDecode(hexToBytes("f8")), /unsupported simple value/); // ai 24
});
