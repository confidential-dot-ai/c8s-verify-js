import { test } from "node:test";
import assert from "node:assert/strict";

import { readTLV, readChildren, decodeOID, decodeTime, TAG } from "../src/asn1.js";

/** Build a DER TLV with a short (<128) content length. */
function der(tag: number, content: Uint8Array): Uint8Array {
  return Uint8Array.of(tag, content.length, ...content);
}

/** Build a time node from an ASCII time string and decode it. */
function decodeTimeStr(tag: number, s: string): Date {
  const node = readTLV(der(tag, new TextEncoder().encode(s)), 0);
  return decodeTime(node);
}

test("readTLV parses tag, length and content offsets", () => {
  // SEQUENCE { } — empty, header only.
  const node = readTLV(Uint8Array.of(TAG.SEQUENCE, 0x00), 0);
  assert.equal(node.tag, TAG.SEQUENCE);
  assert.ok(node.constructed);
  assert.equal(node.headerLen, 2);
  assert.equal(node.contentStart, 2);
  assert.equal(node.end, 2);
  assert.equal(node.content.length, 0);
});

test("readTLV handles long-form (multi-byte) lengths", () => {
  const content = new Uint8Array(200).fill(0xab);
  // 0x04 OCTET STRING, 0x81 => one length byte follows, 0xc8 => 200.
  const buf = Uint8Array.of(TAG.OCTET_STRING, 0x81, 0xc8, ...content);
  const node = readTLV(buf, 0);
  assert.equal(node.headerLen, 3);
  assert.equal(node.content.length, 200);
  assert.deepEqual(node.content, content);
});

test("readTLV rejects malformed input", () => {
  assert.throws(() => readTLV(new Uint8Array(0), 0), /unexpected end of input/);
  // High-tag-number form (low 5 bits all set) is not used in certs.
  assert.throws(() => readTLV(Uint8Array.of(0x1f, 0x00), 0), /high-tag-number form/);
  // Declares 5 content bytes but only 2 are present.
  assert.throws(
    () => readTLV(Uint8Array.of(TAG.OCTET_STRING, 0x05, 0x01, 0x02), 0),
    /exceeds buffer/,
  );
  // Long-form length claiming more than 4 length bytes.
  assert.throws(
    () => readTLV(Uint8Array.of(TAG.OCTET_STRING, 0x85), 0),
    /unsupported length encoding/,
  );
});

test("readChildren splits a constructed node into its elements", () => {
  const a = der(TAG.INTEGER, Uint8Array.of(0x01));
  const b = der(TAG.INTEGER, Uint8Array.of(0x02));
  const seq = der(TAG.SEQUENCE, Uint8Array.of(...a, ...b));
  const kids = readChildren(seq, readTLV(seq, 0));
  assert.equal(kids.length, 2);
  assert.deepEqual(kids[0].content, Uint8Array.of(0x01));
  assert.deepEqual(kids[1].content, Uint8Array.of(0x02));
});

test("readChildren rejects a primitive node", () => {
  const int = der(TAG.INTEGER, Uint8Array.of(0x01));
  assert.throws(() => readChildren(int, readTLV(int, 0)), /expected constructed node/);
});

test("decodeOID decodes dotted-decimal, including multi-byte arcs", () => {
  // 1.2.840.113549 (RSA) — exercises the 40*x+y first byte and 7-bit continuation.
  assert.equal(decodeOID(Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d)), "1.2.840.113549");
  assert.throws(() => decodeOID(new Uint8Array(0)), /empty OID/);
});

test("decodeTime parses UTCTime with the RFC 5280 year pivot at 50", () => {
  assert.deepEqual(
    decodeTimeStr(TAG.UTC_TIME, "230615120000Z"),
    new Date(Date.UTC(2023, 5, 15, 12, 0, 0)),
  );
  assert.deepEqual(
    decodeTimeStr(TAG.UTC_TIME, "490615120000Z"),
    new Date(Date.UTC(2049, 5, 15, 12, 0, 0)),
  );
  assert.deepEqual(
    decodeTimeStr(TAG.UTC_TIME, "500615120000Z"),
    new Date(Date.UTC(1950, 5, 15, 12, 0, 0)),
  );
});

test("decodeTime parses GeneralizedTime with a 4-digit year", () => {
  assert.deepEqual(
    decodeTimeStr(TAG.GENERALIZED_TIME, "20230615120000Z"),
    new Date(Date.UTC(2023, 5, 15, 12, 0, 0)),
  );
});

test("decodeTime tolerates missing seconds and ignores fractional seconds", () => {
  // UTCTime without the (RFC-mandatory but sometimes-omitted) seconds field.
  assert.deepEqual(
    decodeTimeStr(TAG.UTC_TIME, "2306151200Z"),
    new Date(Date.UTC(2023, 5, 15, 12, 0, 0)),
  );
  // GeneralizedTime with a fractional-seconds part — the fraction is dropped.
  assert.deepEqual(
    decodeTimeStr(TAG.GENERALIZED_TIME, "20230615120030.500Z"),
    new Date(Date.UTC(2023, 5, 15, 12, 0, 30)),
  );
});

test("decodeTime rejects a non-time tag", () => {
  const int = readTLV(der(TAG.INTEGER, Uint8Array.of(0x01)), 0);
  assert.throws(() => decodeTime(int), /not a time tag/);
});
