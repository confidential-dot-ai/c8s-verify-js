import { test } from "node:test";
import assert from "node:assert/strict";

import { readTLV, readChildren, decodeOID, decodeTime, TAG } from "../src/asn1.js";
import { C8sVerifyError } from "../src/errors.js";

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

// `len = (len << 8) | b` coerces to int32, so a 4-byte length with the top bit
// set wraps NEGATIVE. contentEnd then lands before contentStart, sails past the
// "exceeds buffer" bounds check, and produces a node whose `end` is at or behind
// its own `start` — which used to send readChildren into a loop that never
// advanced and allocated until V8 aborted with "heap out of memory". Reachable
// from the untrusted discovery document, i.e. a hostile front door could kill
// the tab before any attestation ran.
test("readTLV rejects a 4-byte length that would overflow to negative", () => {
  for (const len of [
    [0xff, 0xff, 0xff, 0xfa], // -6: the original repro, end == start
    [0xff, 0xff, 0xff, 0xff], // -1
    [0x80, 0x00, 0x00, 0x00], // exactly the sign bit
  ]) {
    assert.throws(
      () => readTLV(Uint8Array.of(TAG.OCTET_STRING, 0x84, ...len), 0),
      /length exceeds the supported range/,
      `length ${len.map((b) => b.toString(16)).join("")} must be refused`,
    );
  }
});

// The guard above must not cost us legitimate encodings: a high bit in a
// shorter length is an ordinary value, not an overflow.
test("readTLV still accepts long-form lengths with a high bit below 4 bytes", () => {
  const content = new Uint8Array(128).fill(0x7);
  // 0x81 0x80 — one length byte, value 128. High bit set, perfectly valid.
  assert.equal(
    readTLV(Uint8Array.of(TAG.OCTET_STRING, 0x81, 0x80, ...content), 0).content.length,
    128,
  );
  // 0x83 0xFF 0xFF 0xFF would be 16MiB — valid arithmetic, just larger than the
  // buffer, so it must fail on bounds rather than on the overflow guard.
  assert.throws(
    () => readTLV(Uint8Array.of(TAG.OCTET_STRING, 0x83, 0xff, 0xff, 0xff), 0),
    /exceeds buffer/,
  );
});

// The end-to-end version of the same bug: this exact buffer used to OOM the
// process. readTLV's guard is what stops it now; readChildren's progress
// assertion is belt-and-braces behind that (and consequently unreachable while
// the guard holds, which is the point of having both).
test("readChildren terminates on a length that would not advance", () => {
  // A child whose declared length is -6 would end exactly where it began.
  const inner = [0x04, 0x84, 0xff, 0xff, 0xff, 0xfa];
  const buf = Uint8Array.of(TAG.SEQUENCE, inner.length, ...inner);
  assert.throws(
    () => readChildren(buf, readTLV(buf, 0)),
    (e: unknown) =>
      e instanceof C8sVerifyError &&
      /length exceeds the supported range|does not advance/.test(e.message),
  );
});

// DER makes the parent's length authoritative, so a child that runs past it is
// malformed. Tolerating it would let a crafted element hide bytes from one
// parser that another one sees.
test("readChildren rejects a child that overruns its parent", () => {
  // SEQUENCE declares 2 content bytes; the child inside declares 5.
  const buf = Uint8Array.of(TAG.SEQUENCE, 0x02, TAG.OCTET_STRING, 0x05, 1, 2, 3, 4, 5);
  assert.throws(() => readChildren(buf, readTLV(buf, 0)), /overruns its parent/);
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
