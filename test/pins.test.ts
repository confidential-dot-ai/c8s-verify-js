import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { C8sVerifyError } from "../src/errors.js";
import {
  operatorSeed,
  parseInitDataHash,
  policyPinDigests,
  resolveRegisterPins,
  sandboxIdFromLeaf,
  type RegisterPinInputs,
} from "../src/pins.js";
import { parseCertificate } from "../src/x509.js";
import { decodePEM } from "../src/pem.js";
import { loadFixtures } from "./helpers.js";
import { IA5, extension, mintLeaf, tlv } from "./mint-cert.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const D1 = "sha256:" + "1".repeat(64);
const R = (c: string) => c.repeat(96);

const isInvalid = (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request";

async function vector(): Promise<{ anchor_pem: string; seed_hex: string }> {
  const path = join(ROOT, "test-vectors", "rtmr3_measured_policies_vector.json");
  return JSON.parse(await readFile(path, "utf8"));
}

test("operatorSeed matches the Go golden vector", async () => {
  const v = await vector();
  assert.equal(operatorSeed(v.anchor_pem), v.seed_hex);
});

test("policyPinDigests", () => {
  const doc = '{"version":1,"workloads":[]}';
  const want = "sha256:" + createHash("sha256").update(doc).digest("hex");
  assert.equal(policyPinDigests(undefined, false), undefined);
  assert.deepEqual(policyPinDigests([D1, doc, new TextEncoder().encode(doc)], true), [
    D1,
    want,
    want,
  ]);
  const bad: { name: string; pins: unknown; rtmr3Pinned: boolean }[] = [
    { name: "without an RTMR[3] pin", pins: [D1], rtmr3Pinned: false },
    { name: "empty", pins: [], rtmr3Pinned: true },
    { name: "not an array", pins: D1, rtmr3Pinned: true },
    { name: "uppercase hex", pins: ["sha256:" + "A".repeat(64)], rtmr3Pinned: true },
    { name: "short digest", pins: ["sha256:" + "1".repeat(63)], rtmr3Pinned: true },
    { name: "empty document", pins: [""], rtmr3Pinned: true },
    { name: "uppercase prefix", pins: [D1.toUpperCase()], rtmr3Pinned: true },
    { name: "bare hex", pins: ["1".repeat(64)], rtmr3Pinned: true },
    { name: "empty bytes", pins: [new Uint8Array()], rtmr3Pinned: true },
    { name: "not a string or bytes", pins: [42], rtmr3Pinned: true },
  ];
  for (const c of bad) {
    assert.throws(() => policyPinDigests(c.pins, c.rtmr3Pinned), isInvalid, c.name);
  }
});

test("resolveRegisterPins", async () => {
  const { anchor_pem: pem, seed_hex: seed } = await vector();
  const ok: { name: string; in: RegisterPinInputs; want: object }[] = [
    { name: "nothing", in: { imagePinned: false }, want: {} },
    {
      name: "expectedRtmr3 without an image keeps its earlier rule",
      in: { expectedRtmr3: R("A"), imagePinned: false },
      want: { rtmr3: R("a") },
    },
    {
      name: "operator key",
      in: { operatorPublicKeyPem: pem, imagePinned: true },
      want: { rtmr3: seed },
    },
    { name: "rtmrs[3]", in: { rtmrs: { 3: R("b") }, imagePinned: true }, want: { rtmr3: R("b") } },
    {
      name: "rtmrs[1] and [2] by hand",
      in: { rtmrs: { 1: R("c"), 2: R("d") }, imagePinned: false },
      want: { rtmr1: R("c"), rtmr2: R("d") },
    },
  ];
  for (const c of ok) assert.deepEqual(resolveRegisterPins(c.in), c.want, c.name);

  const bad: { name: string; in: RegisterPinInputs }[] = [
    {
      name: "two RTMR[3] spellings",
      in: { expectedRtmr3: R("a"), operatorPublicKeyPem: pem, imagePinned: true },
    },
    {
      name: "rtmrs[3] and expectedRtmr3",
      in: { expectedRtmr3: R("a"), rtmrs: { 3: R("a") }, imagePinned: true },
    },
    {
      name: "operator key without an image",
      in: { operatorPublicKeyPem: pem, imagePinned: false },
    },
    { name: "rtmrs[3] without an image", in: { rtmrs: { 3: R("a") }, imagePinned: false } },
    { name: "rtmrs[1] with an image", in: { rtmrs: { 1: R("a") }, imagePinned: true } },
    { name: "RTMR[0]", in: { rtmrs: { 0: R("a") } as never, imagePinned: false } },
    { name: "empty rtmrs", in: { rtmrs: {}, imagePinned: false } },
    { name: "short register", in: { rtmrs: { 1: "ab" }, imagePinned: false } },
    { name: "malformed expectedRtmr3", in: { expectedRtmr3: "zz", imagePinned: true } },
    {
      name: "private key PEM",
      in: {
        operatorPublicKeyPem: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        imagePinned: true,
      },
    },
    { name: "not PEM", in: { operatorPublicKeyPem: "operator", imagePinned: true } },
    {
      name: "unparseable public key",
      in: {
        operatorPublicKeyPem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        imagePinned: true,
      },
    },
    {
      name: "non-base64 public key body",
      in: {
        operatorPublicKeyPem: "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n",
        imagePinned: true,
      },
    },
  ];
  for (const c of bad) assert.throws(() => resolveRegisterPins(c.in), isInvalid, c.name);
});

test("parseInitDataHash", () => {
  assert.equal(parseInitDataHash(undefined), undefined);
  assert.deepEqual(parseInitDataHash("0A".repeat(32)), new Uint8Array(32).fill(10));
  for (const pin of ["0".repeat(63), "zz".repeat(32), 42]) {
    assert.throws(() => parseInitDataHash(pin), isInvalid, String(pin));
  }
});

// 1.3.6.1.4.1.66378.1.4
const OID_14_DER = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x84, 0x86, 0x4a, 0x01, 0x04];

async function leafWith(extnValue?: number[]) {
  const { caDer, caKeyPem } = await loadFixtures();
  const { leafPem } = mintLeaf(caDer, caKeyPem, {
    extensions: extnValue === undefined ? [] : [extension(OID_14_DER, extnValue)],
  });
  return parseCertificate(decodePEM(leafPem)[0]);
}

test("sandboxIdFromLeaf", async () => {
  assert.equal(sandboxIdFromLeaf(await leafWith()), undefined);
  assert.equal(sandboxIdFromLeaf(await leafWith(IA5("abc-123"))), "abc-123");
  for (const [name, value] of [
    ["not an IA5String", tlv(0x0c, Array.from(new TextEncoder().encode("abc")))],
    ["outside the grammar", IA5("a b")],
    ["trailing bytes", [...IA5("abc"), 0]],
  ] as const) {
    const leaf = await leafWith([...value]);
    assert.throws(
      () => sandboxIdFromLeaf(leaf),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "sandbox_denied",
      name,
    );
  }
});
