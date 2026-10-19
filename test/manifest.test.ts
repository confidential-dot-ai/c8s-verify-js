import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseImageManifest } from "../src/manifest.js";
import { C8sVerifyError } from "../src/errors.js";
import { utf8ToBytes } from "../src/base64.js";

// Parser parity: the tables mirror attestation-go runtimemeasure's manifest
// tests, so the Go and JS parsers cannot drift on what counts as an image pin.

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

const mrtdHex = "1a".repeat(48);
const rtmr1Hex = "2b".repeat(48);
const rtmr2Hex = "3c".repeat(48);

test("parseImageManifest accepts a manifest with extra unknown fields", () => {
  // Extra unknown fields are allowed: build manifests carry other data.
  const img = parseImageManifest(`{
    "schema": 3, "artifacts": {"kernel": "deadbeef"},
    "mrtd": "${mrtdHex}",
    "rtmr1": "${rtmr1Hex}",
    "rtmr2": "${rtmr2Hex}"
  }`);
  assert.deepEqual(img, { mrtd: mrtdHex, rtmr1: rtmr1Hex, rtmr2: rtmr2Hex });
});

// A verbatim confos build manifest (schema version 3) nests the tuple under "tdx".
test("parseImageManifest reads a confos build manifest", async () => {
  const img = parseImageManifest(await readFile(join(FIX, "confos-tdx-manifest.json")));
  assert.equal(
    img.mrtd,
    "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
  );
  assert.equal(img.rtmr1.length, 96);
  assert.equal(img.rtmr2.length, 96);
});

test("parseImageManifest accepts the nested and the flat shape", () => {
  const want = { mrtd: mrtdHex, rtmr1: rtmr1Hex, rtmr2: rtmr2Hex };
  const tuple = `"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"`;
  for (const [name, content] of [
    ["flat", `{${tuple}}`],
    ["nested", `{"version":3,"tdx":{"firmware":{},${tuple}}}`],
    ["flat with null tdx", `{${tuple},"tdx":null}`],
    [
      "case-folded keys",
      `{"TDX":{"MRTD":"${mrtdHex}","Rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"}}`,
    ],
  ] as const) {
    assert.deepEqual(parseImageManifest(content), want, name);
  }
});

test("parseImageManifest accepts Uint8Array file bytes verbatim", () => {
  const img = parseImageManifest(
    utf8ToBytes(`{"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"}`),
  );
  assert.equal(img.mrtd, mrtdHex);
});

test("parseImageManifest rejects anything that is not a full tuple", () => {
  for (const [name, content, wantErr] of [
    ["not json", "not json at all", "not a JSON object"],
    ["json array", `[1,2,3]`, "not a JSON object"],
    ["missing mrtd", `{"rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"}`, `missing "mrtd"`],
    ["missing rtmr1", `{"mrtd":"${mrtdHex}","rtmr2":"${rtmr2Hex}"}`, `missing "rtmr1"`],
    ["missing rtmr2", `{"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex}"}`, `missing "rtmr2"`],
    [
      "generic artifact-hash manifest",
      `{"files":{"disk.img":"sha256:abc"}}`,
      "a generic artifact-hash manifest.json is not it",
    ],
    [
      "bad hex",
      `{"mrtd":"${"zz".repeat(48)}","rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"}`,
      "lowercase hex",
    ],
    [
      "uppercase hex",
      `{"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex.toUpperCase()}","rtmr2":"${rtmr2Hex}"}`,
      "lowercase hex",
    ],
    ["wrong length", `{"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex}","rtmr2":"aabb"}`, "want 96"],
    [
      "missing mrtd under tdx",
      `{"tdx":{"rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"}}`,
      `missing "mrtd"`,
    ],
    ["tdx not an object", `{"tdx":"${mrtdHex}"}`, `"tdx" is not a JSON object`],
    [
      "flat register beside a tdx object",
      `{"mrtd":"${mrtdHex}","tdx":{"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"}}`,
      `both at the top level and under "tdx"`,
    ],
    [
      "flat tuple beside an empty tdx object",
      `{"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}","tdx":{}}`,
      `both at the top level and under "tdx"`,
    ],
    [
      "duplicate register",
      `{"mrtd":"${mrtdHex}","mrtd":"${"ff".repeat(48)}","rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"}`,
      "duplicate",
    ],
    [
      "case-folded duplicate inside tdx",
      `{"tdx":{"mrtd":"${mrtdHex}","Mrtd":"${"ff".repeat(48)}","rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"}}`,
      "duplicate",
    ],
    [
      "case-folded duplicate tdx object",
      `{"tdx":{"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"},"TDX":{}}`,
      "duplicate",
    ],
    [
      "trailing data",
      `{"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"} {}`,
      "not a JSON object",
    ],
    [
      "wrong json type",
      `{"mrtd":7,"rtmr1":"${rtmr1Hex}","rtmr2":"${rtmr2Hex}"}`,
      "is not a string",
    ],
  ] as const) {
    assert.throws(
      () => parseImageManifest(content),
      (e: unknown) =>
        e instanceof C8sVerifyError && e.code === "invalid_request" && e.message.includes(wantErr),
      `${name}: expected invalid_request containing ${JSON.stringify(wantErr)}`,
    );
  }
});

// One malformed field must fail the whole parse: a partial pin (say MRTD
// without RTMR[2]) would silently verify only part of the image.
test("parseImageManifest is atomic — one bad field fails the whole tuple", () => {
  assert.throws(
    () => parseImageManifest(`{"mrtd":"${mrtdHex}","rtmr1":"${rtmr1Hex}","rtmr2":"bad"}`),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
});
