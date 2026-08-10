import { test } from "node:test";
import assert from "node:assert/strict";

import { parseImageManifest } from "../src/manifest.js";
import { C8sVerifyError } from "../src/errors.js";
import { utf8ToBytes } from "../src/base64.js";

// Parser parity: the reject table mirrors c8s pkg/runtimemeasure's manifest
// tests, so the Go and JS parsers cannot drift on what counts as an image pin.

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
