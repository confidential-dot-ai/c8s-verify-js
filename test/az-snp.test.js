import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifySnp } from "../src/wasm-loader.js";
import { snpReportFromHcl } from "../src/hcl.js";
import { C8sVerifyError } from "../src/errors.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// A recorded Azure SEV-SNP (az-snp) attestation: an HCL report wrapping the raw
// SNP report, plus a TPM quote and the VCEK. Verified end-to-end through the
// JS -> WASM boundary (`verifySnp`), the same path `verifyAttestation` uses.
test("verifies a recorded az-snp attestation through the WASM verifier", async () => {
  const att = JSON.parse(await readFile(join(FIX, "az-snp-attestation.json"), "utf8"));

  // VCEK subject is SEV-Milan / HwID "Milan-B0" -> Milan generation.
  const out = await verifySnp(JSON.stringify(att.evidence), "milan");
  const result = JSON.parse(out);

  assert.equal(result.signature_valid, true, "hardware signature must verify against the VCEK chain");
});

// A second, independently-recorded Milan az-snp attestation (distinct host:
// different chip_id, launch_digest, and vmUniqueId). Guards the HCL unwrap
// against overfitting to a single recorded report.
test("verifies a second recorded az-snp (Milan) attestation", async () => {
  const att = JSON.parse(await readFile(join(FIX, "az-snp-milan-2.json"), "utf8"));

  const out = await verifySnp(JSON.stringify(att.evidence), "milan");
  const result = JSON.parse(out);

  assert.equal(result.signature_valid, true, "hardware signature must verify against the VCEK chain");
});

// The HCL header is host-controlled and untrusted: we only use it to locate the
// SNP report, so malformed envelopes must be rejected before we slice — never
// read out of bounds, never hand the WASM a bogus report.
function hclHeader({ magic = 0x414c4348, requestType = 2 } = {}) {
  const buf = new Uint8Array(32 + 1184);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, magic, true);
  dv.setUint32(12, requestType, true);
  return buf;
}

test("rejects an HCL report that is too short to contain an SNP report", () => {
  assert.throws(
    () => snpReportFromHcl(new Uint8Array(64)),
    (e) => e instanceof C8sVerifyError && e.code === "verification_failed",
  );
});

test("rejects an HCL report with a bad magic", () => {
  assert.throws(
    () => snpReportFromHcl(hclHeader({ magic: 0xdeadbeef })),
    (e) => e instanceof C8sVerifyError && e.code === "verification_failed",
  );
});

test("rejects an HCL report whose hardware type is not SNP", () => {
  assert.throws(
    () => snpReportFromHcl(hclHeader({ requestType: 1 })),
    (e) => e instanceof C8sVerifyError && e.code === "unsupported",
  );
});
