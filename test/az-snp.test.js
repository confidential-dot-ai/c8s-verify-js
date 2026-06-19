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

// The az-snp vTPM freshness chain (src/tpmquote.js): the per-session binding
// rides in the AK-signed TPM quote, not the SNP report_data (which binds the AK).
// Fixture is a real bundle captured from a live c8s LB.
test("az-snp tpm_quote freshness chain verifies a live bundle (and rejects tampering)", async () => {
  const { verifyVtpmFreshness } = await import("../src/tpmquote.js");
  const { expectedReportData } = await import("../src/verify.js");
  const { verifySnp } = await import("../src/wasm-loader.js");
  const { toWasmEvidence } = await import("../src/hcl.js");
  const { base64UrlToBytes, hexToBytes } = await import("../src/base64.js");

  const bundle = JSON.parse(await readFile(join(FIX, "az-snp-bundle.json"), "utf8"));
  const nonce = base64UrlToBytes(bundle.nonce);
  const x = base64UrlToBytes(bundle.session_pubkey.x25519);
  const m = base64UrlToBytes(bundle.session_pubkey.mlkem768);
  const expected = await expectedReportData(x, m, nonce); // SHA-384(x ‖ m ‖ nonce)

  // report_data the hardware actually signed (binds the AK), via the WASM claims.
  const wasm = JSON.parse(
    await verifySnp(JSON.stringify(toWasmEvidence(bundle.evidence)), bundle.generation, expected),
  );
  const reportData = hexToBytes(String(wasm.claims.report_data));

  // Positive: the whole chain (var_data binding + AK sig + quote extraData == expected).
  await verifyVtpmFreshness(bundle.evidence, reportData, expected);

  // Negative: a different expected binding must fail closed.
  await assert.rejects(
    () => verifyVtpmFreshness(bundle.evidence, reportData, new Uint8Array(expected.length)),
    (e) => e instanceof C8sVerifyError && e.code === "report_data_mismatch",
  );

  // Negative: tampering the AK-signed quote message must fail the signature.
  const bad = JSON.parse(JSON.stringify(bundle.evidence));
  const msg = bad.tpm_quote.message;
  const i = msg.length - 40;
  bad.tpm_quote.message = msg.slice(0, i) + (msg[i] === "a" ? "b" : "a") + msg.slice(i + 1);
  await assert.rejects(
    () => verifyVtpmFreshness(bad, reportData, expected),
    (e) => e instanceof C8sVerifyError && e.code === "verification_failed",
  );
});
