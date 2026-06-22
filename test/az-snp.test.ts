import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifySnp, verifyAzSnp } from "../src/wasm-loader.js";
import { verifyEvidence, expectedReportData } from "../src/verify.js";
import { snpReportFromHcl } from "../src/hcl.js";
import { base64UrlToBytes } from "../src/base64.js";
import { C8sVerifyError } from "../src/errors.js";
import type { Evidence, AzSnpEvidence } from "../src/hcl.js";

// Compiled to dist/test; fixtures live in the source tree two levels up.
const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "test", "fixtures");
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

// A recorded Azure SEV-SNP (az-snp) attestation: an HCL report wrapping the raw
// SNP report, plus a TPM quote and the VCEK. Verified end-to-end through the
// JS -> WASM boundary (`verifySnp`), the same path `verifyAttestation` uses.
test("verifies a recorded az-snp attestation through the WASM verifier", async () => {
  const att = JSON.parse(await readFile(join(FIX, "az-snp-attestation.json"), "utf8"));

  // VCEK subject is SEV-Milan / HwID "Milan-B0" -> Milan generation.
  const out = await verifySnp(att.evidence, "milan");
  const result = JSON.parse(out);

  assert.equal(
    result.signature_valid,
    true,
    "hardware signature must verify against the VCEK chain",
  );
});

// A second, independently-recorded Milan az-snp attestation (distinct host:
// different chip_id, launch_digest, and vmUniqueId). Guards the HCL unwrap
// against overfitting to a single recorded report.
test("verifies a second recorded az-snp (Milan) attestation", async () => {
  const att = JSON.parse(await readFile(join(FIX, "az-snp-milan-2.json"), "utf8"));

  const out = await verifySnp(att.evidence, "milan");
  const result = JSON.parse(out);

  assert.equal(
    result.signature_valid,
    true,
    "hardware signature must verify against the VCEK chain",
  );
});

// The HCL header is host-controlled and untrusted: we only use it to locate the
// SNP report, so malformed envelopes must be rejected before we slice — never
// read out of bounds, never hand the WASM a bogus report.
function hclHeader({ magic = 0x414c4348, requestType = 2 } = {}): Uint8Array {
  const buf = new Uint8Array(32 + 1184);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, magic, true);
  dv.setUint32(12, requestType, true);
  return buf;
}

test("rejects an HCL report that is too short to contain an SNP report", () => {
  assert.throws(
    () => snpReportFromHcl(new Uint8Array(64)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "verification_failed",
  );
});

test("rejects an HCL report with a bad magic", () => {
  assert.throws(
    () => snpReportFromHcl(hclHeader({ magic: 0xdeadbeef })),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "verification_failed",
  );
});

test("rejects an HCL report whose hardware type is not SNP", () => {
  assert.throws(
    () => snpReportFromHcl(hclHeader({ requestType: 1 })),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "unsupported",
  );
});

// --- First-class az-snp: full verification including the vTPM quote ---
//
// `verify_az_snp` (exposed as verifyAzSnp / platform:"az-snp") verifies the
// HCL-wrapped SNP report AND the vTPM quote — the TPM signature against the AK
// in the HCL runtime data, the AK→TEE binding, and the freshness anchor in the
// quote's extraData. This is what graduates az-snp from "reserved" (degraded
// hardware-only via verify_snp) to "supported" in PROTOCOL.md.
//
// az-snp-coco-bound.json is a CoCo az-snp fixture whose vTPM quote binds the
// ASCII nonce "challenge"; its launch measurement is fixed and known. (The
// az-snp-attestation.json fixture above verifies too, but its quote carries an
// empty nonce, so it can't exercise the positive freshness-match path.)
const COCO_MEASUREMENT =
  "9ac48fcac8a2d88aeeff8d427ad4f2be0e3917c748a18bdf52cc317e7fe20308b459d5ef1a12e0c22944eb386d17c315";

async function cocoEvidence(): Promise<Evidence> {
  return JSON.parse(await readFile(join(FIX, "az-snp-coco-bound.json"), "utf8"))
    .evidence as Evidence;
}

test("verify_az_snp verifies the vTPM quote, not just the hardware report", async () => {
  const out = JSON.parse(await verifyAzSnp(JSON.stringify(await cocoEvidence())));
  assert.equal(out.platform, "az-snp");
  assert.equal(out.signature_valid, true);
  assert.equal(out.report_data_match, null, "no expected anchor → match is null, not enforced");
  // collateral_verified is false: the WASM path has no async cert provider for CRL.
  assert.equal(out.collateral_verified, false);
});

test("verify_az_snp confirms freshness when the quote extraData matches the anchor", async () => {
  const out = JSON.parse(
    await verifyAzSnp(JSON.stringify(await cocoEvidence()), utf8("challenge")),
  );
  assert.equal(out.report_data_match, true, "quote extraData binds the expected nonce");
});

test("verify_az_snp fails closed (throws) on a freshness mismatch", async () => {
  // Unlike bare verify_snp (non-throwing bool), verify_az_snp binds the anchor in
  // the verifier core and fails closed — it throws on a freshness mismatch. The JS
  // policy layer (verifyEvidence / verifyAttestation) catches this and surfaces it
  // as the report_data_mismatch code; see the policy-layer tests below.
  await assert.rejects(
    verifyAzSnp(JSON.stringify(await cocoEvidence()), utf8("wrong-nonce")),
    /report_data mismatch|TPM nonce/i,
  );
});

// --- Policy layer routing: verifyEvidence with platform:"az-snp" ---

test("verifyEvidence(platform:az-snp) passes with a matching freshness anchor", async () => {
  const res = await verifyEvidence(await cocoEvidence(), {
    platform: "az-snp",
    measurements: [COCO_MEASUREMENT],
    expectedReportData: utf8("challenge"),
  });
  assert.equal(res.ok, true);
  assert.equal(res.platform, "az-snp");
  assert.equal(res.measurement, COCO_MEASUREMENT);
  assert.equal(res.reportDataMatch, true);
});

test("verifyEvidence(platform:az-snp) needs no generation (auto-detected from CPUID)", async () => {
  // generation is omitted entirely — bare snp would reject this, az-snp must not.
  const res = await verifyEvidence(await cocoEvidence(), { platform: "az-snp" });
  assert.equal(res.ok, true);
  assert.equal(res.platform, "az-snp");
});

test("verifyEvidence(platform:az-snp) fails closed when the freshness anchor is wrong", async () => {
  await assert.rejects(
    verifyEvidence(await cocoEvidence(), {
      platform: "az-snp",
      expectedReportData: utf8("not-the-nonce"),
    }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "report_data_mismatch",
  );
});

test("verifyEvidence(platform:az-snp) warns (does not fail) when no anchor is supplied", async () => {
  const res = await verifyEvidence(await cocoEvidence(), { platform: "az-snp" });
  assert.equal(res.reportDataMatch, null);
  assert.ok(
    res.warnings.some((w) => w.includes("report_data freshness")),
    "should warn that freshness was not verified",
  );
});

test("verifyEvidence(platform:az-snp) denies a measurement outside the allowlist", async () => {
  await assert.rejects(
    verifyEvidence(await cocoEvidence(), {
      platform: "az-snp",
      measurements: ["00".repeat(48)],
      expectedReportData: utf8("challenge"),
    }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "measurement_denied",
  );
});

test("verifyEvidence(platform:az-snp) rejects tampered evidence (HW signature fails)", async () => {
  const evidence = (await cocoEvidence()) as AzSnpEvidence;
  // Flip a byte deep in the HCL report (base64url) — the SNP signature must break.
  const h = evidence.hcl_report!;
  const i = Math.floor(h.length / 2);
  evidence.hcl_report = h.slice(0, i) + (h[i] === "A" ? "B" : "A") + h.slice(i + 1);
  await assert.rejects(
    verifyEvidence(evidence, { platform: "az-snp", expectedReportData: utf8("challenge") }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "verification_failed",
  );
});

// A REAL c8s LB bundle (full c8s-verify/v1 shape) captured from a live cluster.
// Unlike the coco fixture's 9-byte ASCII nonce, its vTPM quote binds the
// production 48-byte freshness anchor SHA-384(x25519 ‖ mlkem768 ‖ nonce), so this
// exercises the actual over-encryption binding shape end to end.
test("verifyEvidence(platform:az-snp) verifies a real LB bundle's production freshness anchor", async () => {
  const bundle = JSON.parse(await readFile(join(FIX, "az-snp-bundle.json"), "utf8"));
  const expected = await expectedReportData(
    base64UrlToBytes(bundle.session_pubkey.x25519),
    base64UrlToBytes(bundle.session_pubkey.mlkem768),
    base64UrlToBytes(bundle.nonce),
  );

  const res = await verifyEvidence(bundle.evidence, {
    platform: "az-snp",
    expectedReportData: expected, // 48-byte SHA-384, carried in the vTPM quote extraData
  });
  assert.equal(res.ok, true);
  assert.equal(res.platform, "az-snp");
  assert.equal(
    res.reportDataMatch,
    true,
    "the quote extraData binds the real session+nonce anchor",
  );

  // A wrong anchor on the same real bundle must fail closed.
  await assert.rejects(
    verifyEvidence(bundle.evidence, {
      platform: "az-snp",
      expectedReportData: new Uint8Array(expected.length),
    }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "report_data_mismatch",
  );
});
