import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { evaluateSnp, evaluateAzSnp } from "../src/wasm-loader.js";
import { verifyEvidence } from "../src/verify.js";
import { snpReportFromHcl } from "../src/hcl.js";
import { base64UrlToBytes, concatBytes } from "../src/base64.js";
import { subtle } from "../src/crypto-env.js";
import { C8sVerifyError } from "../src/errors.js";
import type { Evidence, AzSnpEvidence } from "../src/hcl.js";

// Run from source via tsx; fixtures live alongside this file in test/fixtures.
const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

// A recorded Azure SEV-SNP (az-snp) attestation: an HCL report wrapping the raw
// SNP report, plus a TPM quote and the VCEK. Verified end-to-end through the
// JS -> WASM boundary (`evaluateSnp`), the same path `verifyAttestation` uses.
test("verifies a recorded az-snp attestation through the WASM verifier", async () => {
  const att = JSON.parse(await readFile(join(FIX, "az-snp-attestation.json"), "utf8"));

  // VCEK subject is SEV-Milan / HwID "Milan-B0" -> Milan generation.
  const out = await evaluateSnp(att.evidence, "milan");
  const result = JSON.parse(out);

  // Throwing would mean a VCEK chain or signature failure; passed means every
  // guest-policy rule held too.
  assert.equal(result.platform, "snp");
  assert.equal(result.passed, true);
});

// A second, independently-recorded Milan az-snp attestation (distinct host:
// different chip_id, launch_digest, and vmUniqueId). Guards the HCL unwrap
// against overfitting to a single recorded report.
test("verifies a second recorded az-snp (Milan) attestation", async () => {
  const att = JSON.parse(await readFile(join(FIX, "az-snp-milan-2.json"), "utf8"));

  const out = await evaluateSnp(att.evidence, "milan");
  const result = JSON.parse(out);

  assert.equal(result.platform, "snp");
  assert.equal(result.passed, true);
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
// `evaluate_az_snp` (exposed as evaluateAzSnp / platform:"az-snp") verifies the
// HCL-wrapped SNP report AND the vTPM quote — the TPM signature against the AK
// in the HCL runtime data, the AK→TEE binding, and the freshness anchor in the
// quote's extraData. This is what graduates az-snp from "reserved" (degraded
// hardware-only via evaluate_snp) to "supported" in PROTOCOL.md.
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

test("evaluate_az_snp verifies the vTPM quote, not just the hardware report", async () => {
  const out = JSON.parse(await evaluateAzSnp(JSON.stringify(await cocoEvidence())));
  assert.equal(out.platform, "az-snp");
  assert.equal(out.passed, true);
  assert.equal(out.report_data_match, null, "no expected anchor → match is null, not enforced");
  assert.equal(out.crl_ok, null, "no CRL supplied → revocation not checked");
});

test("evaluate_az_snp confirms freshness when the quote extraData matches the anchor", async () => {
  const out = JSON.parse(
    await evaluateAzSnp(JSON.stringify(await cocoEvidence()), utf8("challenge")),
  );
  assert.equal(out.report_data_match, true, "quote extraData binds the expected nonce");
});

test("evaluate_az_snp reports a freshness mismatch as not passed", async () => {
  // A mismatch is a value, not a throw: the policy layer reads report_data_match
  // and surfaces it as report_data_mismatch (see the policy-layer tests below).
  const out = JSON.parse(
    await evaluateAzSnp(JSON.stringify(await cocoEvidence()), utf8("wrong-nonce")),
  );
  assert.equal(out.report_data_match, false);
  assert.equal(out.passed, false);
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

// A real pre-release c8s LB bundle captured from a live cluster.
// Unlike the coco fixture's 9-byte ASCII nonce, its vTPM quote binds the
// production 48-byte freshness anchor SHA-384(x25519 ‖ mlkem768 ‖ nonce), so this
// exercises a production-sized quote freshness anchor end to end.
test("verifyEvidence(platform:az-snp) verifies a captured LB freshness anchor", async () => {
  const bundle = JSON.parse(await readFile(join(FIX, "az-snp-bundle.json"), "utf8"));
  const expected = new Uint8Array(
    await subtle().digest(
      "SHA-384",
      concatBytes(
        base64UrlToBytes(bundle.session_pubkey.x25519),
        base64UrlToBytes(bundle.session_pubkey.mlkem768),
        base64UrlToBytes(bundle.nonce),
      ),
    ),
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
