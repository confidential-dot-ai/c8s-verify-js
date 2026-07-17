import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifyAzTdx } from "../src/wasm-loader.js";
import { verifyEvidence } from "../src/verify.js";
import { C8sVerifyError } from "../src/errors.js";
import type { Evidence, AzTdxEvidence } from "../src/hcl.js";

// Run from source via tsx; fixtures live alongside this file in test/fixtures.
const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// A recorded Azure TDX (az-tdx) attestation: an HCL report wrapping the TD
// report, the Intel-signed TD quote, and the vTPM quote. Copied verbatim from
// attestation-rs' recorded fixture (test_data/az_tdx/evidence-v1.json), the same
// bundle the Rust and Go verifiers exercise. The envelope is { platform, evidence }.
async function tdxEvidence(): Promise<Evidence> {
  return JSON.parse(await readFile(join(FIX, "az-tdx-evidence.json"), "utf8")).evidence as Evidence;
}

// MRTD (TD launch measurement) surfaced by the verifier as claims.launch_digest.
// This is what a client would pin for the workload/node image on Azure TDX.
const TDX_MRTD =
  "024a32b070383331181619fa387cb4d55d1e38879f989933055ccad5bc2db795d1737b66205949d15469dc8c1ba7ab7b";

// --- First-class az-tdx: full verification including the vTPM quote ---
//
// verify_az_tdx (exposed as verifyAzTdx / platform:"az-tdx") verifies the
// HCL-wrapped TD report AND the vTPM quote — the TPM signature against the AK in
// the HCL runtime data, the AK->TEE binding, the TD quote's ECDSA signature and
// DCAP chain to the pinned Intel SGX Root CA, the TD debug policy, and the
// freshness anchor in the quote's extraData. This graduates az-tdx from
// "reserved" (PROTOCOL.md) to "supported".

test("verify_az_tdx verifies the TD quote + vTPM quote of a recorded az-tdx bundle", async () => {
  const out = JSON.parse(await verifyAzTdx(JSON.stringify(await tdxEvidence())));
  assert.equal(out.platform, "az-tdx");
  assert.equal(out.signature_valid, true, "TD quote signature + DCAP chain must verify");
  assert.equal(out.report_data_match, null, "no expected anchor → freshness not enforced, null");
  // collateral_verified is false: the WASM path has no async provider for the
  // Intel PCS collateral (PCK CRL, TCB status, TD-QE identity) — same trade-off
  // verify_az_snp documents.
  assert.equal(out.collateral_verified, false);
  assert.equal(out.claims.launch_digest, TDX_MRTD, "MRTD surfaces as claims.launch_digest");
});

test("verify_az_tdx fails closed (throws) on a freshness mismatch", async () => {
  // Like verify_az_snp, the anchor is bound in the verifier core, which fails
  // closed on a mismatch rather than returning a non-throwing bool. The JS policy
  // layer catches this and surfaces the report_data_mismatch code (below).
  await assert.rejects(
    verifyAzTdx(JSON.stringify(await tdxEvidence()), new Uint8Array(48)),
    /report_data mismatch|TPM nonce/i,
  );
});

// --- Policy layer routing: verifyEvidence with platform:"az-tdx" ---

test("verifyEvidence(platform:az-tdx) verifies and pins the MRTD", async () => {
  const res = await verifyEvidence(await tdxEvidence(), {
    platform: "az-tdx",
    measurements: [TDX_MRTD],
  });
  assert.equal(res.ok, true);
  assert.equal(res.platform, "az-tdx");
  assert.equal(res.measurement, TDX_MRTD);
});

test("verifyEvidence(platform:az-tdx) needs no generation (TDX collateral is Intel PCS/DCAP)", async () => {
  const res = await verifyEvidence(await tdxEvidence(), { platform: "az-tdx" });
  assert.equal(res.ok, true);
  assert.equal(res.platform, "az-tdx");
});

test("verifyEvidence(platform:az-tdx) denies an MRTD outside the allowlist", async () => {
  await assert.rejects(
    verifyEvidence(await tdxEvidence(), {
      platform: "az-tdx",
      measurements: ["00".repeat(48)],
    }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "measurement_denied",
  );
});

test("verifyEvidence(platform:az-tdx) fails closed when the freshness anchor is wrong", async () => {
  await assert.rejects(
    verifyEvidence(await tdxEvidence(), {
      platform: "az-tdx",
      expectedReportData: new Uint8Array(48),
    }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "report_data_mismatch",
  );
});

test("verifyEvidence(platform:az-tdx) warns (does not fail) when no anchor is supplied", async () => {
  const res = await verifyEvidence(await tdxEvidence(), { platform: "az-tdx" });
  assert.equal(res.reportDataMatch, null);
  assert.ok(
    res.warnings.some((w) => w.includes("report_data freshness")),
    "should warn that freshness was not verified",
  );
});

test("verifyEvidence(platform:az-tdx) rejects tampered evidence (HW verification fails)", async () => {
  const evidence = (await tdxEvidence()) as AzTdxEvidence;
  // Flip a byte deep in the HCL report (base64url) — verification must break.
  const h = evidence.hcl_report!;
  const i = Math.floor(h.length / 2);
  evidence.hcl_report = h.slice(0, i) + (h[i] === "A" ? "B" : "A") + h.slice(i + 1);
  await assert.rejects(
    verifyEvidence(evidence, { platform: "az-tdx" }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "verification_failed",
  );
});
