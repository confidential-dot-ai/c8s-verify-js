import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifyTdx } from "../src/wasm-loader.js";
import { verifyEvidence } from "../src/verify.js";
import { C8sVerifyError } from "../src/errors.js";
import { base64UrlToBytes } from "../src/base64.js";
import type { TdxEvidence } from "../src/hcl.js";

// Run from source via tsx; fixtures live alongside this file in test/fixtures.
const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// A LIVE-captured bare-metal Intel TDX attestation bundle from a c8s cluster's
// cds-attest sidecar (`GET /.well-known/c8s/attestation?nonce=…&pq=false`):
// platform "tdx", tls-cert binding, evidence = { quote, cc_eventlog }. The TD
// quote's report_data binds SHA-384(serving_leaf_SPKI ‖ nonce), zero-padded to
// 64 bytes; the SPKI below is the serving certificate's SubjectPublicKeyInfo
// captured from the same TLS session that fetched the bundle.
async function tdxBundle(): Promise<{ nonce: string; evidence: TdxEvidence }> {
  return JSON.parse(await readFile(join(FIX, "tdx-bundle.json"), "utf8"));
}

// SubjectPublicKeyInfo (DER, hex) of the TLS leaf served when the bundle was
// captured — the first half of the report_data preimage.
const LEAF_SPKI_HEX =
  "3059301306072a8648ce3d020106082a8648ce3d03010703420004ffe8cdbe2d0b32ee21c8987f61f326e1" +
  "32cd2529acbba3966502eedb415a1f0898371a35388ec4bdb9f435e9437afba215f6a488c3b582f72a98b3" +
  "686c35ff4f";

// MRTD (TD launch measurement) surfaced by the verifier as claims.launch_digest.
// This is what a client would pin for the guest image on this cluster.
const TDX_MRTD =
  "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1";

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/../g)!.map((b) => parseInt(b, 16)));
}

/** report_data anchor: SHA-384(serving_leaf_SPKI ‖ nonce). */
async function tlsCertAnchor(): Promise<Uint8Array> {
  const { nonce } = await tdxBundle();
  const h = createHash("sha384");
  h.update(hexToBytes(LEAF_SPKI_HEX));
  h.update(base64UrlToBytes(nonce));
  return new Uint8Array(h.digest());
}

// --- First-class bare tdx: direct DCAP verification, no vTPM in the path ---
//
// verify_tdx (exposed as verifyTdx / platform:"tdx") verifies the TD quote's
// ECDSA signature and the full DCAP chain to the pinned Intel SGX Root CA,
// rejects debug TDs, replays the CC event log against RTMR0-3, and binds the
// freshness anchor directly against the quote's 64-byte report_data.

test("verify_tdx verifies a live-captured bare-metal TDX bundle", async () => {
  const { evidence } = await tdxBundle();
  const out = JSON.parse(await verifyTdx(JSON.stringify(evidence)));
  assert.equal(out.platform, "tdx");
  assert.equal(out.signature_valid, true, "TD quote signature + DCAP chain must verify");
  assert.equal(out.report_data_match, null, "no expected anchor → freshness not enforced, null");
  // collateral_verified is false: the WASM path has no async provider for the
  // Intel PCS collateral (PCK CRL, TCB status, TD-QE identity) — same trade-off
  // the az-snp/az-tdx WASM paths document.
  assert.equal(out.collateral_verified, false);
  assert.equal(out.claims.launch_digest, TDX_MRTD, "MRTD surfaces as claims.launch_digest");
});

test("verify_tdx binds report_data to the tls-cert anchor (SPKI ‖ nonce)", async () => {
  const { evidence } = await tdxBundle();
  const out = JSON.parse(await verifyTdx(JSON.stringify(evidence), await tlsCertAnchor()));
  assert.equal(out.report_data_match, true, "SHA-384(SPKI ‖ nonce) must match report_data");
});

test("verify_tdx fails closed (throws) on a freshness mismatch", async () => {
  const { evidence } = await tdxBundle();
  await assert.rejects(
    verifyTdx(JSON.stringify(evidence), new Uint8Array(48)),
    /report_data mismatch/i,
  );
});

test("verify_tdx fails closed on a tampered CC event log", async () => {
  const { evidence } = await tdxBundle();
  // Truncate the event log deep into the measured events: the replay of what
  // remains against RTMR0-3 must fail, even though the quote itself is
  // untouched and genuine. (Flipping a byte in an event's *data* would not do —
  // per-event digests are precomputed in the log, so only the digests enter
  // the replay; and cutting in the zero-padded tail of the CCEL region would
  // leave the measured prefix intact.)
  const raw = Buffer.from(evidence.cc_eventlog!, "base64");
  const truncated = raw.subarray(0, 1024).toString("base64");
  await assert.rejects(
    verifyTdx(JSON.stringify({ ...evidence, cc_eventlog: truncated })),
    /eventlog integrity/i,
  );
});

// --- Policy layer routing: verifyEvidence with platform:"tdx" ---

test('verifyEvidence platform:"tdx" verifies without a generation', async () => {
  const { evidence } = await tdxBundle();
  const res = await verifyEvidence(evidence, {
    platform: "tdx",
    measurements: [TDX_MRTD],
    expectedReportData: await tlsCertAnchor(),
  });
  assert.equal(res.ok, true);
  assert.equal(res.platform, "tdx");
  assert.equal(res.measurement, TDX_MRTD);
  assert.equal(res.reportDataMatch, true);
  assert.deepEqual(res.warnings, []);
});

test('verifyEvidence platform:"tdx" denies a wrong measurement pin', async () => {
  const { evidence } = await tdxBundle();
  await assert.rejects(
    verifyEvidence(evidence, {
      platform: "tdx",
      measurements: ["ab".repeat(48)],
    }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "measurement_denied",
  );
});

test('verifyEvidence platform:"tdx" maps a stale anchor to report_data_mismatch', async () => {
  const { evidence } = await tdxBundle();
  await assert.rejects(
    verifyEvidence(evidence, {
      platform: "tdx",
      measurements: [TDX_MRTD],
      expectedReportData: new Uint8Array(48),
    }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "report_data_mismatch",
  );
});

// RTMR[3] of the TD that produced the fixture. Unlike MRTD, this register is
// extended after launch — on a c8s node with the operator public key bound at
// boot — so it identifies a specific deployment rather than a build. Pinning it
// is what separates "a genuine instance of the audited image" (which anyone can
// stand up, since the image is reproducible) from "this operator's cluster".
const TDX_RTMR3 =
  "21df104d732e863ffd57be4311de7ac2721b29550bc482ec1d2e85d572bfcb9c669b7f498d5910f9ba5a795209f215a6";

test('verifyEvidence platform:"tdx" accepts a matching RTMR[3] pin', async () => {
  const { evidence } = await tdxBundle();
  const res = await verifyEvidence(evidence, {
    platform: "tdx",
    measurements: [TDX_MRTD],
    expectedRtmr3: TDX_RTMR3,
  });
  assert.equal(res.ok, true);
  assert.equal((res.claims.platform_data as Record<string, unknown>).rtmr_3, TDX_RTMR3);
});

test('verifyEvidence platform:"tdx" denies a wrong RTMR[3] pin', async () => {
  const { evidence } = await tdxBundle();
  await assert.rejects(
    verifyEvidence(evidence, {
      platform: "tdx",
      measurements: [TDX_MRTD],
      expectedRtmr3: "ff".repeat(48),
    }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "rtmr3_denied",
  );
});

// The pin must survive a correct measurement: a matching MRTD says the right
// code booted, and must not be allowed to stand in for deployment identity.
test('verifyEvidence platform:"tdx" denies a wrong RTMR[3] even when MRTD matches', async () => {
  const { evidence } = await tdxBundle();
  await assert.rejects(
    verifyEvidence(evidence, {
      platform: "tdx",
      measurements: [TDX_MRTD],
      expectedRtmr3: TDX_RTMR3.slice(0, 94) + "00",
    }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "rtmr3_denied",
  );
});

// The register is TDX-only and the verifier consults it only on the TDX path,
// so a pin combined with any other platform must be refused up front rather
// than silently dropped — a pin that looks configured and enforces nothing is
// worse than no pin.
test("verifyEvidence refuses an RTMR[3] pin on a non-TDX platform", async () => {
  const { evidence } = await tdxBundle();
  for (const platform of ["snp", "az-snp", "az-tdx"]) {
    await assert.rejects(
      verifyEvidence(evidence, {
        platform,
        generation: "milan",
        measurements: [TDX_MRTD],
        expectedRtmr3: TDX_RTMR3,
      }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      `platform ${platform} must refuse the pin`,
    );
  }
});

test("verifyEvidence refuses a malformed RTMR[3] pin", async () => {
  const { evidence } = await tdxBundle();
  for (const bad of ["", "deadbeef", "z".repeat(96), TDX_RTMR3.slice(0, 95)]) {
    await assert.rejects(
      verifyEvidence(evidence, {
        platform: "tdx",
        measurements: [TDX_MRTD],
        expectedRtmr3: bad,
      }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      `pin ${JSON.stringify(bad)} must be refused`,
    );
  }
});

// Omitting the pin must stay valid: existing callers keep working, and the
// result then carries no rtmr3_match at all.
test('verifyEvidence platform:"tdx" without a pin does not check RTMR[3]', async () => {
  const { evidence } = await tdxBundle();
  const res = await verifyEvidence(evidence, { platform: "tdx", measurements: [TDX_MRTD] });
  assert.equal(res.ok, true);
});
