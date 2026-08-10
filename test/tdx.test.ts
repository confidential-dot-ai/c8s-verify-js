import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifyTdx } from "../src/wasm-loader.js";
import { enforceTdxImagePins, verifyEvidence, type WasmVerifyResult } from "../src/verify.js";
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
  // MRTD-only is not a platform-complete TDX image policy: warn prominently.
  assert.ok(
    res.warnings.some((w) => w.includes("not platform-complete")),
    `expected the platform-completeness warning, got: ${JSON.stringify(res.warnings)}`,
  );
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

// The register is TDX-only, so a pin combined with an SNP platform must be
// refused up front rather than silently dropped — a pin that looks configured
// and enforces nothing is worse than no pin. "TDX" is the family, though, not
// the bare-metal tag: az-tdx carries the same registers and accepts the pin
// (see az-tdx.test.ts), which is why only the SNP tags appear here.
test("verifyEvidence refuses an RTMR[3] pin on a non-TDX platform", async () => {
  const { evidence } = await tdxBundle();
  for (const platform of ["snp", "az-snp"]) {
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

// ---------------------------------------------------------------------------
// The TDX image tuple: MRTD + RTMR[1] + RTMR[2] pinned as one unit
// ---------------------------------------------------------------------------

// RTMR[1]/RTMR[2] of the TD that produced the fixture: the guest kernel and
// rootfs measurements that, together with MRTD, form the complete image
// identity — the tuple a build publishes in its image manifest.
const TDX_RTMR1 =
  "e0aaa1f273b80e1e4e5032b789f34fc3f78c88719717b266cb3152aa4bc6490f13fe3a9cea8e00b48a3719074e06c05a";
const TDX_RTMR2 =
  "15d4452b636e411b9c85a9fdb8b9c75b8ac7abb7eafe846aed987495a8b44b3b22a9681521961b382bdfe170efc4adeb";
const TDX_IMAGE = { mrtd: TDX_MRTD, rtmr1: TDX_RTMR1, rtmr2: TDX_RTMR2 };

test('verifyEvidence platform:"tdx" accepts a matching image tuple', async () => {
  const { evidence } = await tdxBundle();
  // The tuple's MRTD joins the allowlist, so no separate `measurements` pin is
  // needed; the result reports both registers as compared.
  const res = await verifyEvidence(evidence, { platform: "tdx", tdxImage: TDX_IMAGE });
  assert.equal(res.ok, true);
  assert.equal(res.measurement, TDX_MRTD);
  assert.deepEqual(res.rtmrsPinned, [`1:${TDX_RTMR1}`, `2:${TDX_RTMR2}`]);
  assert.ok(!res.warnings.some((w) => w.includes("not platform-complete")));
});

test("a full tuple pin also records RTMR[3] when that pin is set", async () => {
  const { evidence } = await tdxBundle();
  const res = await verifyEvidence(evidence, {
    platform: "tdx",
    tdxImage: TDX_IMAGE,
    expectedRtmr3: TDX_RTMR3,
  });
  assert.deepEqual(res.rtmrsPinned, [`1:${TDX_RTMR1}`, `2:${TDX_RTMR2}`, `3:${TDX_RTMR3}`]);
});

// A matching MRTD must not stand in for the image: the same firmware boots
// any guest kernel/rootfs, so a diverging RTMR[1] or RTMR[2] is a different
// image and fails with the register-precise code.
test("a wrong RTMR[1] or RTMR[2] fails with rtmr_denied even when MRTD matches", async () => {
  const { evidence } = await tdxBundle();
  for (const bad of [
    { ...TDX_IMAGE, rtmr1: "ff".repeat(48) },
    { ...TDX_IMAGE, rtmr2: TDX_RTMR2.slice(0, 94) + "00" },
  ]) {
    await assert.rejects(
      verifyEvidence(evidence, { platform: "tdx", tdxImage: bad }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "rtmr_denied",
    );
  }
});

// All three registers or none: a partial tuple would silently verify only
// part of the image, so it is refused up front — as are bad hex, uppercase
// (the claims are lowercase and comparisons are byte-exact), and wrong length.
test("a partial or malformed tuple is refused with invalid_request", async () => {
  const { evidence } = await tdxBundle();
  const partials = [
    { rtmr1: TDX_RTMR1, rtmr2: TDX_RTMR2 },
    { mrtd: TDX_MRTD, rtmr2: TDX_RTMR2 },
    { mrtd: TDX_MRTD, rtmr1: TDX_RTMR1 },
    { ...TDX_IMAGE, rtmr1: "" },
    { ...TDX_IMAGE, mrtd: "zz".repeat(48) },
    { ...TDX_IMAGE, rtmr2: TDX_RTMR2.toUpperCase() },
    { ...TDX_IMAGE, rtmr1: TDX_RTMR1.slice(0, 95) },
  ];
  for (const bad of partials) {
    await assert.rejects(
      verifyEvidence(evidence, {
        platform: "tdx",
        tdxImage: bad as unknown as typeof TDX_IMAGE,
      }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      `tuple ${JSON.stringify(bad).slice(0, 60)}… must be refused`,
    );
  }
});

// An absent or malformed claim must fail closed, never read as "held": a
// verifier build whose claims omit the registers cannot vouch for the pin.
// Real evidence always carries them, so the fail-closed paths are exercised
// directly on hand-built results.
test("enforceTdxImagePins fails closed on absent or malformed register claims", () => {
  const base = {
    signature_valid: true,
    platform: "tdx",
    report_data_match: null,
  };
  for (const claims of [
    { launch_digest: TDX_MRTD }, // no platform_data at all
    { launch_digest: TDX_MRTD, platform_data: {} }, // registers absent
    { launch_digest: TDX_MRTD, platform_data: { rtmr_1: TDX_RTMR1 } }, // rtmr_2 absent
    // present but not a comparable register encoding
    {
      launch_digest: TDX_MRTD,
      platform_data: { rtmr_1: TDX_RTMR1.toUpperCase(), rtmr_2: TDX_RTMR2 },
    },
    { launch_digest: TDX_MRTD, platform_data: { rtmr_1: "abcd", rtmr_2: TDX_RTMR2 } },
    { launch_digest: TDX_MRTD, platform_data: { rtmr_1: 7, rtmr_2: TDX_RTMR2 } },
  ]) {
    const result: WasmVerifyResult = { ...base, claims };
    assert.throws(
      () => enforceTdxImagePins(result, TDX_IMAGE),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "rtmr_denied",
      `claims ${JSON.stringify(claims).slice(0, 80)}… must fail closed`,
    );
  }
  // The same helper passes on well-formed matching claims.
  const ok = enforceTdxImagePins(
    {
      ...base,
      claims: { launch_digest: TDX_MRTD, platform_data: { rtmr_1: TDX_RTMR1, rtmr_2: TDX_RTMR2 } },
    },
    TDX_IMAGE,
  );
  assert.deepEqual(ok, [`1:${TDX_RTMR1}`, `2:${TDX_RTMR2}`]);
});

// Mirror of the expectedRtmr3 platform rule: the registers exist only on TDX
// (SNP's launch measurement already covers the full image by design), so a
// tuple combined with an SNP platform is a policy error, never ignored — and,
// equally, never refused on az-tdx, which has the registers.
test("verifyEvidence refuses an image tuple on a non-TDX platform", async () => {
  const { evidence } = await tdxBundle();
  for (const platform of ["snp", "az-snp"]) {
    await assert.rejects(
      verifyEvidence(evidence, {
        platform,
        generation: "milan",
        tdxImage: TDX_IMAGE,
      }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      `platform ${platform} must refuse the tuple`,
    );
  }
});
