// SEV-SNP platform-security policy: the minimum-TCB floor (minTcb), the
// caller-supplied AMD KDS CRL (snpCrl), and the production requirement that
// collateral be verified (requireCollateral). Measurement pinning alone
// accepts a genuine, correctly-measured guest on unpatched firmware with a
// revoked endorsement key — these pins are what close that gap, so every
// unenforceable combination must be rejected, never silently dropped.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { evaluateSnp } from "../src/wasm-loader.js";
import { verifyEvidence } from "../src/verify.js";
import { C8sVerifyError } from "../src/errors.js";
import type { Evidence } from "../src/hcl.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// CoCo az-snp fixture with a known launch measurement (see az-snp.test.ts).
const COCO_MEASUREMENT =
  "9ac48fcac8a2d88aeeff8d427ad4f2be0e3917c748a18bdf52cc317e7fe20308b459d5ef1a12e0c22944eb386d17c315";

async function cocoEvidence(): Promise<Evidence> {
  return JSON.parse(await readFile(join(FIX, "az-snp-coco-bound.json"), "utf8"))
    .evidence as Evidence;
}

async function bareSnpEvidence(): Promise<Evidence> {
  return JSON.parse(await readFile(join(FIX, "az-snp-attestation.json"), "utf8"))
    .evidence as Evidence;
}

function code(c: string) {
  return (e: unknown) => e instanceof C8sVerifyError && e.code === c;
}

// --- minTcb: the floor is enforced against the verified reported TCB ---

test("a zero minTcb floor passes and the gap in collateral is surfaced", async () => {
  const res = await verifyEvidence(await cocoEvidence(), {
    platform: "az-snp",
    measurements: [COCO_MEASUREMENT],
    minTcb: { bootloader: 0, tee: 0, snp: 0, microcode: 0 },
  });
  assert.equal(res.ok, true);
  assert.equal(res.collateralVerified, false, "no CRL supplied ⇒ revocation was not checked");
  assert.ok(
    res.warnings.some((w) => w.includes("snpCrl")),
    "the collateral gap must be a named warning, not silence",
  );
});

test("a reported TCB below the minTcb floor fails closed as tcb_denied", async () => {
  await assert.rejects(
    verifyEvidence(await cocoEvidence(), {
      platform: "az-snp",
      measurements: [COCO_MEASUREMENT],
      minTcb: { bootloader: 0, tee: 0, snp: 0, microcode: 255 },
    }),
    code("tcb_denied"),
  );
});

test("minTcb components outside a u8 (or non-integers) are rejected upfront", async () => {
  for (const microcode of [256, 1.5, -1]) {
    await assert.rejects(
      verifyEvidence(await cocoEvidence(), {
        platform: "az-snp",
        measurements: [COCO_MEASUREMENT],
        minTcb: { bootloader: 0, tee: 0, snp: 0, microcode },
      }),
      code("invalid_request"),
    );
  }
});

test("minTcb on a TDX platform is rejected rather than silently dropped", async () => {
  await assert.rejects(
    verifyEvidence(
      {},
      {
        platform: "tdx",
        measurements: [COCO_MEASUREMENT],
        minTcb: { bootloader: 0, tee: 0, snp: 0, microcode: 0 },
      },
    ),
    code("invalid_request"),
  );
});

// --- snpCrl: supplied collateral must positively verify, never "skip" ---

test("an unparseable snpCrl fails closed as collateral_denied", async () => {
  await assert.rejects(
    verifyEvidence(await cocoEvidence(), {
      platform: "az-snp",
      measurements: [COCO_MEASUREMENT],
      snpCrl: new Uint8Array(64).fill(0xab),
    }),
    code("collateral_denied"),
  );
});

test("an empty snpCrl is rejected upfront", async () => {
  await assert.rejects(
    verifyEvidence(await cocoEvidence(), {
      platform: "az-snp",
      measurements: [COCO_MEASUREMENT],
      snpCrl: new Uint8Array(0),
    }),
    code("invalid_request"),
  );
});

test("snpCrl on a TDX platform is rejected", async () => {
  await assert.rejects(
    verifyEvidence(
      {},
      {
        platform: "tdx",
        measurements: [COCO_MEASUREMENT],
        snpCrl: new Uint8Array(64).fill(0xab),
      },
    ),
    code("invalid_request"),
  );
});

// --- requireCollateral: production policy that cannot be met is an error ---

test("requireCollateral without snpCrl is rejected upfront: it could never pass", async () => {
  await assert.rejects(
    verifyEvidence(await cocoEvidence(), {
      platform: "az-snp",
      measurements: [COCO_MEASUREMENT],
      requireCollateral: true,
    }),
    code("invalid_request"),
  );
});

test("requireCollateral on TDX needs tdxCollateral, and az-tdx has no collateral path", async () => {
  for (const platform of ["tdx", "az-tdx"]) {
    await assert.rejects(
      verifyEvidence(
        {},
        {
          platform,
          measurements: [COCO_MEASUREMENT],
          requireCollateral: true,
        },
      ),
      code("invalid_request"),
    );
  }
});

// --- bare snp (evaluate_snp): the same gates through the legacy entry point ---

test("bare evaluate_snp reports the minimum-TCB floor", async () => {
  const evidence = await bareSnpEvidence();
  // At floor zero the fixture passes and reports its collateral honestly.
  const ok = JSON.parse(
    await evaluateSnp(
      evidence,
      "milan",
      undefined,
      JSON.stringify({ bootloader: 0, tee: 0, snp: 0, microcode: 0 }),
    ),
  );
  assert.equal(ok.min_tcb_met, true);
  assert.equal(ok.passed, true);
  assert.equal(ok.crl_ok, null, "no CRL supplied ⇒ revocation was not checked");
  // Above the reported TCB it does not pass: a value, not a throw.
  const below = JSON.parse(
    await evaluateSnp(
      evidence,
      "milan",
      undefined,
      JSON.stringify({ bootloader: 0, tee: 0, snp: 0, microcode: 255 }),
    ),
  );
  assert.equal(below.min_tcb_met, false);
  assert.equal(below.passed, false);
});

test("bare evaluate_snp rejects a report_data anchor over 64 bytes", async () => {
  await assert.rejects(
    evaluateSnp(await bareSnpEvidence(), "milan", new Uint8Array(65)),
    /report_data exceeds maximum size \(64 bytes\)/,
  );
});

test("bare evaluate_snp fails closed on an unparseable CRL", async () => {
  await assert.rejects(
    evaluateSnp(
      await bareSnpEvidence(),
      "milan",
      undefined,
      undefined,
      new Uint8Array(64).fill(0xab),
    ),
    /CRL check/i,
  );
});

test("bare evaluate_snp rejects a malformed min TCB rather than dropping it", async () => {
  await assert.rejects(
    evaluateSnp(await bareSnpEvidence(), "milan", undefined, "not json"),
    /min_tcb deserialize/i,
  );
});
