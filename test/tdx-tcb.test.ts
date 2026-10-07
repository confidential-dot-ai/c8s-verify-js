// TDX TCB-status policy: caller-supplied Intel PCS collateral, verified in
// WASM against Intel's signatures and the verification time, and the TCB
// levels the caller accepts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifyAttestation, verifyEvidence } from "../src/verify.js";
import { C8sVerifyError } from "../src/errors.js";
import { generateNonce } from "../src/nonce.js";
import type { TdxCollateral } from "../src/tdx-tcb.js";
import type { Evidence } from "../src/hcl.js";
import { buildBundle } from "./helpers.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const COLLATERAL = join(FIX, "tdx-collateral");

// tdx-bundle.json's quote is from a c8s node with FMSPC 00a06d080000; the
// collateral was fetched for it from Intel PCS v4 on 2026-10-05. Every item is
// current between 2026-10-05T14:40:24Z and 2026-11-04T14:22:24Z.
const AT = new Date("2026-10-06T00:00:00Z");
const TDX_IMAGE = {
  mrtd: "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
  rtmr1:
    "e0aaa1f273b80e1e4e5032b789f34fc3f78c88719717b266cb3152aa4bc6490f13fe3a9cea8e00b48a3719074e06c05a",
  rtmr2:
    "15d4452b636e411b9c85a9fdb8b9c75b8ac7abb7eafe846aed987495a8b44b3b22a9681521961b382bdfe170efc4adeb",
};

async function evidence(): Promise<Evidence> {
  return JSON.parse(await readFile(join(FIX, "tdx-bundle.json"), "utf8")).evidence as Evidence;
}

async function collateral(): Promise<TdxCollateral> {
  const text = (f: string) => readFile(join(COLLATERAL, f), "utf8");
  const bytes = async (f: string) => new Uint8Array(await readFile(join(COLLATERAL, f)));
  return {
    tcbInfo: await text("tcb_info_00a06d080000.json"),
    tcbInfoIssuerChain: await text("tcb_signing_chain.pem"),
    qeIdentity: await bytes("td_qe_identity.json"),
    qeIdentityIssuerChain: await text("qe_identity_signing_chain.pem"),
    pckCrl: await bytes("pck_crl_platform.der"),
    rootCaCrl: await bytes("root_ca_crl.der"),
  };
}

function code(c: string) {
  return (e: unknown) => e instanceof C8sVerifyError && e.code === c;
}

test("supplied collateral reports the evaluated TCB status", async () => {
  const r = await verifyEvidence(await evidence(), {
    platform: "tdx",
    tdxImage: TDX_IMAGE,
    tdxCollateral: await collateral(),
    requireCollateral: true,
    at: AT,
  });
  assert.equal(r.collateralVerified, true);
  assert.deepEqual(r.tdxTcb, { status: "UpToDate", fmspc: "00a06d080000", advisoryIds: [] });
  assert.ok(!r.warnings.some((w) => w.includes("DCAP collateral")), JSON.stringify(r.warnings));
});

test("without collateral the TCB status is reported as not checked", async () => {
  const r = await verifyEvidence(await evidence(), { platform: "tdx", tdxImage: TDX_IMAGE });
  assert.equal(r.collateralVerified, false);
  assert.equal(r.tdxTcb, undefined);
  assert.ok(r.warnings.some((w) => w.includes("no tdxCollateral supplied")));
});

test("a TCB status outside the accepted set fails with tcb_denied", async () => {
  await assert.rejects(
    verifyEvidence(await evidence(), {
      platform: "tdx",
      tdxImage: TDX_IMAGE,
      tdxCollateral: await collateral(),
      tdxTcbStatuses: ["SWHardeningNeeded", "OutOfDate"],
      at: AT,
    }),
    (e: unknown) => code("tcb_denied")(e) && (e as C8sVerifyError).details.status === "UpToDate",
  );
});

test("stale or tampered collateral fails closed with collateral_denied", async () => {
  const good = await collateral();
  const tcbInfo = (good.tcbInfo as string).replace('"OutOfDate"', '"UpToDate"');
  assert.notEqual(tcbInfo, good.tcbInfo);
  const crl = new Uint8Array(good.pckCrl as Uint8Array);
  crl[crl.length - 1] ^= 1;
  for (const [c, at] of [
    [good, new Date("2026-12-01T00:00:00Z")],
    [good, new Date("2026-09-01T00:00:00Z")],
    [{ ...good, tcbInfo }, AT],
    [{ ...good, pckCrl: crl }, AT],
    [{ ...good, pckCrl: good.rootCaCrl }, AT],
  ] as const) {
    await assert.rejects(
      verifyEvidence(await evidence(), {
        platform: "tdx",
        tdxImage: TDX_IMAGE,
        tdxCollateral: c,
        at,
      }),
      code("collateral_denied"),
    );
  }
});

test("an evidence failure is not reported as a collateral failure", async () => {
  await assert.rejects(
    verifyEvidence(await evidence(), {
      platform: "tdx",
      tdxImage: TDX_IMAGE,
      tdxCollateral: await collateral(),
      expectedReportData: new Uint8Array(64).fill(0xff),
      at: AT,
    }),
    code("report_data_mismatch"),
  );
});

test("TCB policies the verifier could not enforce are refused upfront", async () => {
  const good = await collateral();
  const ev = await evidence();
  for (const opts of [
    { platform: "az-tdx", tdxImage: TDX_IMAGE, tdxCollateral: good },
    { platform: "tdx", tdxImage: TDX_IMAGE, tdxTcbStatuses: ["UpToDate" as const] },
    { platform: "tdx", tdxImage: TDX_IMAGE, tdxCollateral: good, tdxTcbStatuses: [] },
    {
      platform: "tdx",
      tdxImage: TDX_IMAGE,
      tdxCollateral: good,
      tdxTcbStatuses: ["Revoked" as const],
    },
    { platform: "tdx", tdxImage: TDX_IMAGE, tdxCollateral: { ...good, pckCrl: "" } },
    { platform: "tdx", tdxImage: TDX_IMAGE, requireCollateral: true },
  ]) {
    await assert.rejects(verifyEvidence(ev, opts), code("invalid_request"), JSON.stringify(opts));
  }
});

test("an invalid verification time is refused, not serialized as null", async () => {
  await assert.rejects(
    verifyEvidence(await evidence(), {
      platform: "tdx",
      tdxImage: TDX_IMAGE,
      tdxCollateral: await collateral(),
      at: new Date("not a date"),
    }),
    code("invalid_request"),
  );
});

test("verifyAttestation surfaces the TCB status on the result", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce, {
    evidence: await evidence(),
    platform: "tdx",
  });
  const base = {
    platform: "tdx",
    requireFreshness: false,
    tdxImage: TDX_IMAGE,
    meshCaPem,
    at: AT,
  };
  const r = await verifyAttestation(bundle, nonce, {
    ...base,
    tdxCollateral: await collateral(),
    tdxTcbStatuses: ["UpToDate", "SWHardeningNeeded"],
    requireCollateral: true,
  });
  assert.equal(r.collateralVerified, true);
  assert.equal(r.tdxTcb?.status, "UpToDate");

  const unchecked = await verifyAttestation(bundle, nonce, base);
  assert.equal(unchecked.collateralVerified, false);
  assert.equal(unchecked.tdxTcb, undefined);
});
