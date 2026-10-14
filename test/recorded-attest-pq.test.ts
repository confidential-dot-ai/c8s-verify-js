import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { evaluateTdx } from "../src/wasm-loader.js";
import { verifyAttestation, type AttestationBundle, type VerifyPolicy } from "../src/verify.js";
import { C8sVerifyError } from "../src/errors.js";
import { base64UrlToBytes } from "../src/base64.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// A c8s/attest-pq/v1 response recorded from a live bare-metal TDX cluster
// (c8s v0.13.28-rc.2): the TD quote's report_data binds the identity
// transcript of this nonce, X-Wing exchange and CDS chain. Verified at the
// capture time, because the mesh leaf is short-lived.
interface Recorded {
  capturedAt: string;
  nonce: string;
  meshCaPem: string;
  bundle: AttestationBundle;
}

async function recorded(): Promise<Recorded> {
  return JSON.parse(await readFile(join(FIX, "tdx-attest-pq-bundle.json"), "utf8"));
}

// The cluster's image and deployment pins, taken out of band.
const TDX_IMAGE = {
  mrtd: "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1",
  rtmr1:
    "70f5d4740bab2ead4193c069a156052128854f87835b7828e78b821c31af2e4145fe11ce903686c0650bfb4efb2ade6c",
  rtmr2:
    "f57af25bd9d14e1b761ddde6b5e8124f8eaad2d6d5ec875d6eaa369e30e23186fead763b6d04844d7f31aa50e3eb5b59",
};
const RTMR3 =
  "3e70612c6cd297bb2ded912284fcafd674d76f2ed8bf9bacfa03eee9bcb5d754cbc80e442b503a2608f8a720de75091f";

function strictPolicy(r: Recorded, overrides: Partial<VerifyPolicy> = {}): VerifyPolicy {
  // requireFreshness is left at its default (true).
  return {
    platform: "tdx",
    tdxImage: TDX_IMAGE,
    expectedRtmr3: RTMR3,
    meshCaPem: r.meshCaPem,
    at: new Date(r.capturedAt),
    ...overrides,
  };
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/../g)!.map((b) => parseInt(b, 16)));
}

test("a recorded bundle that binds its transcript verifies with strict freshness", async () => {
  const r = await recorded();
  const res = await verifyAttestation(r.bundle, base64UrlToBytes(r.nonce), strictPolicy(r));
  assert.equal(res.ok, true);
  assert.equal(res.identityBound, true);
  assert.equal(res.reportDataMatch, true);
  assert.equal(res.trustClass, "specific-cluster");
  assert.ok(!res.warnings.some((w) => w.includes("freshness")), res.warnings.join("; "));
  // The verdict rests on the verifier's own `passed` for this transcript.
  const out = JSON.parse(
    await evaluateTdx(
      JSON.stringify(r.bundle.evidence),
      res.keyAgreementContext,
      undefined,
      hexToBytes(RTMR3),
    ),
  );
  assert.equal(out.passed, true);
});

test("a recorded bundle the verifier does not pass is rejected", async () => {
  const r = await recorded();
  const nonce = base64UrlToBytes(r.nonce);
  const code = (c: string) => (e: unknown) => e instanceof C8sVerifyError && e.code === c;
  // Another front-door mode changes the transcript, so report_data no longer binds it.
  await assert.rejects(
    verifyAttestation({ ...r.bundle, front_door_mode: "webpki" }, nonce, strictPolicy(r)),
    code("report_data_mismatch"),
  );
  // A pin for another deployment: the verifier reports rtmr_match[3] false.
  await assert.rejects(
    verifyAttestation(r.bundle, nonce, strictPolicy(r, { expectedRtmr3: "00".repeat(48) })),
    code("rtmr3_denied"),
  );
  const out = JSON.parse(
    await evaluateTdx(
      JSON.stringify(r.bundle.evidence),
      new Uint8Array(48),
      undefined,
      new Uint8Array(48),
    ),
  );
  assert.equal(out.passed, false);
});

test("with requireFreshness false the transcript is not checked and the verdict says so", async () => {
  const r = await recorded();
  const res = await verifyAttestation(
    r.bundle,
    base64UrlToBytes(r.nonce),
    strictPolicy(r, { requireFreshness: false }),
  );
  assert.equal(res.identityBound, false);
  assert.equal(res.reportDataMatch, null);
  assert.ok(res.warnings.some((w) => w.includes("freshness binding not enforced")));
});
