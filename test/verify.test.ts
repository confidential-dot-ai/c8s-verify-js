import { test } from "node:test";
import assert from "node:assert/strict";

import {
  verifyAttestation,
  verifyEvidence,
  expectedReportData,
  type VerifyPolicy,
} from "../src/verify.js";
import { generateNonce } from "../src/nonce.js";
import { C8sVerifyError } from "../src/errors.js";
import { DEMO_MEASUREMENTS } from "../demo/config.js";
import { buildBundle, loadFixtures } from "./helpers.js";
import { base64ToBytes, bytesToBase64 } from "../src/base64.js";

const POLICY: VerifyPolicy = { measurements: DEMO_MEASUREMENTS, requireFreshness: false };

test("verifies a well-formed bundle (recorded evidence)", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  const r = await verifyAttestation(bundle, nonce, { ...POLICY, meshCaPem });
  assert.equal(r.ok, true);
  assert.equal(r.platform, "snp");
  assert.equal(r.measurement, DEMO_MEASUREMENTS[0]);
  assert.equal(r.cert!.subjectCN, "lb.demo.c8s.local");
  assert.equal(r.cert!.issuerCN, "c8s-demo-mesh-ca");
});

test("rejects a nonce mismatch", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  await assert.rejects(
    () => verifyAttestation(bundle, generateNonce(), { ...POLICY, meshCaPem }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "nonce_mismatch",
  );
});

test("rejects tampered hardware evidence (signature fails in WASM)", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce, { tamperReport: true });
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, { ...POLICY, meshCaPem }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "verification_failed",
  );
});

test("rejects a measurement not in the allowlist", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  await assert.rejects(
    () =>
      verifyAttestation(bundle, nonce, {
        measurements: ["deadbeef"],
        requireFreshness: false,
        meshCaPem,
      }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "measurement_denied",
  );
});

test("enforces freshness binding when required (fixture is not live-bound)", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, { ...POLICY, requireFreshness: true, meshCaPem }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "report_data_mismatch",
  );
});

test("rejects when the pinned anchor is the wrong cert", async () => {
  const nonce = generateNonce();
  const { bundle } = await buildBundle(nonce);
  const { leafPem } = await loadFixtures();
  // Pin the (P-256, non-CA) leaf as the anchor: the served leaf must fail to
  // verify against it, since it was actually signed by the P-384 mesh CA.
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, { ...POLICY, meshCaPem: leafPem }),
    (e: unknown) =>
      e instanceof C8sVerifyError && (e.code === "cert_chain" || e.code === "invalid_cert"),
  );
});

test("expectedReportData is a 48-byte SHA-384 digest", async () => {
  const d = await expectedReportData(new Uint8Array(32), new Uint8Array(1184), new Uint8Array(32));
  assert.equal(d.length, 48);
});

// --- verifyEvidence: bare SNP evidence (no bundle / nonce / session / cert) ---

test("verifyEvidence verifies bare SNP evidence", async () => {
  const { snpEvidence } = await loadFixtures();
  const r = await verifyEvidence(snpEvidence, {
    generation: "genoa",
    measurements: DEMO_MEASUREMENTS,
  });
  assert.equal(r.ok, true);
  assert.equal(r.platform, "snp");
  assert.equal(r.measurement, DEMO_MEASUREMENTS[0]);
  // No expected binding supplied -> warns rather than fails.
  assert.ok(r.warnings.some((w) => w.includes("expectedReportData")));
});

test("verifyEvidence rejects a measurement not in the allowlist", async () => {
  const { snpEvidence } = await loadFixtures();
  await assert.rejects(
    () => verifyEvidence(snpEvidence, { generation: "genoa", measurements: ["deadbeef"] }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "measurement_denied",
  );
});

test("verifyEvidence rejects tampered hardware evidence", async () => {
  const { snpEvidence } = await loadFixtures();
  const evidence = JSON.parse(JSON.stringify(snpEvidence));
  const rep = base64ToBytes(evidence.attestation_report);
  rep[200] ^= 0x01;
  evidence.attestation_report = bytesToBase64(rep);
  await assert.rejects(
    () => verifyEvidence(evidence, { generation: "genoa", measurements: DEMO_MEASUREMENTS }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "verification_failed",
  );
});

test("verifyEvidence enforces an explicit report_data binding", async () => {
  const { snpEvidence } = await loadFixtures();
  await assert.rejects(
    () =>
      verifyEvidence(snpEvidence, {
        generation: "genoa",
        measurements: DEMO_MEASUREMENTS,
        expectedReportData: new Uint8Array(48), // will not match the fixture's report_data
      }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "report_data_mismatch",
  );
});

test("verifyEvidence requires a generation", async () => {
  const { snpEvidence } = await loadFixtures();
  await assert.rejects(
    () => verifyEvidence(snpEvidence, { measurements: DEMO_MEASUREMENTS }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
});
