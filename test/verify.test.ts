import { test } from "node:test";
import assert from "node:assert/strict";

import {
  verifyAttestation,
  verifyEvidence,
  type AttestationBundle,
  type VerifyEvidenceOptions,
  type VerifyPolicy,
} from "../src/verify.js";
import { generateNonce } from "../src/nonce.js";
import { C8sVerifyError } from "../src/errors.js";
import { DEMO_MEASUREMENTS } from "../demo/config.js";
import { buildBundle, loadFixtures } from "./helpers.js";
import { base64ToBytes, bytesToBase64, bytesToBase64Url } from "../src/base64.js";
import { certificateHashBase64Url } from "../src/identity.js";

function policy(meshCaPem: string, overrides: Partial<VerifyPolicy> = {}): VerifyPolicy {
  return { measurements: DEMO_MEASUREMENTS, requireFreshness: false, meshCaPem, ...overrides };
}

test("verifies a well-formed bundle (recorded evidence)", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  const r = await verifyAttestation(bundle, nonce, policy(meshCaPem));
  assert.equal(r.ok, true);
  assert.equal(r.platform, "snp");
  assert.equal(r.measurement, DEMO_MEASUREMENTS[0]);
  assert.equal(r.cert.subjectCN, "lb.demo.c8s.local");
  assert.equal(r.cert.issuerCN, "c8s-demo-mesh-ca");
});

test("rejects a nonce mismatch", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  await assert.rejects(
    () => verifyAttestation(bundle, generateNonce(), policy(meshCaPem)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "nonce_mismatch",
  );
});

test("rejects tampered hardware evidence (signature fails in WASM)", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce, { tamperReport: true });
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem)),
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
    () => verifyAttestation(bundle, nonce, policy(meshCaPem, { requireFreshness: true })),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "report_data_mismatch",
  );
});

test("rejects when the pinned anchor is the wrong cert", async () => {
  const nonce = generateNonce();
  const { bundle } = await buildBundle(nonce);
  const { leafPem } = await loadFixtures();
  // Pin the leaf instead of the CA. The proof names the real CA, so selection
  // must fail before the chain can be accepted against the wrong anchor.
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(leafPem)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("verifies the mesh proof even when recorded evidence disables freshness", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem, transcript } = await buildBundle(nonce);
  const result = await verifyAttestation(bundle, nonce, policy(meshCaPem));
  assert.equal(result.identityBound, false);
  assert.ok(result.warnings.some((w) => w.includes("freshness binding not enforced")));
  // The KDF context is the verified transcript even without hardware freshness.
  assert.deepEqual(result.keyAgreementContext, transcript);
});

test("rejects session-key substitution after the mesh leaf signs", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  bundle.session_pubkey.x25519 = bytesToBase64Url(new Uint8Array(32).fill(0x55));
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

// --- protocol gates (all fail before / independently of the WASM verifier) ---

test("rejects an unexpected bundle version", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  bundle.version = "c8s-verify/v2";
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("rejects a bundle missing its identity proof", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  const malformed = { ...bundle, identity_proof: undefined } as unknown as AttestationBundle;
  await assert.rejects(
    () => verifyAttestation(malformed, nonce, policy(meshCaPem)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("rejects a bundle missing its certificate chain", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  const malformed = { ...bundle, cds_cert_pem: undefined } as unknown as AttestationBundle;
  await assert.rejects(
    () => verifyAttestation(malformed, nonce, policy(meshCaPem)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("requires a mesh CA pinned out of band", async () => {
  const nonce = generateNonce();
  const { bundle } = await buildBundle(nonce);
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy("")),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("rejects a proof naming an unpinned mesh CA", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  bundle.identity_proof.mesh_ca_sha256 = bytesToBase64Url(new Uint8Array(32).fill(0x07));
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("accepts padded base64url identity-proof fields", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  const pad = (s: string): string => s + "=".repeat((4 - (s.length % 4)) % 4);
  bundle.identity_proof.leaf_sha256 = pad(bundle.identity_proof.leaf_sha256);
  bundle.identity_proof.mesh_ca_sha256 = pad(bundle.identity_proof.mesh_ca_sha256);
  bundle.identity_proof.signature = pad(bundle.identity_proof.signature);
  const result = await verifyAttestation(bundle, nonce, policy(meshCaPem));
  assert.equal(result.ok, true);
});

test("rejects a leaf that does not chain to the pinned mesh CA", async () => {
  const nonce = generateNonce();
  const { bundle } = await buildBundle(nonce);
  // Pin the (non-CA) leaf as the anchor and point the proof at it so CA
  // selection succeeds; the chain check must then reject leaf-signed-by-leaf.
  const { leafPem, leafDer } = await loadFixtures();
  bundle.identity_proof.mesh_ca_sha256 = await certificateHashBase64Url(leafDer);
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(leafPem)),
    (e: unknown) =>
      e instanceof C8sVerifyError && (e.code === "cert_chain" || e.code === "invalid_cert"),
  );
});

test("requires a non-empty measurement allowlist", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, { measurements: [], meshCaPem }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
});

test("rejects a bundle with malformed base64url fields with a typed error", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  bundle.session_pubkey.mlkem768 = "!!not-base64url!!";
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
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

test("verifyEvidence rejects missing options with a typed error", async () => {
  const { snpEvidence } = await loadFixtures();
  await assert.rejects(
    () => verifyEvidence(snpEvidence, undefined as unknown as VerifyEvidenceOptions),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
});
