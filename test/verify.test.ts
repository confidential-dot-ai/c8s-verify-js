import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

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
import { fingerprintSHA256 } from "../src/x509.js";
import { allowlistDigestHex } from "../src/workload.js";
import { encodeMatchedWorkload, extension, mintLeaf, OID_15_DER } from "./mint-cert.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

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
  bundle.version = "c8s/attest-pq/v2";
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

// Cross-endpoint and stale-server rejection: an attest-lb response is a
// different trust decision (native clients binding the outer TLS leaf), and a
// pre-cutover c8s-verify/v1 bundle is a server this client must not adapt to.
// Both carry otherwise-plausible evidence, so the version gate has to be the
// thing that stops them.
test("rejects attest-lb and retired c8s-verify/v1 bundle versions", async () => {
  for (const version of ["c8s/attest-lb/v1", "c8s-verify/v1"]) {
    const nonce = generateNonce();
    const { bundle, meshCaPem } = await buildBundle(nonce);
    bundle.version = version;
    await assert.rejects(
      () => verifyAttestation(bundle, nonce, policy(meshCaPem)),
      (e: unknown) =>
        e instanceof C8sVerifyError && e.code === "identity_binding" && e.message.includes(version),
      `version ${version} must be rejected`,
    );
  }
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

// A multi-block meshCaPem means "each of these is independently trusted as an
// anchor", and selectPinnedCA anchors to whichever one the proof names. That is
// the documented contract, and also what a caller gets by accident if they pass
// a chain the SERVER handed them — at which point the pin is not a pin. It
// still verifies (the named block really is pinned), but it must not do so
// quietly.
test("warns when meshCaPem pins more than one certificate", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  const { leafPem } = await loadFixtures();
  // A second, unrelated block alongside the real anchor.
  const r = await verifyAttestation(bundle, nonce, policy(meshCaPem + leafPem));
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings.some((w) => w.includes("pins 2 certificates and each is independently trusted")),
    `expected a multi-anchor warning, got: ${JSON.stringify(r.warnings)}`,
  );
});

test("a single-certificate meshCaPem produces no anchor warning", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  const r = await verifyAttestation(bundle, nonce, policy(meshCaPem));
  assert.ok(!r.warnings.some((w) => w.includes("independently trusted")));
});

// ---------------------------------------------------------------------------
// Anchors and trust class
// ---------------------------------------------------------------------------

/** The fixture allowlist's exact canonical bytes. */
const readAllowlistBytes = async () =>
  new Uint8Array(await readFile(join(FIX, "cds-allowlist.json")));

/** A leaf minted on the fixture mesh CA, stamped with the given extnValue. */
async function stampedLeaf(extnValue: Uint8Array) {
  const { caDer, caKeyPem } = await loadFixtures();
  return mintLeaf(caDer, caKeyPem, { extensions: [extension(OID_15_DER, extnValue)] });
}

/** A stamp whose digest commits the fixture allowlist bytes. */
async function stampFor(name: string): Promise<Uint8Array> {
  const digestHex = await allowlistDigestHex(await readAllowlistBytes());
  return encodeMatchedWorkload(
    name,
    "7",
    new Uint8Array(digestHex.match(/../g)!.map((b) => parseInt(b, 16))),
  );
}

test("requires an anchor: neither meshCaPem nor allowlist is a policy error", async () => {
  const nonce = generateNonce();
  const { bundle } = await buildBundle(nonce);
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, { measurements: DEMO_MEASUREMENTS }),
    (e: unknown) =>
      e instanceof C8sVerifyError &&
      e.code === "identity_binding" &&
      e.message.includes("requires an anchor"),
  );
});

test("rejects an empty allowlist pin and an empty workloadName pin", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  await assert.rejects(
    () =>
      verifyAttestation(bundle, nonce, {
        measurements: DEMO_MEASUREMENTS,
        allowlist: new Uint8Array(0),
      }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem, { workloadName: "" })),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
});

test("a pinned meshCaPem yields a specific-cluster verdict", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  const r = await verifyAttestation(bundle, nonce, policy(meshCaPem));
  assert.equal(r.trustClass, "specific-cluster");
  assert.equal(r.workload, undefined, "no workload pin, so the stamp is not read");
});

test("allowlist-only anchor: derives the CA from the served chain, deployment-class", async () => {
  const nonce = generateNonce();
  const leaf = await stampedLeaf(await stampFor("sglang-dev"));
  const { bundle } = await buildBundle(nonce, { leaf });
  const allowlist = await readAllowlistBytes();
  const r = await verifyAttestation(bundle, nonce, {
    measurements: DEMO_MEASUREMENTS,
    requireFreshness: false,
    allowlist,
  });
  assert.equal(r.trustClass, "deployment-class");
  assert.ok(r.workload);
  assert.equal(r.workload.name, "sglang-dev");
  assert.equal(r.workload.allowlistVersion, "7");
  assert.equal(r.workload.allowlistDigestHex, await allowlistDigestHex(allowlist));
  // The anchor really is the fixture CA — selected from the served chain by
  // the transcript commitment, not assumed.
  const { caDer } = await loadFixtures();
  assert.equal(r.cert.caSha256, await fingerprintSHA256(caDer));
});

test("both anchors together: specific-cluster plus the stamp checks", async () => {
  const nonce = generateNonce();
  const leaf = await stampedLeaf(await stampFor("sglang-dev"));
  const { bundle, meshCaPem } = await buildBundle(nonce, { leaf });
  const r = await verifyAttestation(
    bundle,
    nonce,
    policy(meshCaPem, { allowlist: await readAllowlistBytes(), workloadName: "sglang-dev" }),
  );
  assert.equal(r.trustClass, "specific-cluster");
  assert.equal(r.workload?.name, "sglang-dev");
});

test("derivation fails closed when the served chain carries no matching CA", async () => {
  const nonce = generateNonce();
  const leaf = await stampedLeaf(await stampFor("sglang-dev"));
  const { bundle } = await buildBundle(nonce, { leaf });
  // Serve the leaf alone: the proof commits the real CA, but nothing served
  // matches it, so there is no anchor to derive.
  bundle.cds_cert_pem = leaf.leafPem;
  await assert.rejects(
    async () =>
      verifyAttestation(bundle, nonce, {
        measurements: DEMO_MEASUREMENTS,
        requireFreshness: false,
        allowlist: await readAllowlistBytes(),
      }),
    (e: unknown) =>
      e instanceof C8sVerifyError &&
      e.code === "identity_binding" &&
      e.message.includes("cannot be derived"),
  );
});

// ---------------------------------------------------------------------------
// Workload policy on the chain-verified leaf
// ---------------------------------------------------------------------------

test("workload pin against an unstamped leaf fails with workload_not_attested", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem, { workloadName: "api" })),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "workload_not_attested",
  );
});

test("allowlist pin against an unstamped leaf fails with workload_not_attested", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  await assert.rejects(
    async () =>
      verifyAttestation(
        bundle,
        nonce,
        policy(meshCaPem, { allowlist: await readAllowlistBytes() }),
      ),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "workload_not_attested",
  );
});

test("a matching workloadName pin passes and surfaces the stamp", async () => {
  const nonce = generateNonce();
  // The golden-vector stamp: name "api", version "7", digest 0x11*32. With no
  // allowlist pinned the digest is not checked — there is nothing to check it
  // against.
  const leaf = await stampedLeaf(encodeMatchedWorkload("api", "7", new Uint8Array(32).fill(0x11)));
  const { bundle, meshCaPem } = await buildBundle(nonce, { leaf });
  const r = await verifyAttestation(bundle, nonce, policy(meshCaPem, { workloadName: "api" }));
  assert.equal(r.workload?.name, "api");
  assert.equal(r.workload?.allowlistDigestHex, "11".repeat(32));
});

test("a mismatched workloadName pin fails with workload_denied", async () => {
  const nonce = generateNonce();
  const leaf = await stampedLeaf(await stampFor("sglang-dev"));
  const { bundle, meshCaPem } = await buildBundle(nonce, { leaf });
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem, { workloadName: "sglang-kimi-k3" })),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "workload_denied",
  );
});

test("a stamped digest that is not the pinned bytes fails with allowlist_denied", async () => {
  const nonce = generateNonce();
  // Golden-vector digest (0x11*32) can never be SHA-256 of the fixture bytes.
  const leaf = await stampedLeaf(encodeMatchedWorkload("api", "7", new Uint8Array(32).fill(0x11)));
  const { bundle, meshCaPem } = await buildBundle(nonce, { leaf });
  // workloadName would ALSO mismatch — the digest check must come first, so a
  // policy-skew failure is reported as such rather than as a name mismatch.
  await assert.rejects(
    async () =>
      verifyAttestation(
        bundle,
        nonce,
        policy(meshCaPem, { allowlist: await readAllowlistBytes(), workloadName: "other" }),
      ),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "allowlist_denied",
  );
});

test("a stamped name absent from the pinned document fails with workload_unresolved", async () => {
  const nonce = generateNonce();
  // Digest matches the pinned bytes; the name resolves nowhere in them. The
  // name-pin check passes first ("api" == "api"), so what fails is resolution.
  const leaf = await stampedLeaf(await stampFor("api"));
  const { bundle, meshCaPem } = await buildBundle(nonce, { leaf });
  await assert.rejects(
    async () =>
      verifyAttestation(
        bundle,
        nonce,
        policy(meshCaPem, { allowlist: await readAllowlistBytes(), workloadName: "api" }),
      ),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "workload_unresolved",
  );
});

test("a malformed stamp fails with workload_invalid, never reads as absent", async () => {
  const nonce = generateNonce();
  const damaged = new Uint8Array([...(await stampFor("sglang-dev")), 0x00]); // trailing byte
  const leaf = await stampedLeaf(damaged);
  const { bundle, meshCaPem } = await buildBundle(nonce, { leaf });
  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem, { workloadName: "sglang-dev" })),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "workload_invalid",
  );
});

// ---------------------------------------------------------------------------
// TDX measurement-policy completeness: the mrtd+rtmr1+rtmr2 image tuple
// ---------------------------------------------------------------------------

// MRTD covers only the TDVF firmware; the guest kernel and rootfs live in
// RTMR[1]/RTMR[2], so an image pin is only complete as the tdxImage tuple. A
// deployment-class verdict rests entirely on the measurement policy, so an
// MRTD-only policy is rejected there; with a pinned mesh CA cluster identity
// does not depend on the measurement pins, so the gap is a prominent warning.

const TDX_MRTD =
  "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1";
// The image tuple of the TD that produced the recorded fixture (RTMR[1] =
// guest kernel, RTMR[2] = guest rootfs).
const TDX_IMAGE = {
  mrtd: TDX_MRTD,
  rtmr1:
    "e0aaa1f273b80e1e4e5032b789f34fc3f78c88719717b266cb3152aa4bc6490f13fe3a9cea8e00b48a3719074e06c05a",
  rtmr2:
    "15d4452b636e411b9c85a9fdb8b9c75b8ac7abb7eafe846aed987495a8b44b3b22a9681521961b382bdfe170efc4adeb",
};

async function tdxEvidence() {
  const { evidence } = JSON.parse(await readFile(join(FIX, "tdx-bundle.json"), "utf8"));
  return evidence;
}

test("TDX deployment-class verdict rejects an MRTD-only measurement policy", async () => {
  const nonce = generateNonce();
  const leaf = await stampedLeaf(await stampFor("sglang-dev"));
  const { bundle } = await buildBundle(nonce, {
    leaf,
    evidence: await tdxEvidence(),
    platform: "tdx",
  });
  await assert.rejects(
    async () =>
      verifyAttestation(bundle, nonce, {
        measurements: [TDX_MRTD],
        platform: "tdx",
        requireFreshness: false,
        allowlist: await readAllowlistBytes(),
      }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "measurement_incomplete",
  );
});

test("TDX deployment-class verdict passes with the full image tuple pinned", async () => {
  const nonce = generateNonce();
  const leaf = await stampedLeaf(await stampFor("sglang-dev"));
  const { bundle } = await buildBundle(nonce, {
    leaf,
    evidence: await tdxEvidence(),
    platform: "tdx",
  });
  // The tuple's MRTD joins the measurement allowlist, so the explicit list
  // may pin a different (e.g. previous) image alongside it.
  const r = await verifyAttestation(bundle, nonce, {
    measurements: ["ab".repeat(48)],
    platform: "tdx",
    requireFreshness: false,
    tdxImage: TDX_IMAGE,
    allowlist: await readAllowlistBytes(),
  });
  assert.equal(r.trustClass, "deployment-class");
  assert.equal(r.measurement, TDX_MRTD);
  assert.deepEqual(r.rtmrsPinned, [`1:${TDX_IMAGE.rtmr1}`, `2:${TDX_IMAGE.rtmr2}`]);
  assert.ok(!r.warnings.some((w) => w.includes("not platform-complete")));
});

test("a wrong RTMR[1] fails the tuple with rtmr_denied even though MRTD matches", async () => {
  const nonce = generateNonce();
  const leaf = await stampedLeaf(await stampFor("sglang-dev"));
  const { bundle } = await buildBundle(nonce, {
    leaf,
    evidence: await tdxEvidence(),
    platform: "tdx",
  });
  await assert.rejects(
    async () =>
      verifyAttestation(bundle, nonce, {
        measurements: [TDX_MRTD],
        platform: "tdx",
        requireFreshness: false,
        tdxImage: { ...TDX_IMAGE, rtmr1: "ff".repeat(48) },
        allowlist: await readAllowlistBytes(),
      }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "rtmr_denied",
  );
});

test("TDX specific-cluster verdict without the tuple keeps the prominent warning", async () => {
  const nonce = generateNonce();
  const leaf = await stampedLeaf(await stampFor("sglang-dev"));
  const { bundle, meshCaPem } = await buildBundle(nonce, {
    leaf,
    evidence: await tdxEvidence(),
    platform: "tdx",
  });
  const r = await verifyAttestation(bundle, nonce, {
    measurements: [TDX_MRTD],
    platform: "tdx",
    requireFreshness: false,
    meshCaPem,
  });
  assert.equal(r.trustClass, "specific-cluster");
  assert.ok(
    r.warnings.some((w) => w.includes("not platform-complete")),
    `expected the platform-completeness warning, got: ${JSON.stringify(r.warnings)}`,
  );
  assert.equal(r.rtmrsPinned, undefined);

  // With the tuple pinned the warning goes away.
  const nonce2 = generateNonce();
  const { bundle: bundle2, meshCaPem: meshCaPem2 } = await buildBundle(nonce2, {
    leaf,
    evidence: await tdxEvidence(),
    platform: "tdx",
  });
  const r2 = await verifyAttestation(bundle2, nonce2, {
    measurements: [TDX_MRTD],
    platform: "tdx",
    requireFreshness: false,
    tdxImage: TDX_IMAGE,
    meshCaPem: meshCaPem2,
  });
  assert.ok(!r2.warnings.some((w) => w.includes("not platform-complete")));
});

// SNP is unaffected by the completeness rule (its launch measurement already
// covers the full image), and — mirroring expectedRtmr3 — an image tuple
// combined with a non-TDX platform is a policy error, never silently ignored.
test("SNP verdicts are unaffected, and a tuple on SNP is refused", async () => {
  const nonce = generateNonce();
  const { bundle, meshCaPem } = await buildBundle(nonce);
  const r = await verifyAttestation(bundle, nonce, policy(meshCaPem));
  assert.equal(r.ok, true);
  assert.equal(r.rtmrsPinned, undefined);
  assert.ok(!r.warnings.some((w) => w.includes("not platform-complete")));

  await assert.rejects(
    () => verifyAttestation(bundle, nonce, policy(meshCaPem, { tdxImage: TDX_IMAGE })),
    (e: unknown) =>
      e instanceof C8sVerifyError &&
      e.code === "invalid_request" &&
      e.message.includes('tdxImage requires platform "tdx"'),
  );
});

// The tuple is all-or-nothing at the policy boundary too: verifyAttestation
// refuses a partial or non-lowercase tuple before touching the evidence.
test("verifyAttestation refuses a partial or malformed tuple with invalid_request", async () => {
  const nonce = generateNonce();
  const leaf = await stampedLeaf(await stampFor("sglang-dev"));
  const { bundle, meshCaPem } = await buildBundle(nonce, {
    leaf,
    evidence: await tdxEvidence(),
    platform: "tdx",
  });
  for (const bad of [
    { mrtd: TDX_IMAGE.mrtd, rtmr1: TDX_IMAGE.rtmr1 }, // missing rtmr2
    { ...TDX_IMAGE, rtmr2: TDX_IMAGE.rtmr2.toUpperCase() },
    { ...TDX_IMAGE, mrtd: TDX_IMAGE.mrtd.slice(0, 95) },
  ]) {
    await assert.rejects(
      () =>
        verifyAttestation(bundle, nonce, {
          measurements: [TDX_MRTD],
          platform: "tdx",
          requireFreshness: false,
          tdxImage: bad as unknown as typeof TDX_IMAGE,
          meshCaPem,
        }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      `tuple ${JSON.stringify(bad).slice(0, 60)}… must be refused`,
    );
  }
});
