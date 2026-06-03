import { test } from "node:test";
import assert from "node:assert/strict";

import { decodePEM } from "../src/pem.js";
import { parseCertificate, verifyCertChain, verifySignedBy } from "../src/x509.js";
import { C8sVerifyError } from "../src/errors.js";
import { loadFixtures } from "./helpers.js";

test("parses the demo mesh CA and leaf certs", async () => {
  const { meshCaPem, leafPem } = await loadFixtures();
  const ca = parseCertificate(decodePEM(meshCaPem)[0]);
  const leaf = parseCertificate(decodePEM(leafPem)[0]);
  assert.equal(ca.subjectCN, "c8s-demo-mesh-ca");
  assert.equal(ca.spkiCurve, "P-384");
  assert.equal(leaf.subjectCN, "lb.demo.c8s.local");
  assert.equal(leaf.issuerCN, "c8s-demo-mesh-ca");
  assert.equal(leaf.spkiCurve, "P-256");
});

test("verifies the leaf chains to the mesh CA", async () => {
  const { meshCaPem, leafPem } = await loadFixtures();
  const { leaf, ca, leafSha256, caSha256 } = await verifyCertChain(
    decodePEM(leafPem)[0],
    decodePEM(meshCaPem)[0],
  );
  assert.equal(leaf.subjectCN, "lb.demo.c8s.local");
  assert.equal(ca.subjectCN, "c8s-demo-mesh-ca");
  assert.match(leafSha256, /^[0-9a-f]{64}$/);
  assert.match(caSha256, /^[0-9a-f]{64}$/);
});

test("rejects a tampered leaf signature", async () => {
  const { meshCaPem, leafPem } = await loadFixtures();
  const leafDer = decodePEM(leafPem)[0].slice();
  leafDer[leafDer.length - 1] ^= 0x01; // mangle last signature byte
  await assert.rejects(
    () => verifyCertChain(leafDer, decodePEM(meshCaPem)[0]),
    (e) => e instanceof C8sVerifyError && e.code === "cert_chain",
  );
});

test("rejects a leaf not signed by the given CA (self as issuer)", async () => {
  const { leafPem } = await loadFixtures();
  const leaf = parseCertificate(decodePEM(leafPem)[0]);
  // The leaf is P-256 but not self-signed; verifying it against itself must fail.
  await assert.rejects(
    () => verifySignedBy(leaf, leaf),
    (e) => e instanceof C8sVerifyError,
  );
});

test("rejects an expired certificate", async () => {
  const { meshCaPem, leafPem } = await loadFixtures();
  await assert.rejects(
    () => verifyCertChain(decodePEM(leafPem)[0], decodePEM(meshCaPem)[0], { at: new Date("2999-01-01") }),
    (e) => e instanceof C8sVerifyError && e.code === "invalid_cert",
  );
});

test("verifies a self-signed CA against itself", async () => {
  const { meshCaPem } = await loadFixtures();
  const caDer = decodePEM(meshCaPem)[0];
  await assert.doesNotReject(() => verifyCertChain(caDer, caDer));
});
