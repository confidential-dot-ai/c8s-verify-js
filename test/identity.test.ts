import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";

import {
  identityTranscriptHash,
  verifyMeshIdentityProof,
  type MeshIdentityProof,
} from "../src/identity.js";
import { decodePEM } from "../src/pem.js";
import { parseCertificate } from "../src/x509.js";
import { bytesToBase64Url, bytesToHex } from "../src/base64.js";
import { C8sVerifyError } from "../src/errors.js";
import { stateDigest } from "../src/rollout.js";
import { mintIdentityProof } from "./mint-identity.js";
import { loadFixtures } from "./helpers.js";

async function fixtureProof(): Promise<{
  proof: MeshIdentityProof;
  transcript: Uint8Array;
  leaf: ReturnType<typeof parseCertificate>;
  ca: ReturnType<typeof parseCertificate>;
}> {
  const { leafPem, meshCaPem, leafKeyPem } = await loadFixtures();
  const leaf = parseCertificate(decodePEM(leafPem, "CERTIFICATE")[0]);
  const ca = parseCertificate(decodePEM(meshCaPem, "CERTIFICATE")[0]);
  const { transcript, proof } = await mintIdentityProof(
    "cds",
    new Uint8Array(1216).fill(0x11),
    new Uint8Array(1120).fill(0x22),
    new Uint8Array(16).fill(0x44),
    new Uint8Array(32).fill(0x33),
    leaf.der,
    ca.der,
    leafKeyPem,
  );
  return { transcript, leaf, ca, proof };
}

test("v1 transcript matches the Go cross-language vector", async () => {
  const transcript = await identityTranscriptHash(
    "cds",
    new Uint8Array(1216).fill(0x11),
    new Uint8Array(1120).fill(0x22),
    new Uint8Array(16).fill(0x44),
    new Uint8Array(32).fill(0x33),
    new TextEncoder().encode("leaf-der"),
    new TextEncoder().encode("ca-der"),
  );
  assert.equal(
    bytesToHex(transcript),
    "8f534c54dce6062fbf66e7f9b4317ab98b736786c72f101de5df3b4f1951e090325fccc6f700083b03a132a07d40c9df",
  );
});

test("the rollout state digest is committed last", async () => {
  const args = [
    "cds",
    new Uint8Array(1216).fill(0x11),
    new Uint8Array(1120).fill(0x22),
    new Uint8Array(16).fill(0x44),
    new Uint8Array(32).fill(0x33),
    new TextEncoder().encode("leaf-der"),
    new TextEncoder().encode("ca-der"),
  ] as const;
  const withState = await identityTranscriptHash(
    ...args,
    await stateDigest(new TextEncoder().encode('{"bound":[]}')),
  );
  assert.equal(
    bytesToHex(withState),
    "050a0fc785c1fdc2a4b04ed9e6a31e03a6581ea8f8509b13118b11f5ec8aa97a20beae8c8c0f8032f834e20c81a73353",
  );
  await assert.rejects(
    () => identityTranscriptHash(...args, new Uint8Array(1)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("the front-door mode is committed: another mode changes the transcript", async () => {
  const args = [
    new Uint8Array(1216).fill(0x11),
    new Uint8Array(1120).fill(0x22),
    new Uint8Array(16).fill(0x44),
    new Uint8Array(32).fill(0x33),
    new TextEncoder().encode("leaf-der"),
    new TextEncoder().encode("ca-der"),
  ] as const;
  const acme = await identityTranscriptHash("acme", ...args);
  assert.equal(
    bytesToHex(acme),
    "37c590018d74c3107c8ff7258888469cdc34e353844b6ec2c77a0f25c3e0f7095e252b7f1b72201e1c48983599a99845",
  );
  await assert.rejects(
    () => identityTranscriptHash("", ...args),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("verifies proof of possession by the committed mesh leaf", async () => {
  const { proof, transcript, leaf, ca } = await fixtureProof();
  await verifyMeshIdentityProof(proof, transcript, leaf, ca);
});

test("rejects a copied public leaf signed by an attacker key", async () => {
  const { proof, transcript, leaf, ca } = await fixtureProof();
  const attacker = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const forged = sign("sha384", transcript, {
    key: attacker.privateKey,
    dsaEncoding: "der",
  });
  await assert.rejects(
    () =>
      verifyMeshIdentityProof(
        { ...proof, signature: bytesToBase64Url(forged) },
        transcript,
        leaf,
        ca,
      ),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("rejects session-key substitution after the leaf signs", async () => {
  const { proof, transcript, leaf, ca } = await fixtureProof();
  const substituted = new Uint8Array(transcript);
  substituted[0] ^= 0xff;
  await assert.rejects(
    () => verifyMeshIdentityProof(proof, substituted, leaf, ca),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("rejects a CA fingerprint outside the proof", async () => {
  const { proof, transcript, leaf, ca } = await fixtureProof();
  const wrong = { ...proof, mesh_ca_sha256: bytesToBase64Url(new Uint8Array(32).fill(0x44)) };
  await assert.rejects(
    () => verifyMeshIdentityProof(wrong, transcript, leaf, ca),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});
