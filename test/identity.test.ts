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
    new Uint8Array(32).fill(0x99),
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
    new Uint8Array(32).fill(0x99),
  );
  assert.equal(
    bytesToHex(transcript),
    "90555fc4be6af7df26403a39bd747b42504bcca774d9f3d40a2028058631b4011c3efa8f7d615da588de1cc4a38fbf7f",
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
    new Uint8Array(32).fill(0x99),
  ] as const;
  const acme = await identityTranscriptHash("acme", ...args);
  assert.equal(
    bytesToHex(acme),
    "48e29993e1c03a7fb735dd91d1cbc454c00f39a1fb83c77446c5cb65c0fb12b7cbec2514ea29c2fd618c76d12611e109",
  );
  await assert.rejects(
    () => identityTranscriptHash("", ...args),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
  );
});

test("the route digest is committed and must be 32 bytes", async () => {
  const fields = [
    new Uint8Array(1216).fill(0x11),
    new Uint8Array(1120).fill(0x22),
    new Uint8Array(16).fill(0x44),
    new Uint8Array(32).fill(0x33),
    new TextEncoder().encode("leaf-der"),
    new TextEncoder().encode("ca-der"),
  ] as const;
  const base = await identityTranscriptHash("cds", ...fields, new Uint8Array(32).fill(0x99));
  const other = await identityTranscriptHash("cds", ...fields, new Uint8Array(32).fill(0x98));
  assert.notEqual(bytesToHex(other), bytesToHex(base));
  for (const length of [0, 31, 33]) {
    await assert.rejects(
      () => identityTranscriptHash("cds", ...fields, new Uint8Array(length)),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "identity_binding",
      `route digest of ${length} bytes`,
    );
  }
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
