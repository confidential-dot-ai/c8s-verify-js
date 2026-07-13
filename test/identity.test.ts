import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";

import {
  identityProofMessage,
  identityTranscriptHash,
  verifyMeshIdentityProof,
  type MeshIdentityProof,
} from "../src/identity.js";
import { decodePEM } from "../src/pem.js";
import { parseCertificate } from "../src/x509.js";
import { bytesToBase64Url, bytesToHex } from "../src/base64.js";
import { C8sVerifyError } from "../src/errors.js";
import { mintIdentityProof } from "../demo/mint-identity.js";
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
    { x25519: new Uint8Array(32).fill(0x11), mlkem768: new Uint8Array(1184).fill(0x22) },
    new Uint8Array(32).fill(0x33),
    leaf.der,
    ca.der,
    leafKeyPem,
  );
  return { transcript, leaf, ca, proof };
}

test("v1 transcript matches the Go cross-language vector", async () => {
  const transcript = await identityTranscriptHash(
    { x25519: new Uint8Array(32).fill(0x11), mlkem768: new Uint8Array(1184).fill(0x22) },
    new Uint8Array(32).fill(0x33),
    new TextEncoder().encode("leaf-der"),
    new TextEncoder().encode("ca-der"),
  );
  assert.equal(
    bytesToHex(transcript),
    "4ad70e2d4cdb8044527d82886a35ebdaee1f250883f2a789acea681bff8acc62401c4ccbfa633a02521af62f2f2e0d0f",
  );
});

test("verifies proof of possession by the committed mesh leaf", async () => {
  const { proof, transcript, leaf, ca } = await fixtureProof();
  await verifyMeshIdentityProof(proof, transcript, leaf, ca);
});

test("rejects a copied public leaf signed by an attacker key", async () => {
  const { proof, transcript, leaf, ca } = await fixtureProof();
  const attacker = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const forged = sign("sha384", identityProofMessage(transcript), {
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
