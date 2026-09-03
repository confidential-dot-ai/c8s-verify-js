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
    "003e433637125a49cb2136a5e8148f6de5fd16c43caa11bcc79e49865da4c5e32625e54f7a9a33476954eb7f745fcae3",
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
    "594e10d4d384724391d9fa215d90e2169029aa47f4091d9155b9970d0ebb38a4112518dce87db42cb837bbc71986c81a",
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
