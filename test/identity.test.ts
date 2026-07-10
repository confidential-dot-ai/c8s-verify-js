import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  certificateHashBase64Url,
  IDENTITY_PROOF_ALGORITHM,
  identityProofMessage,
  identityTranscriptHash,
  verifyMeshIdentityProof,
  type MeshIdentityProof,
} from "../src/identity.js";
import { decodePEM } from "../src/pem.js";
import { parseCertificate } from "../src/x509.js";
import { bytesToBase64Url, bytesToHex } from "../src/base64.js";
import { C8sVerifyError } from "../src/errors.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "demo", "fixtures");

async function fixtureProof(): Promise<{
  proof: MeshIdentityProof;
  transcript: Uint8Array;
  leaf: ReturnType<typeof parseCertificate>;
  ca: ReturnType<typeof parseCertificate>;
}> {
  const [leafPem, caPem, leafKey] = await Promise.all([
    readFile(join(FIX, "cds-leaf.crt"), "utf8"),
    readFile(join(FIX, "mesh-ca.crt"), "utf8"),
    readFile(join(FIX, "cds-leaf.key"), "utf8"),
  ]);
  const leaf = parseCertificate(decodePEM(leafPem, "CERTIFICATE")[0]);
  const ca = parseCertificate(decodePEM(caPem, "CERTIFICATE")[0]);
  const transcript = await identityTranscriptHash(
    { x25519: new Uint8Array(32).fill(0x11), mlkem768: new Uint8Array(1184).fill(0x22) },
    new Uint8Array(32).fill(0x33),
    leaf.der,
    ca.der,
  );
  const signature = sign("sha384", identityProofMessage(transcript), {
    key: leafKey,
    dsaEncoding: "der",
  });
  return {
    transcript,
    leaf,
    ca,
    proof: {
      algorithm: IDENTITY_PROOF_ALGORITHM,
      leaf_sha256: await certificateHashBase64Url(leaf.der),
      mesh_ca_sha256: await certificateHashBase64Url(ca.der),
      signature: bytesToBase64Url(signature),
    },
  };
}

test("v2 transcript matches the Go cross-language vector", async () => {
  const transcript = await identityTranscriptHash(
    { x25519: new Uint8Array(32).fill(0x11), mlkem768: new Uint8Array(1184).fill(0x22) },
    new Uint8Array(32).fill(0x33),
    new TextEncoder().encode("leaf-der"),
    new TextEncoder().encode("ca-der"),
  );
  assert.equal(
    bytesToHex(transcript),
    "f6f10a6a95249c535ae3210248fa2c2fbe214744edffe53809795a877840731728175a35dd8091a1e15263190032b3f2",
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
