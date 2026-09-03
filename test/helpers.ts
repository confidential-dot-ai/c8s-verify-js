// Shared test helpers: load fixtures and build attestation bundles the way the
// mock LB does, so verification tests can run without an HTTP server.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { generateXWingKeyPair, xwingEncapsulate, type XWingKeyPair } from "../src/keyagreement.js";
import { bytesToBase64Url, base64ToBytes, bytesToBase64 } from "../src/base64.js";
import type { AttestationBundle } from "../src/verify.js";
import type { Evidence } from "../src/hcl.js";
import { decodePEM } from "../src/pem.js";
import { mintIdentityProof } from "./mint-identity.js";

// Run from source via tsx (see package.json); this file lives at test/, so the
// repo root is one directory up (test/ -> repo root).
const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "demo", "fixtures");

export interface Fixtures {
  snpEvidence: Evidence;
  meshCaPem: string;
  caKeyPem: string;
  leafPem: string;
  leafKeyPem: string;
  leafDer: Uint8Array;
  caDer: Uint8Array;
}

let fixturesPromise: Promise<Fixtures> | undefined;

/**
 * Load the recorded fixtures once per process; the files are immutable and
 * every consumer either treats them as read-only or deep-clones before
 * mutating (see buildBundle). A failed load clears the cache so the next
 * caller retries instead of replaying a stale rejection.
 */
export function loadFixtures(): Promise<Fixtures> {
  fixturesPromise ??= (async () => {
    const [evidenceJson, meshCaPem, caKeyPem, leafPem, leafKeyPem] = await Promise.all([
      readFile(join(FIX, "snp-evidence-genoa.json"), "utf8"),
      readFile(join(FIX, "mesh-ca.crt"), "utf8"),
      readFile(join(FIX, "mesh-ca.key"), "utf8"),
      readFile(join(FIX, "cds-leaf.crt"), "utf8"),
      readFile(join(FIX, "cds-leaf.key"), "utf8"),
    ]);
    const evidence = JSON.parse(evidenceJson);
    return {
      snpEvidence: (evidence.evidence ?? evidence) as Evidence,
      meshCaPem,
      caKeyPem,
      leafPem,
      leafKeyPem,
      leafDer: decodePEM(leafPem, "CERTIFICATE")[0],
      caDer: decodePEM(meshCaPem, "CERTIFICATE")[0],
    };
  })().catch((e: unknown) => {
    fixturesPromise = undefined;
    throw e;
  });
  return fixturesPromise;
}

export interface BuiltBundle {
  bundle: AttestationBundle;
  /** The client keypair whose ek the bundle echoes. */
  clientKeyPair: XWingKeyPair;
  /** The shared secret the server derived when encapsulating. */
  serverSharedSecret: Uint8Array;
  sessionId: Uint8Array;
  meshCaPem: string;
  transcript: Uint8Array;
}

/**
 * Build an attestation bundle for a client-first exchange bound to `nonce`,
 * mirroring the mock LB: generate the client keypair (unless given),
 * encapsulate to it, mint a session id, and commit everything in the
 * transcript. `opts.leaf` substitutes a different mesh leaf (e.g. one minted
 * with a matched-workload stamp via mint-cert.ts) for the fixture leaf; the
 * identity proof is minted with its key so the bundle stays internally
 * consistent.
 */
export async function buildBundle(
  nonce: Uint8Array,
  opts: {
    tamperReport?: boolean;
    leaf?: { leafPem: string; leafKeyPem: string };
    evidence?: Evidence;
    platform?: string;
    clientKeyPair?: XWingKeyPair;
  } = {},
): Promise<BuiltBundle> {
  const fixtures = await loadFixtures();
  const { snpEvidence, meshCaPem, caDer } = fixtures;
  const leafPem = opts.leaf?.leafPem ?? fixtures.leafPem;
  const leafKeyPem = opts.leaf?.leafKeyPem ?? fixtures.leafKeyPem;
  const leafDer = opts.leaf ? decodePEM(leafPem, "CERTIFICATE")[0] : fixtures.leafDer;
  const clientKeyPair = opts.clientKeyPair ?? (await generateXWingKeyPair());
  const { ct, sharedSecret } = await xwingEncapsulate(clientKeyPair.ek);
  const sessionId = crypto.getRandomValues(new Uint8Array(16));

  const evidence = JSON.parse(JSON.stringify(opts.evidence ?? snpEvidence));
  if (opts.tamperReport) {
    const rep = base64ToBytes(evidence.attestation_report);
    rep[200] ^= 0x01;
    evidence.attestation_report = bytesToBase64(rep);
  }

  const minted = await mintIdentityProof(
    clientKeyPair.ek,
    ct,
    sessionId,
    nonce,
    leafDer,
    caDer,
    leafKeyPem,
  );
  const bundle: AttestationBundle = {
    ...minted.bundleFields,
    platform: opts.platform ?? "snp",
    generation: "genoa",
    nonce: bytesToBase64Url(nonce),
    evidence,
    cds_cert_pem: leafPem.trim() + "\n" + meshCaPem.trim() + "\n",
    xwing_ek: bytesToBase64Url(clientKeyPair.ek),
    xwing_ct: bytesToBase64Url(ct),
    session_id: bytesToBase64Url(sessionId),
  };
  return {
    bundle,
    clientKeyPair,
    serverSharedSecret: sharedSecret,
    sessionId,
    meshCaPem,
    transcript: minted.transcript,
  };
}
