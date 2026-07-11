// Shared test helpers: load fixtures and build attestation bundles the way the
// mock LB does, so verification tests can run without an HTTP server.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  generateServerHybridKey,
  type ServerKeys,
  type PublicHalves,
} from "../src/keyagreement.js";
import { bytesToBase64Url, base64ToBytes, bytesToBase64 } from "../src/base64.js";
import type { AttestationBundle } from "../src/verify.js";
import type { Evidence } from "../src/hcl.js";
import { decodePEM } from "../src/pem.js";
import { mintIdentityProof } from "../demo/mint-identity.js";

// Run from source via tsx (see package.json); this file lives at test/, so the
// repo root is one directory up (test/ -> repo root).
const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "demo", "fixtures");

export interface Fixtures {
  snpEvidence: Evidence;
  meshCaPem: string;
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
    const [evidenceJson, meshCaPem, leafPem, leafKeyPem] = await Promise.all([
      readFile(join(FIX, "snp-evidence-genoa.json"), "utf8"),
      readFile(join(FIX, "mesh-ca.crt"), "utf8"),
      readFile(join(FIX, "cds-leaf.crt"), "utf8"),
      readFile(join(FIX, "cds-leaf.key"), "utf8"),
    ]);
    const evidence = JSON.parse(evidenceJson);
    return {
      snpEvidence: (evidence.evidence ?? evidence) as Evidence,
      meshCaPem,
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
  priv: ServerKeys;
  pub: PublicHalves;
  meshCaPem: string;
  /** v2 transcript hash; set when built with identity: true. */
  transcript?: Uint8Array;
}

/**
 * Build an attestation bundle bound to `nonce`, mirroring the mock LB.
 */
export async function buildBundle(
  nonce: Uint8Array,
  opts: { tamperReport?: boolean; identity?: boolean } = {},
): Promise<BuiltBundle> {
  const { snpEvidence, meshCaPem, leafPem, leafKeyPem, leafDer, caDer } = await loadFixtures();
  const { priv, pub } = await generateServerHybridKey();

  const evidence = JSON.parse(JSON.stringify(snpEvidence));
  if (opts.tamperReport) {
    const rep = base64ToBytes(evidence.attestation_report);
    rep[200] ^= 0x01;
    evidence.attestation_report = bytesToBase64(rep);
  }

  const bundle: AttestationBundle = {
    version: "c8s-verify/v1",
    platform: "snp",
    generation: "genoa",
    nonce: bytesToBase64Url(nonce),
    evidence,
    cds_cert_pem: leafPem.trim() + "\n" + meshCaPem.trim() + "\n",
    session_pubkey: {
      x25519: bytesToBase64Url(pub.x25519),
      mlkem768: bytesToBase64Url(pub.mlkem768),
    },
  };
  if (opts.identity) {
    const minted = await mintIdentityProof(pub, nonce, leafDer, caDer, leafKeyPem);
    Object.assign(bundle, minted.bundleFields);
    return { bundle, priv, pub, meshCaPem, transcript: minted.transcript };
  }
  return { bundle, priv, pub, meshCaPem };
}
