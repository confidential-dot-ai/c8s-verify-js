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

// Run from source via tsx (see package.json); this file lives at test/, so the
// repo root is one directory up (test/ -> repo root).
const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "demo", "fixtures");

export interface Fixtures {
  snpEvidence: Evidence;
  meshCaPem: string;
  leafPem: string;
}

export async function loadFixtures(): Promise<Fixtures> {
  const evidence = JSON.parse(await readFile(join(FIX, "snp-evidence-genoa.json"), "utf8"));
  return {
    snpEvidence: (evidence.evidence ?? evidence) as Evidence,
    meshCaPem: await readFile(join(FIX, "mesh-ca.crt"), "utf8"),
    leafPem: await readFile(join(FIX, "cds-leaf.crt"), "utf8"),
  };
}

export interface BuiltBundle {
  bundle: AttestationBundle;
  priv: ServerKeys;
  pub: PublicHalves;
  meshCaPem: string;
}

/**
 * Build an attestation bundle bound to `nonce`, mirroring the mock LB.
 */
export async function buildBundle(
  nonce: Uint8Array,
  opts: { tamperReport?: boolean } = {},
): Promise<BuiltBundle> {
  const { snpEvidence, meshCaPem, leafPem } = await loadFixtures();
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
  return { bundle, priv, pub, meshCaPem };
}
