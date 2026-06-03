import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifySnp } from "../src/wasm-loader.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// A recorded Azure SEV-SNP (az-snp) attestation: an HCL report wrapping the raw
// SNP report, plus a TPM quote and the VCEK. Verified end-to-end through the
// JS -> WASM boundary (`verifySnp`), the same path `verifyAttestation` uses.
test("verifies a recorded az-snp attestation through the WASM verifier", async () => {
  const att = JSON.parse(await readFile(join(FIX, "az-snp-attestation.json"), "utf8"));

  // VCEK subject is SEV-Milan / HwID "Milan-B0" -> Milan generation.
  const out = await verifySnp(JSON.stringify(att.evidence), "milan");
  const result = JSON.parse(out);

  assert.equal(result.signature_valid, true, "hardware signature must verify against the VCEK chain");
});
