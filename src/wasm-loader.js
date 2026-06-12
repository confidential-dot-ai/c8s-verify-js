// Portable loader for the attestation-rs WASM verifier (wasm-bindgen --target web).
// Works in the browser (fetch the .wasm by URL) and in Node (read the file bytes,
// since Node's fetch does not support file:// URLs). Initialised once and cached.

import initWasm, { verify_snp, verify_az_snp } from "../wasm/attestation_wasm.js";
import { toWasmEvidence } from "./hcl.js";

const WASM_URL = new URL("../wasm/attestation_wasm_bg.wasm", import.meta.url);

/** @type {Promise<void>|null} */
let initialised = null;

const isNode =
  typeof process !== "undefined" && process.versions != null && process.versions.node != null;

/**
 * Initialise the WASM module exactly once. Optionally pass an explicit init input
 * (BufferSource, URL, Response, or WebAssembly.Module) to override discovery.
 * @param {any} [input]
 * @returns {Promise<void>}
 */
export function initVerifier(input) {
  if (initialised) return initialised;
  initialised = (async () => {
    if (input !== undefined) {
      await initWasm({ module_or_path: input });
      return;
    }
    if (isNode) {
      const { readFile } = await import("node:fs/promises");
      const bytes = await readFile(WASM_URL);
      await initWasm({ module_or_path: bytes });
    } else {
      await initWasm({ module_or_path: WASM_URL });
    }
  })();
  return initialised;
}

/**
 * Call the SNP verifier. Initialises the module on first use. Accepts both
 * bare SNP evidence and az-snp (Azure HCL-wrapped) evidence; the latter is
 * unwrapped to the raw SNP report the WASM verifier understands.
 * @param {string} evidenceJson
 * @param {string} generation  "milan" | "genoa" | "turin"
 * @param {Uint8Array} [expectedReportData]
 * @returns {Promise<string>} verification result JSON (or throws on HW/chain failure)
 */
export async function verifySnp(evidenceJson, generation, expectedReportData) {
  await initVerifier();
  const evidence = toWasmEvidence(JSON.parse(evidenceJson));
  return verify_snp(JSON.stringify(evidence), generation, expectedReportData);
}

/**
 * Call the az-snp verifier: full Azure SEV-SNP verification including the vTPM
 * quote. Unlike {@link verifySnp}, the evidence is NOT unwrapped to a bare SNP
 * report — the HCL report, VCEK, and TPM quote are all verified together. The
 * freshness anchor (`expectedReportData`) is checked against the TPM quote's
 * extraData, not the SNP report_data (which instead binds the vTPM AK).
 *
 * The processor generation is auto-detected from the report CPUID, so no
 * generation argument is needed.
 *
 * @param {string} evidenceJson  az-snp evidence: { version, tpm_quote, hcl_report, vcek }
 * @param {Uint8Array} [expectedReportData]  raw bytes the TPM quote extraData must equal
 * @param {Uint8Array} [expectedInitDataHash]  32-byte hash to bind against PCR[8]
 * @returns {Promise<string>} verification result JSON (or throws on any failure)
 */
export async function verifyAzSnp(evidenceJson, expectedReportData, expectedInitDataHash) {
  await initVerifier();
  return verify_az_snp(evidenceJson, expectedReportData, expectedInitDataHash);
}
