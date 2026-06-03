// Portable loader for the attestation-rs WASM verifier (wasm-bindgen --target web).
// Works in the browser (fetch the .wasm by URL) and in Node (read the file bytes,
// since Node's fetch does not support file:// URLs). Initialised once and cached.

import initWasm, { verify_snp } from "../wasm/attestation_wasm.js";

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
 * Call the SNP verifier. Initialises the module on first use.
 * @param {string} evidenceJson
 * @param {string} generation  "milan" | "genoa" | "turin"
 * @param {Uint8Array} [expectedReportData]
 * @returns {Promise<string>} verification result JSON (or throws on HW/chain failure)
 */
export async function verifySnp(evidenceJson, generation, expectedReportData) {
  await initVerifier();
  return verify_snp(evidenceJson, generation, expectedReportData);
}
