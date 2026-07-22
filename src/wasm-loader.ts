// Portable loader for the attestation-rs WASM verifier (wasm-bindgen --target web).
// Works in the browser (fetch the .wasm by URL) and in Node (read the file bytes,
// since Node's fetch does not support file:// URLs). Initialised once and cached.
//
// All verification goes through the single generic `verify` export: platform
// dispatch, quote/chain cryptography, debug-policy enforcement, and the
// per-platform freshness semantics (hardware quote report_data vs vTPM
// extraData) all live in the Rust core. This module is a thin transport shim;
// the per-platform helpers below are legacy conveniences over the same call.

import initWasm, { verify, type InitInput } from "./wasm/attestation_wasm.js";
import { toWasmEvidence, type Evidence } from "./hcl.js";

const WASM_URL = new URL("./wasm/attestation_wasm_bg.wasm", import.meta.url);

let initialised: Promise<void> | null = null;

const isNode = typeof process !== "undefined" && process.versions?.node != null;

/**
 * Initialise the WASM module exactly once. Optionally pass an explicit init input
 * (BufferSource, URL, Response, or WebAssembly.Module) to override discovery.
 */
export function initVerifier(input?: InitInput): Promise<void> {
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
 * Verify attestation evidence for a caller-asserted platform — the one entry
 * point every platform goes through.
 *
 * Builds the core's self-describing `{ platform, evidence }` envelope and calls
 * the WASM `verify` export, which dispatches to the matching platform verifier
 * in Rust: quote/report signature, cert chain to the bundled AMD/Intel roots,
 * debug-guest rejection (never an opt-in here), and — where the evidence
 * carries one — CC event log replay. Collateral checks (CRL, TCB status, QE
 * identity) need network access and are skipped in WASM: `collateral_verified`
 * is always `false` in the result.
 *
 * `platform` MUST be the platform the caller expects, never a value read from
 * the server's response — the platform tag selects the verification path, so
 * letting the peer choose it would let a malicious peer pick the weakest one.
 * Callers should additionally compare the result's `platform` field against
 * the same expectation.
 *
 * The freshness anchor (`expectedReportData`) is bound where each platform
 * defines it — the hardware quote's `report_data` for bare-metal platforms
 * (`snp`, `tdx`, `gcp-snp`, `gcp-tdx`), the vTPM quote's `extraData` for the
 * Azure vTPM platforms (`az-snp`, `az-tdx`) — and a supplied-but-mismatched
 * anchor fails closed (throws) in the core, uniformly across platforms.
 *
 * @param platform caller-asserted platform tag ("snp" | "tdx" | "az-snp" |
 *   "az-tdx" | "gcp-snp" | "gcp-tdx")
 * @param evidence that platform's evidence payload, verbatim
 * @param expectedReportData raw bytes the platform's freshness anchor must equal
 * @param expectedInitDataHash bytes bound against the platform's init-data
 *   field (SNP HOST_DATA / TDX MRCONFIGID / vTPM PCR[8])
 * @returns verification result JSON (or throws on any failure)
 */
export async function verifyEnvelope(
  platform: string,
  evidence: Evidence,
  expectedReportData?: Uint8Array,
  expectedInitDataHash?: Uint8Array,
): Promise<string> {
  await initVerifier();
  return verify(JSON.stringify({ platform, evidence }), expectedReportData, expectedInitDataHash);
}

/**
 * Verify bare SEV-SNP evidence. Accepts both bare SNP evidence and az-snp
 * (Azure HCL-wrapped) evidence; the latter is unwrapped to the raw SNP report.
 *
 * @deprecated Use {@link verifyEnvelope} with platform `"snp"`. The
 * `generation` argument is ignored: the core auto-detects the processor
 * generation from the report's CPUID fields (v3+ reports).
 */
export async function verifySnp(
  evidence: Evidence,
  _generation: string,
  expectedReportData?: Uint8Array,
): Promise<string> {
  return verifyEnvelope("snp", toWasmEvidence(evidence), expectedReportData);
}

/**
 * Verify Azure SEV-SNP (az-snp) vTPM evidence (HCL report + vTPM quote + SNP
 * report, verified together; the anchor binds the vTPM quote's extraData).
 *
 * @deprecated Use {@link verifyEnvelope} with platform `"az-snp"`.
 */
export async function verifyAzSnp(
  evidenceJson: string,
  expectedReportData?: Uint8Array,
  expectedInitDataHash?: Uint8Array,
): Promise<string> {
  return verifyEnvelope(
    "az-snp",
    JSON.parse(evidenceJson) as Evidence,
    expectedReportData,
    expectedInitDataHash,
  );
}

/**
 * Verify Azure TDX (az-tdx) vTPM evidence (HCL report + vTPM quote + TD quote,
 * verified together; the anchor binds the vTPM quote's extraData).
 *
 * @deprecated Use {@link verifyEnvelope} with platform `"az-tdx"`.
 */
export async function verifyAzTdx(
  evidenceJson: string,
  expectedReportData?: Uint8Array,
  expectedInitDataHash?: Uint8Array,
): Promise<string> {
  return verifyEnvelope(
    "az-tdx",
    JSON.parse(evidenceJson) as Evidence,
    expectedReportData,
    expectedInitDataHash,
  );
}

/**
 * Verify bare-metal Intel TDX (tdx) DCAP evidence (TD quote + optional CC
 * event log replayed against RTMR0-3; the anchor binds the quote's report_data).
 *
 * @deprecated Use {@link verifyEnvelope} with platform `"tdx"`.
 */
export async function verifyTdx(
  evidenceJson: string,
  expectedReportData?: Uint8Array,
  expectedInitDataHash?: Uint8Array,
): Promise<string> {
  return verifyEnvelope(
    "tdx",
    JSON.parse(evidenceJson) as Evidence,
    expectedReportData,
    expectedInitDataHash,
  );
}
