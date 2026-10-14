// Portable loader for the attestation-rs WASM verifier (wasm-bindgen --target web).
// Works in the browser (fetch the .wasm by URL) and in Node (read the file bytes,
// since Node's fetch does not support file:// URLs). Initialised once and cached.

import initWasm, {
  evaluate_snp,
  evaluate_az_snp,
  evaluate_az_tdx,
  evaluate_tdx,
  type InitInput,
} from "./wasm/attestation_wasm.js";
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
 * Call the SNP verifier. Initialises the module on first use. Accepts both
 * bare SNP evidence and az-snp (Azure HCL-wrapped) evidence; the latter is
 * unwrapped to the raw SNP report the WASM verifier understands.
 *
 * The verifier enforces the full endorsement-key policy (ARK → ASK/ASVK → VEK
 * chain against the bundled AMD roots, VEK validity period, VEK chip-id/TCB
 * cross-validation against the report, report signature); a failure there
 * throws. The rules are values in the result: VMPL and debug (`vmpl`,
 * `debug`), the optional minimum-TCB floor (`min_tcb_met`), the optional
 * `report_data` anchor (`report_data_match`) and, when `crlDer` carries the
 * AMD KDS CRL for the generation, revocation of the VEK's issuing ASK/ASVK
 * (`crl_ok`; `null` without a CRL). A CRL that cannot be parsed, is not
 * ARK-signed or is stale throws with a `CRL check:` prefix, and so does an
 * `expectedReportData` over 64 bytes (invalid params). `passed` is true only when every rule held.
 *
 * @param evidence bare SNP or az-snp evidence
 * @param generation "milan" | "genoa" | "turin"
 * @param expectedReportData raw bytes report_data must equal (`report_data_match`)
 * @param minTcbJson minimum TCB floor as SnpTcb JSON
 * @param crlDer DER AMD KDS CRL for the generation
 * @returns result JSON with `passed`; throws only when the evidence cannot be verified
 */
export async function evaluateSnp(
  evidence: Evidence,
  generation: string,
  expectedReportData?: Uint8Array,
  minTcbJson?: string,
  crlDer?: Uint8Array,
): Promise<string> {
  await initVerifier();
  return evaluate_snp(
    JSON.stringify(toWasmEvidence(evidence)),
    generation,
    expectedReportData,
    minTcbJson,
    crlDer,
  );
}

/**
 * Call the az-snp verifier: full Azure SEV-SNP verification including the vTPM
 * quote. Unlike {@link evaluateSnp}, the evidence is NOT unwrapped to a bare SNP
 * report — the HCL report, VCEK, and TPM quote are all verified together. The
 * freshness anchor (`expectedReportData`) is checked against the TPM quote's
 * extraData, not the SNP report_data (which instead binds the vTPM AK).
 *
 * The processor generation is auto-detected from the report CPUID, so no
 * generation argument is needed.
 *
 * `minTcbJson` and `crlDer` behave exactly as on {@link evaluateSnp}
 * (`min_tcb_met`, `crl_ok`).
 *
 * @param evidenceJson az-snp evidence: { version, tpm_quote, hcl_report, vcek }
 * @param expectedReportData raw bytes the TPM quote extraData must equal
 * @param expectedInitDataHash 32-byte hash to bind against PCR[8]
 * @param minTcbJson minimum TCB floor as SnpTcb JSON
 * @param crlDer DER AMD KDS CRL for the report's generation
 * @returns result JSON with `passed`; throws only when the evidence cannot be verified
 */
export async function evaluateAzSnp(
  evidenceJson: string,
  expectedReportData?: Uint8Array,
  expectedInitDataHash?: Uint8Array,
  minTcbJson?: string,
  crlDer?: Uint8Array,
): Promise<string> {
  await initVerifier();
  return evaluate_az_snp(
    evidenceJson,
    expectedReportData,
    expectedInitDataHash,
    minTcbJson,
    crlDer,
  );
}

/**
 * Call the az-tdx verifier: full Azure TDX verification. Like {@link evaluateAzSnp},
 * the evidence is passed through unwrapped — the HCL report, TD quote, and vTPM
 * quote are verified together. The freshness anchor (`expectedReportData`) is
 * checked against the TPM quote's extraData (the TD quote's report_data instead
 * binds the vTPM AK). The measurement surfaces as `claims.launch_digest` = hex(MRTD).
 *
 * The underlying WASM export is async (the shared az-tdx core is async for its
 * optional DCAP collateral provider, which is skipped here), so this awaits it.
 *
 * @param evidenceJson az-tdx evidence: { version, tpm_quote, hcl_report, td_quote }
 * @param expectedReportData raw bytes the TPM quote extraData must equal
 * @param expectedInitDataHash 32-byte hash to bind against PCR[8]
 * @returns result JSON with `passed`; throws only when the evidence cannot be verified
 */
export async function evaluateAzTdx(
  evidenceJson: string,
  expectedReportData?: Uint8Array,
  expectedInitDataHash?: Uint8Array,
): Promise<string> {
  await initVerifier();
  return evaluate_az_tdx(evidenceJson, expectedReportData, expectedInitDataHash);
}

/**
 * Call the bare-metal tdx verifier: direct Intel TDX DCAP verification with no
 * vTPM in the path. The TD quote signature and the full DCAP chain (PCK chain
 * to the pinned Intel SGX Root CA, QE report signature and binding) are
 * verified in WASM, debug TDs are rejected, and — when the evidence carries a
 * `cc_eventlog` — the CCEL is replayed against RTMR0–3, failing closed on any
 * divergence. Unlike the vTPM platforms, the freshness anchor
 * (`expectedReportData`) is checked directly against the TD quote's 64-byte
 * `report_data` (zero-padded, constant-time). The measurement surfaces as
 * `claims.launch_digest` = hex(MRTD).
 *
 * The processor generation is irrelevant for TDX, so no generation argument is
 * needed. DCAP collateral checks (PCK CRL, TCB status, TD-QE identity) run
 * only on caller-supplied collateral (`collateralJson`): every item is
 * signature-checked and the collateral freshness-checked at `at`, and the
 * result carries `tcb_status`, `tcb_status_accepted` (false for Revoked and
 * NoMatchingLevel) and `crl_ok` (false when the PCK certificate or its
 * issuing CA is revoked); collateral that fails its own checks throws with a
 * `TDX collateral:` prefix. Without it the checks are skipped and
 * `tcb_status` and `crl_ok` are `null`.
 *
 * When `expectedRtmr3` is supplied the verifier additionally compares the
 * TD's RTMR[3] with it: `rtmr_match[3]`, and `passed: false` on a mismatch. RTMR[3] is extended after
 * launch (on a c8s node: the operator key bound at boot, plus any per-workload
 * measurements chained on), so unlike MRTD it identifies a specific deployment
 * rather than a build. It is not replayable from the CCEL by construction,
 * which is why it must be supplied rather than derived.
 *
 * @param evidenceJson tdx evidence: { quote, cc_eventlog? } (base64 std)
 * @param expectedReportData raw bytes the TD quote report_data must equal
 * @param expectedInitDataHash bytes to bind against MRCONFIGID
 * @param expectedRtmr3 48 raw bytes the TD's RTMR[3] must equal
 * @param collateralJson Intel PCS collateral: { tcb_info, tcb_info_issuer_chain,
 *   qe_identity, qe_identity_issuer_chain, pck_crl, root_ca_crl, at } — JSON
 *   bodies verbatim, issuer chains as URL-decoded PEM, CRLs base64, `at` in
 *   Unix seconds
 * @returns result JSON with `passed`; throws only when the evidence cannot be verified
 */
export async function evaluateTdx(
  evidenceJson: string,
  expectedReportData?: Uint8Array,
  expectedInitDataHash?: Uint8Array,
  expectedRtmr3?: Uint8Array,
  collateralJson?: string,
): Promise<string> {
  await initVerifier();
  return evaluate_tdx(
    evidenceJson,
    expectedReportData,
    expectedInitDataHash,
    expectedRtmr3,
    collateralJson,
  );
}
