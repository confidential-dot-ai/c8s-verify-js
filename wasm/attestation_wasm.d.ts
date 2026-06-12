/* tslint:disable */
/* eslint-disable */

/**
 * Verify Azure SEV-SNP (az-snp) vTPM attestation evidence in WASM.
 *
 * Unlike [`verify_snp`], which only checks the bare SNP hardware report, this
 * verifies the full az-snp evidence: the HCL-wrapped SNP report **and** the
 * vTPM quote that binds freshness. The freshness anchor for az-snp lives in
 * the TPM quote's `extraData` (qualifyingData), not in the SNP `report_data`
 * — the SNP `report_data` instead binds the vTPM attestation key (AK).
 *
 * Verification (mirrors the native async path, minus the CRL revocation check
 * which needs an async cert provider — so `collateral_verified` is always
 * `false` here):
 * 1. Verify the TPM quote signature with the AK extracted from HCL var_data.
 * 2. Check the quote's `extraData` equals `expected_report_data` (freshness).
 * 3. Verify the PCR digest, and optionally bind PCR[8] to `expected_init_data_hash`.
 * 4. Bind the AK to the TEE: `snp.report_data[..32] == SHA-256(var_data)`.
 * 5. Validate the VCEK chain (auto-detecting the generation from CPUID) and the
 *    SNP report signature, then enforce VMPL/debug/TCB policy.
 *
 * - `evidence_json`: az-snp evidence JSON (`{ version, tpm_quote, hcl_report, vcek }`)
 * - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
 * - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
 *
 * Returns the verification result as JSON, or throws on any check failure.
 */
export function verify_az_snp(evidence_json: string, expected_report_data?: Uint8Array | null, expected_init_data_hash?: Uint8Array | null): string;

/**
 * Verify live SNP evidence in WASM.
 *
 * - `evidence_json`: evidence JSON with inline cert_chain.vcek
 * - `generation`: processor generation ("milan", "genoa", "turin")
 * - `expected_report_data`: optional raw bytes to check against report_data in the report
 *
 * Returns verification result as JSON.
 */
export function verify_snp(evidence_json: string, generation: string, expected_report_data?: Uint8Array | null): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly verify_az_snp: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly verify_snp: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
