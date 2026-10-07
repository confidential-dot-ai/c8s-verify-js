// TDX TCB-status policy: caller-supplied Intel PCS collateral, verified in
// WASM, and the TCB levels the caller accepts.

import { bytesToBase64, utf8ToBytes } from "./base64.js";
import { fail } from "./errors.js";

/** Intel's TDX TCB status levels, as Intel PCS names them. */
export type TdxTcbStatus =
  | "UpToDate"
  | "SWHardeningNeeded"
  | "ConfigurationNeeded"
  | "ConfigurationAndSWHardeningNeeded"
  | "OutOfDate"
  | "OutOfDateConfigurationNeeded"
  | "Revoked";

const TCB_STATUSES: readonly TdxTcbStatus[] = [
  "UpToDate",
  "SWHardeningNeeded",
  "ConfigurationNeeded",
  "ConfigurationAndSWHardeningNeeded",
  "OutOfDate",
  "OutOfDateConfigurationNeeded",
  "Revoked",
];

/** Accepted when the caller names no levels. */
const DEFAULT_ACCEPTED: readonly TdxTcbStatus[] = ["UpToDate"];

/**
 * Intel PCS v4 collateral for a bare-metal TDX quote, fetched by the caller:
 * PCS sends no CORS headers, so a browser cannot fetch it itself. Nothing
 * here is trusted on transport: the verifier checks Intel's signatures on
 * every item, that the TCB Info is the TDX one for the quote's FMSPC, and
 * that the TCB Info, QE Identity and both CRLs are current at the
 * verification time `at`. Intel certificate validity (the PCK chain and both
 * issuer chains) is checked against the current time, not `at`.
 *
 * Pass the JSON bodies verbatim — the signatures cover their exact bytes.
 */
export interface TdxCollateral {
  /** Body of `GET /tdx/certification/v4/tcb?fmspc=<fmspc>`. */
  tcbInfo: string | Uint8Array;
  /** PEM of that response's `TCB-Info-Issuer-Chain` header, URL-decoded. */
  tcbInfoIssuerChain: string;
  /** Body of `GET /tdx/certification/v4/qe/identity`. */
  qeIdentity: string | Uint8Array;
  /** PEM of that response's `SGX-Enclave-Identity-Issuer-Chain` header, URL-decoded. */
  qeIdentityIssuerChain: string;
  /**
   * CRL of the CA that issued the quote's PCK certificate
   * (`GET /sgx/certification/v4/pckcrl?ca=platform|processor`): DER bytes or
   * a PEM string.
   */
  pckCrl: string | Uint8Array;
  /** Intel SGX Root CA CRL: DER bytes or a PEM string. */
  rootCaCrl: string | Uint8Array;
}

/** The TCB status a verdict evaluated from {@link TdxCollateral}. */
export interface TdxTcbResult {
  status: TdxTcbStatus;
  /** The platform's FMSPC, from its PCK certificate (hex). */
  fmspc: string;
  /** Intel security advisories listed for the matched TCB level. */
  advisoryIds: string[];
}

/** The `tcb_status` block of the WASM verifier's result. */
export interface WasmTcbStatus {
  tcb_status: string;
  fmspc: string;
  advisory_ids: string[];
}

const FIELDS = [
  "tcbInfo",
  "tcbInfoIssuerChain",
  "qeIdentity",
  "qeIdentityIssuerChain",
  "pckCrl",
  "rootCaCrl",
] as const;

/**
 * Validate the TDX TCB policy, failing closed on anything the verifier could
 * not enforce. Returns the accepted statuses, or undefined without collateral.
 */
export function validateTdxTcbPolicy(
  platform: string,
  collateral: TdxCollateral | undefined,
  accepted: TdxTcbStatus[] | undefined,
): readonly TdxTcbStatus[] | undefined {
  if (collateral === undefined) {
    if (accepted !== undefined) {
      fail(
        "invalid_request",
        "tdxTcbStatuses needs tdxCollateral: without collateral no TCB status is evaluated",
      );
    }
    return undefined;
  }
  // The vTPM entry point (az-tdx) has no collateral input, so a pin there
  // would be dropped.
  if (platform !== "tdx") {
    fail(
      "invalid_request",
      `tdxCollateral requires platform "tdx" (got ${JSON.stringify(platform)}): only the bare-metal TDX verifier takes collateral`,
    );
  }
  if (collateral === null || typeof collateral !== "object") {
    fail("invalid_request", "tdxCollateral must be an object");
  }
  for (const field of FIELDS) {
    const v: unknown = collateral[field];
    if (!((typeof v === "string" || v instanceof Uint8Array) && v.length > 0)) {
      fail("invalid_request", `tdxCollateral.${field} must be a non-empty string or byte array`);
    }
  }
  if (accepted === undefined) return DEFAULT_ACCEPTED;
  if (!Array.isArray(accepted) || accepted.length === 0) {
    fail("invalid_request", "tdxTcbStatuses must list at least one TCB status");
  }
  for (const status of accepted) {
    if (!TCB_STATUSES.includes(status) || status === "Revoked") {
      fail(
        "invalid_request",
        `tdxTcbStatuses: ${JSON.stringify(status)} is not an acceptable TDX TCB status`,
      );
    }
  }
  return accepted;
}

function text(v: string | Uint8Array): string {
  return typeof v === "string" ? v : new TextDecoder("utf-8", { fatal: true }).decode(v);
}

function base64(v: string | Uint8Array): string {
  return bytesToBase64(typeof v === "string" ? utf8ToBytes(v) : v);
}

/** Serialize validated collateral to the JSON the WASM `verify_tdx` takes. */
export function tdxCollateralJson(c: TdxCollateral, at: Date | undefined): string {
  let tcbInfo: string;
  let qeIdentity: string;
  try {
    tcbInfo = text(c.tcbInfo);
    qeIdentity = text(c.qeIdentity);
  } catch (cause) {
    fail("invalid_request", "tdxCollateral tcbInfo and qeIdentity must be UTF-8", { cause });
  }
  return JSON.stringify({
    tcb_info: tcbInfo,
    tcb_info_issuer_chain: c.tcbInfoIssuerChain,
    qe_identity: qeIdentity,
    qe_identity_issuer_chain: c.qeIdentityIssuerChain,
    pck_crl: base64(c.pckCrl),
    root_ca_crl: base64(c.rootCaCrl),
    at: Math.floor((at ?? new Date()).getTime() / 1000),
  });
}

/** A collateral failure the verifier tagged as such. */
export function isTdxCollateralFailure(e: unknown): boolean {
  return String((e as { message?: unknown })?.message ?? e).includes("TDX collateral:");
}

/**
 * Enforce the accepted TCB statuses against the VERIFIED result. Collateral
 * that was supplied but produced no status fails closed: a verifier build
 * that ignored it must never read as checked.
 */
export function enforceTdxTcb(
  tcb: WasmTcbStatus | null | undefined,
  collateralVerified: boolean,
  accepted: readonly TdxTcbStatus[],
): TdxTcbResult {
  if (!collateralVerified || tcb == null) {
    fail(
      "collateral_required",
      "tdxCollateral was supplied but the verifier evaluated no TCB status — refusing to report a TCB policy that was never enforced",
    );
  }
  const status = tcb.tcb_status as TdxTcbStatus;
  if (!TCB_STATUSES.includes(status)) {
    fail(
      "collateral_denied",
      `verifier reported an unknown TDX TCB status ${JSON.stringify(status)}`,
    );
  }
  const result = { status, fmspc: tcb.fmspc, advisoryIds: tcb.advisory_ids ?? [] };
  if (!accepted.includes(status)) {
    fail(
      "tcb_denied",
      `TDX TCB status is ${status}, not one of the accepted ${accepted.join(", ")}: genuine silicon, but platform firmware or configuration the policy does not accept`,
      { details: { ...result, accepted } },
    );
  }
  return result;
}
