// Typed errors for the c8s-verify flow. Codes mirror the c8s error envelope
// (pkg/types/error_codes.go) where they overlap, plus client-side codes for
// checks the browser performs that the server never sees.

export type C8sErrorCode =
  | "invalid_request"
  | "nonce_mismatch"
  | "verification_failed"
  | "report_data_mismatch"
  | "measurement_denied"
  | "rtmr3_denied"
  | "invalid_cert"
  | "cert_chain"
  | "identity_binding"
  | "key_binding"
  | "channel_error"
  // Matched-workload policy: enforcing a workload/allowlist pin against the
  // stamp on the chain-verified mesh leaf. "_denied" means a check ran and
  // failed; "_not_attested" means the leaf never carried the stamp, which is
  // an upgrade/lifecycle state (an unstamped leaf is issued mid-lifecycle by
  // design) rather than forged data — conflating them would send an operator
  // hunting a breach when the pod is simply not yet named.
  | "workload_not_attested"
  // A stamp is present but is not the one canonical v1 encoding, or violates
  // the name/version/digest grammar. Distinct from absence: a verifier must
  // not read damage as "not stamped", and an unpinned diagnostic may report
  // only that an unparseable extension exists, never any field from it.
  | "workload_invalid"
  // The stamped name is not the pinned workloadName. Everything about the
  // stamp is genuine and CA-vouched; it names a different workload.
  | "workload_denied"
  // The stamped name does not resolve in the pinned allowlist document. The
  // digest check normally catches skew first, so reaching this means a
  // document that hashes right yet omits the entry — never acceptable.
  | "workload_unresolved"
  // The stamped allowlist digest is not SHA-256 of the pinned canonical
  // bytes: CDS decided the match under a different policy document than the
  // one the caller holds.
  | "allowlist_denied"
  | "unsupported";

export interface C8sErrorOptions {
  cause?: unknown;
  details?: Record<string, unknown>;
}

export class C8sVerifyError extends Error {
  readonly code: C8sErrorCode;
  readonly details: Record<string, unknown>;

  constructor(code: C8sErrorCode, message: string, opts: C8sErrorOptions = {}) {
    super(message, opts.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = "C8sVerifyError";
    this.code = code;
    this.details = opts.details ?? {};
  }
}

/**
 * Helper to throw a typed error in one expression.
 */
export function fail(code: C8sErrorCode, message: string, opts?: C8sErrorOptions): never {
  throw new C8sVerifyError(code, message, opts);
}
