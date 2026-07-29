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
  // CDS roll-up: attesting CDS once and deriving the mesh CA and allowlist from
  // its claims. "_denied" means a check ran and failed; "_not_attested" means
  // the target's claims never carried the field, which is an upgrade problem
  // rather than an attack — conflating them would send an operator hunting a
  // breach when the cluster is simply older.
  | "cds_identity_missing"
  | "cds_identity_invalid"
  | "cds_identity_denied"
  // The certificate body — validity window, serial, subject — sits OUTSIDE the
  // REPORTDATA transcript, which covers only the SPKI and the config-claims
  // bytes. It is trustworthy only because the certificate self-signs with the
  // key REPORTDATA bound, so these two are separate failures from
  // "_denied": the hardware evidence was fine and the certificate around it
  // was not.
  | "cds_identity_unsigned"
  | "cds_identity_expired"
  // A newly presented CDS certificate that is older than one already verified.
  // Distinct from every other failure because nothing is forged: each half is
  // internally consistent, and the attack is serving yesterday's genuine
  // (certificate, allowlist) pair to roll back the admission policy.
  | "cds_identity_rollback"
  | "mesh_ca_denied"
  | "mesh_ca_not_attested"
  | "allowlist_denied"
  | "allowlist_not_attested"
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
