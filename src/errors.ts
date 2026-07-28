// Typed errors for the c8s-verify flow. Codes mirror the c8s error envelope
// (pkg/types/error_codes.go) where they overlap, plus client-side codes for
// checks the browser performs that the server never sees.

export type C8sErrorCode =
  | "invalid_request"
  | "nonce_mismatch"
  | "verification_failed"
  | "report_data_mismatch"
  | "measurement_denied"
  | "invalid_cert"
  | "cert_chain"
  | "identity_binding"
  | "key_binding"
  | "channel_error"
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
