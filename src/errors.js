// Typed errors for the c8s-verify flow. Codes mirror the c8s error envelope
// (pkg/types/error_codes.go) where they overlap, plus client-side codes for
// checks the browser performs that the server never sees.

/**
 * @typedef {(
 *   "invalid_request" |
 *   "nonce_mismatch" |
 *   "verification_failed" |
 *   "report_data_mismatch" |
 *   "measurement_denied" |
 *   "invalid_cert" |
 *   "cert_chain" |
 *   "key_binding" |
 *   "channel_error" |
 *   "unsupported"
 * )} C8sErrorCode
 */

export class C8sVerifyError extends Error {
  /**
   * @param {C8sErrorCode} code
   * @param {string} message
   * @param {{ cause?: unknown, details?: Record<string, unknown> }} [opts]
   */
  constructor(code, message, opts = {}) {
    super(message, opts.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = "C8sVerifyError";
    /** @type {C8sErrorCode} */
    this.code = code;
    /** @type {Record<string, unknown>} */
    this.details = opts.details ?? {};
  }
}

/**
 * Helper to throw a typed error in one expression.
 * @param {C8sErrorCode} code
 * @param {string} message
 * @param {{ cause?: unknown, details?: Record<string, unknown> }} [opts]
 * @returns {never}
 */
export function fail(code, message, opts) {
  throw new C8sVerifyError(code, message, opts);
}
