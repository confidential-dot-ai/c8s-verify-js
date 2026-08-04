// The TDX image pin: the complete measurement identity of one guest image.
//
// MRTD covers the TDVF firmware's measured regions, while the guest kernel and
// rootfs land in RTMR[1]/RTMR[2] — so MRTD alone does not identify an image
// (two different guest images built against the same firmware share it). The
// three registers are only meaningful as one tuple from one build, which is
// why they load atomically from a single provenanced build-artifact manifest.
//
// Parser parity: c8s pkg/runtimemeasure LoadImageManifest. Same field names,
// same all-three-required atomic rule, same lowercase-hex strictness; unknown
// extra fields are allowed (build manifests carry other data).

import { fail } from "./errors.js";

/**
 * A TDX guest-image pin: MRTD + RTMR[1] + RTMR[2] as one tuple, each exactly
 * 96 lowercase hex chars (48 bytes, SHA-384).
 */
export interface TdxImage {
  /** TDVF firmware measurement (surfaces as `claims.launch_digest`). */
  mrtd: string;
  /** Guest kernel / UKI image identity (`claims.platform_data.rtmr_1`). */
  rtmr1: string;
  /** Guest rootfs / UKI section chain (`claims.platform_data.rtmr_2`). */
  rtmr2: string;
}

/**
 * Exactly 96 lowercase hex chars. Uppercase is rejected rather than folded:
 * the manifest is a measurement reference, and accepting mixed case would let
 * two spellings of one value slip past byte-exact comparisons elsewhere.
 */
const REGISTER_HEX = /^[0-9a-f]{96}$/;

/**
 * Validate one register field of a tuple; `context` names the source for the
 * error message ("image manifest", "tdxImage", ...).
 */
function requireRegister(context: string, name: string, value: unknown): string {
  if (value === undefined || value === null || value === "") {
    fail(
      "invalid_request",
      `${context}: missing ${JSON.stringify(name)} — a TDX image pin is the mrtd+rtmr1+rtmr2 ` +
        "tuple from one provenanced build-artifact manifest; a generic artifact-hash " +
        "manifest.json is not it",
    );
  }
  if (typeof value !== "string") {
    fail("invalid_request", `${context}: ${JSON.stringify(name)} is not a string`);
  }
  if (value.length !== 96) {
    fail(
      "invalid_request",
      `${context}: ${JSON.stringify(name)} is ${value.length} chars, want 96 lowercase hex chars`,
    );
  }
  if (!REGISTER_HEX.test(value)) {
    fail("invalid_request", `${context}: ${JSON.stringify(name)} is not 96 lowercase hex chars`);
  }
  return value;
}

/**
 * Validate a caller-supplied tuple (e.g. `VerifyPolicy.tdxImage`) with the
 * same strictness as {@link parseImageManifest}: all three registers or
 * nothing — a partial tuple would silently verify only part of the image.
 */
export function requireTdxImage(context: string, tuple: TdxImage): TdxImage {
  if (tuple === null || typeof tuple !== "object" || Array.isArray(tuple)) {
    fail("invalid_request", `${context}: a TDX image pin must be a { mrtd, rtmr1, rtmr2 } object`);
  }
  return {
    mrtd: requireRegister(context, "mrtd", tuple.mrtd),
    rtmr1: requireRegister(context, "rtmr1", tuple.rtmr1),
    rtmr2: requireRegister(context, "rtmr2", tuple.rtmr2),
  };
}

/**
 * Parse a published TDX image manifest — a JSON object carrying "mrtd",
 * "rtmr1", and "rtmr2", each exactly 96 lowercase hex chars — into the tuple
 * {@link VerifyPolicy.tdxImage} pins. A missing or malformed field fails the
 * whole parse, so a policy can never end up pinning part of an image; unknown
 * extra fields are allowed (build manifests carry other data). Feed it the
 * manifest file bytes verbatim.
 */
export function parseImageManifest(jsonBytes: Uint8Array | string): TdxImage {
  const text = typeof jsonBytes === "string" ? jsonBytes : new TextDecoder().decode(jsonBytes);
  let doc: unknown;
  try {
    doc = JSON.parse(text) as unknown;
  } catch (cause) {
    fail("invalid_request", "image manifest is not a JSON object", { cause });
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    fail("invalid_request", "image manifest is not a JSON object");
  }
  return requireTdxImage("image manifest", doc as TdxImage);
}
