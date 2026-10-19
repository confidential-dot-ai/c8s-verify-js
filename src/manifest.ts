// The TDX image pin: the complete measurement identity of one guest image.
//
// MRTD covers the TDVF firmware's measured regions, while the guest kernel and
// rootfs land in RTMR[1]/RTMR[2] — so MRTD alone does not identify an image
// (two different guest images built against the same firmware share it). The
// three registers are only meaningful as one tuple from one build, which is
// why they load atomically from a single provenanced build-artifact manifest.
//
// Parser parity: attestation-go runtimemeasure LoadImageManifest, which
// `c8s verify --image-manifest` uses. Same field names, matched
// case-insensitively as encoding/json does; registers nested under "tdx" (a
// confos build manifest) or flat; a key repeated in any letter case refused;
// same all-three-required atomic rule and lowercase-hex strictness. Unknown
// extra fields are allowed (build manifests carry other data).

import { fail } from "./errors.js";
import { parseStrictJson, type JsonValue } from "./strict-json.js";

const REGISTERS = ["mrtd", "rtmr1", "rtmr2"] as const;

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
 * Parse a published TDX image manifest into the tuple
 * {@link VerifyPolicy.tdxImage} pins. The registers "mrtd", "rtmr1" and
 * "rtmr2", each exactly 96 lowercase hex chars, sit either under a "tdx"
 * object (a confos build manifest) or at the top level, never both. A
 * missing or malformed field fails the whole parse, so a policy can never end
 * up pinning part of an image; unknown extra fields are allowed (build
 * manifests carry other data). Feed it the manifest file bytes verbatim.
 */
export function parseImageManifest(jsonBytes: Uint8Array | string): TdxImage {
  const bytes = typeof jsonBytes === "string" ? new TextEncoder().encode(jsonBytes) : jsonBytes;
  let doc: JsonValue;
  try {
    doc = parseStrictJson(bytes);
  } catch (cause) {
    fail("invalid_request", `image manifest is not a JSON object: ${(cause as Error).message}`, {
      cause,
    });
  }
  if (doc.kind !== "object") fail("invalid_request", "image manifest is not a JSON object");
  rejectFoldedDuplicates(doc);
  let source = doc.members;
  const tdx = member(doc.members, "tdx");
  if (tdx !== undefined && !(tdx.kind === "literal" && tdx.value === null)) {
    if (tdx.kind !== "object")
      fail("invalid_request", 'image manifest: "tdx" is not a JSON object');
    // The nested tuple wins, so a flat register beside it would be a second,
    // unread spelling of the pin.
    for (const key of doc.members.keys()) {
      if ((REGISTERS as readonly string[]).includes(key.toLowerCase())) {
        fail(
          "invalid_request",
          `image manifest: ${JSON.stringify(key)} is named both at the top level and under "tdx"; use one form`,
        );
      }
    }
    source = tdx.members;
  }
  const field = (name: string): unknown => {
    const v = member(source, name);
    if (v === undefined || (v.kind === "literal" && v.value === null)) return undefined;
    return v.kind === "string" ? v.value : v;
  };
  return requireTdxImage("image manifest", {
    mrtd: field("mrtd"),
    rtmr1: field("rtmr1"),
    rtmr2: field("rtmr2"),
  } as TdxImage);
}

/** The member whose key equals `name` in any letter case, as encoding/json matches fields. */
function member(members: Map<string, JsonValue>, name: string): JsonValue | undefined {
  for (const [key, value] of members) if (key.toLowerCase() === name) return value;
  return undefined;
}

/**
 * Refuse a key named twice in one object in any letter case, anywhere in the
 * document: encoding/json would load the last spelling, not the one a reviewer
 * read.
 */
function rejectFoldedDuplicates(value: JsonValue): void {
  if (value.kind === "array") {
    value.items.forEach(rejectFoldedDuplicates);
    return;
  }
  if (value.kind !== "object") return;
  const seen = new Set<string>();
  for (const [key, child] of value.members) {
    const folded = key.toLowerCase();
    if (seen.has(folded)) {
      fail("invalid_request", `image manifest: duplicate ${JSON.stringify(key)} key`);
    }
    seen.add(folded);
    rejectFoldedDuplicates(child);
  }
}
