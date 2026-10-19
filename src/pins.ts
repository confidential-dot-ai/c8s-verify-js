// Pins that mirror `c8s verify` flags: the RTMR[3] pin in its three
// spellings, by-hand RTMR[1]/RTMR[2] pins, the init-data digest and the leaf's
// sandbox ID. Each is validated once, before any evidence is read.

import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { readTLV, TAG } from "./asn1.js";
import { bytesToHex, bytesToUtf8, utf8ToBytes } from "./base64.js";
import { fail } from "./errors.js";
import { decodePEM } from "./pem.js";
import type { Certificate } from "./x509.js";

const REGISTER_HEX = /^[0-9a-fA-F]{96}$/;
const POLICY_DIGEST = /^sha256:[0-9a-f]{64}$/;

/** TDX runtime registers pinned by index, each 96 hex characters. */
export interface RtmrPins {
  1?: string;
  2?: string;
  3?: string;
}

/** The inputs that pin TDX runtime registers. */
export interface RegisterPinInputs {
  expectedRtmr3?: string;
  operatorPublicKeyPem?: string;
  rtmrs?: RtmrPins;
  /** Whether a `tdxImage` tuple is pinned. */
  imagePinned: boolean;
}

/** Resolved register pins, as 96 lowercase hex characters. */
export interface RegisterPins {
  rtmr1?: string;
  rtmr2?: string;
  rtmr3?: string;
}

/**
 * The bare RTMR[3] seed a guest booted with this operator public key reports,
 * as `c8s verify --operator-pkey` derives it: SHA-384(0x00*48 ‖ SHA-384(pem)),
 * over the PEM bytes verbatim.
 */
export function operatorSeed(pem: string): string {
  const buf = new Uint8Array(96);
  buf.set(sha384(utf8ToBytes(pem)), 48);
  return bytesToHex(sha384(buf));
}

function checkOperatorPublicKeyPem(pem: unknown): asserts pem is string {
  if (typeof pem !== "string" || pem === "") {
    fail("invalid_request", "operatorPublicKeyPem must be a non-empty PEM string");
  }
  const first = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(pem)?.[1];
  if (first === undefined) {
    fail(
      "invalid_request",
      'operatorPublicKeyPem is not PEM: expected "-----BEGIN PUBLIC KEY-----"',
    );
  }
  if (first.includes("PRIVATE KEY")) {
    fail(
      "invalid_request",
      `operatorPublicKeyPem holds a ${JSON.stringify(first)} block: pass the operator PUBLIC key, the exact bytes the guest initrd hashed`,
    );
  }
  let ok = false;
  try {
    const der = first === "PUBLIC KEY" ? decodePEM(pem, "PUBLIC KEY")[0] : undefined;
    ok = der !== undefined && readTLV(der, 0).tag === TAG.SEQUENCE;
  } catch {
    // A body that does not parse is reported below with the block type.
  }
  if (!ok) {
    fail(
      "invalid_request",
      `operatorPublicKeyPem's first block is ${JSON.stringify(first)}, want a parseable "PUBLIC KEY"`,
    );
  }
}

/**
 * Resolve the register pins. RTMR[3] has three spellings that write one
 * register, so at most one may be set; `operatorPublicKeyPem` and `rtmrs[3]`
 * require `tdxImage`, as in `c8s verify`, while `expectedRtmr3` keeps its
 * earlier rules. By-hand RTMR[1]/RTMR[2] pins exclude `tdxImage`, which pins
 * both from one build. The caller checks the platform.
 */
export function resolveRegisterPins(o: RegisterPinInputs): RegisterPins {
  const out: RegisterPins = {};
  if (o.rtmrs !== undefined) {
    if (o.rtmrs === null || typeof o.rtmrs !== "object" || Array.isArray(o.rtmrs)) {
      fail("invalid_request", "rtmrs must be an object mapping 1, 2 or 3 to 96 hex characters");
    }
    const keys = Object.keys(o.rtmrs);
    if (keys.length === 0) {
      fail("invalid_request", "rtmrs must pin at least one register when set");
    }
    for (const key of keys) {
      const value = (o.rtmrs as Record<string, unknown>)[key];
      if (key !== "1" && key !== "2" && key !== "3") {
        fail(
          "invalid_request",
          `rtmrs pins RTMR[${key}]: only 1, 2 and 3 are pinnable (RTMR[0] is firmware configuration)`,
        );
      }
      if (typeof value !== "string" || !REGISTER_HEX.test(value)) {
        fail("invalid_request", `rtmrs[${key}] must be 96 hex characters (48 bytes, SHA-384)`);
      }
      out[`rtmr${key}`] = value.toLowerCase();
    }
    if ((out.rtmr1 !== undefined || out.rtmr2 !== undefined) && o.imagePinned) {
      fail(
        "invalid_request",
        "rtmrs[1] and rtmrs[2] cannot be combined with tdxImage: the tuple already pins both, " +
          "together with the MRTD of the same build",
      );
    }
  }
  const rtmr3Inputs = [
    o.rtmrs?.[3] !== undefined && "rtmrs[3]",
    o.expectedRtmr3 !== undefined && "expectedRtmr3",
    o.operatorPublicKeyPem !== undefined && "operatorPublicKeyPem",
  ].filter((name): name is string => name !== false);
  if (rtmr3Inputs.length > 1) {
    fail("invalid_request", `${rtmr3Inputs.join(" and ")} all pin RTMR[3]: name the register once`);
  }
  if (o.expectedRtmr3 !== undefined) {
    if (typeof o.expectedRtmr3 !== "string" || !REGISTER_HEX.test(o.expectedRtmr3)) {
      fail("invalid_request", "expectedRtmr3 must be 96 hex characters (48 bytes, SHA-384)");
    }
    out.rtmr3 = o.expectedRtmr3.toLowerCase();
  }
  if (o.operatorPublicKeyPem !== undefined) {
    checkOperatorPublicKeyPem(o.operatorPublicKeyPem);
    out.rtmr3 = operatorSeed(o.operatorPublicKeyPem);
  }
  if (rtmr3Inputs[0] !== undefined && rtmr3Inputs[0] !== "expectedRtmr3" && !o.imagePinned) {
    fail(
      "invalid_request",
      `${rtmr3Inputs[0]} requires tdxImage: RTMR[3] records events extended into a guest whose ` +
        "image the untrusted host selects, so pinning it without the image proves nothing " +
        "about what is running",
    );
  }
  return out;
}

/**
 * Normalize a `pinPolicies` option to policy digests. An entry is a
 * `sha256:<64 lowercase hex>` digest, or an allowlist document (bytes, or a
 * JSON string encoded as UTF-8 verbatim) whose SHA-256 is taken over its exact
 * bytes, the canonical bytes `GET /allowlist` serves. Set only with an
 * RTMR[3] pin: the history it judges is what replays from that pin.
 */
export function policyPinDigests(pins: unknown, rtmr3Pinned: boolean): string[] | undefined {
  if (pins === undefined) return undefined;
  if (!rtmr3Pinned) {
    fail(
      "invalid_request",
      "pinPolicies requires an RTMR[3] pin (expectedRtmr3, operatorPublicKeyPem or rtmrs[3]): " +
        "the node's policy history counts only as far as it replays against RTMR[3]",
    );
  }
  if (!Array.isArray(pins) || pins.length === 0) {
    fail(
      "invalid_request",
      "pinPolicies must be a non-empty array when set: an empty pin set accepts nothing",
    );
  }
  return pins.map((pin: unknown) => {
    // An allowlist document is a JSON object, so anything else in a string
    // is a digest, and a malformed one must not be hashed as a document.
    if (typeof pin === "string" && !pin.trimStart().startsWith("{")) {
      if (!POLICY_DIGEST.test(pin)) {
        fail(
          "invalid_request",
          `pinPolicies entry ${JSON.stringify(pin)} is neither sha256:<64 lowercase hex> nor a JSON allowlist document`,
        );
      }
      return pin;
    }
    const bytes =
      typeof pin === "string" ? utf8ToBytes(pin) : pin instanceof Uint8Array ? pin : undefined;
    if (bytes === undefined || bytes.length === 0) {
      fail(
        "invalid_request",
        "pinPolicies entries must be sha256:<hex> digests or non-empty allowlist documents " +
          "(Uint8Array, or a string hashed as UTF-8 verbatim)",
      );
    }
    return `sha256:${bytesToHex(sha256(bytes))}`;
  });
}

/** Parse an `initDataHash` pin: SHA-256 of the init-data document, 64 hex characters. */
export function parseInitDataHash(pin: unknown): Uint8Array | undefined {
  if (pin === undefined) return undefined;
  if (typeof pin !== "string" || !/^[0-9a-fA-F]{64}$/.test(pin)) {
    fail(
      "invalid_request",
      "initDataHash must be 64 hex characters: SHA-256 of the init-data document",
    );
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(pin.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** OID of the pod sandbox-ID extension CDS stamps on a mesh leaf. */
export const OID_SANDBOX_ID = "1.3.6.1.4.1.66378.1.4";

const SANDBOX_ID = /^[A-Za-z0-9._-]{1,128}$/;

/** Check a `sandboxId` pin against the CRI sandbox-ID grammar CDS enforces. */
export function validateSandboxId(id: unknown): void {
  if (id === undefined) return;
  if (typeof id !== "string" || !SANDBOX_ID.test(id)) {
    fail("invalid_request", `sandboxId must match ${SANDBOX_ID.source}`);
  }
}

/**
 * The CRI pod sandbox ID the leaf names, or undefined when it carries no
 * sandbox-ID extension. A present but malformed extension fails
 * (`sandbox_denied`), never reads as absent.
 */
export function sandboxIdFromLeaf(leaf: Certificate): string | undefined {
  const value = leaf.extensions.get(OID_SANDBOX_ID);
  if (value === undefined) return undefined;
  let id: string | undefined;
  try {
    const node = readTLV(value, 0);
    if (node.tag === TAG.IA5_STRING && node.end === value.length) id = bytesToUtf8(node.content);
  } catch {
    // Reported below as a malformed extension.
  }
  if (id === undefined || !SANDBOX_ID.test(id)) {
    fail("sandbox_denied", "the mesh leaf's sandbox-ID extension is malformed");
  }
  return id;
}
