// Replay of the allowlist policies a c8s TDX node measures into RTMR[3] after
// the operator-key seed. The node reports its journal of measured policies
// next to the quote; the replay is what authenticates it.

import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "./base64.js";
import { fail } from "./errors.js";

/** The most measured policies a node may report. */
export const MAX_MEASURED_POLICIES = 256;

const CANONICAL_POLICY_DIGEST = /^sha256:[0-9a-f]{64}$/;

/**
 * Fold one policy digest into an RTMR value the way the node measures it:
 * `SHA-384(reg || SHA-384(ascii digest))`.
 */
export function extendRegister(reg: Uint8Array, digest: string): Uint8Array {
  const event = sha384(utf8ToBytes(digest));
  const buf = new Uint8Array(reg.length + event.length);
  buf.set(reg);
  buf.set(event, reg.length);
  return sha384(buf);
}

/**
 * Check a reported measured-policy list: an array of at most
 * {@link MAX_MEASURED_POLICIES} canonical `sha256:<64 lowercase hex>` digests.
 * Anything else fails with `rtmr3_denied`, like a list that does not replay.
 * `undefined` reads as empty.
 */
export function validateMeasuredPolicies(list: unknown): string[] {
  if (list === undefined) return [];
  if (!Array.isArray(list)) {
    fail("rtmr3_denied", "measured policy list is malformed: not an array of policy digests");
  }
  if (list.length > MAX_MEASURED_POLICIES) {
    fail(
      "rtmr3_denied",
      `measured policy list is malformed: ${list.length} entries, more than the ${MAX_MEASURED_POLICIES} allowed`,
    );
  }
  for (const entry of list) {
    if (typeof entry !== "string" || !CANONICAL_POLICY_DIGEST.test(entry)) {
      fail(
        "rtmr3_denied",
        `measured policy list is malformed: ${JSON.stringify(entry)} is not a canonical sha256:<64 lowercase hex> digest`,
      );
    }
  }
  return list as string[];
}

/**
 * The shortest prefix of `measured` that, extended onto `seedHex`, yields
 * `gotHex`, or undefined when none does. The list is read after the quote, so
 * it may run ahead of the register. Both hex values are 96 lowercase chars.
 */
export function replayMeasuredPolicies(
  seedHex: string,
  measured: string[],
  gotHex: string,
): string[] | undefined {
  let reg = hexToBytes(seedHex);
  for (let i = 0; i < measured.length; i++) {
    reg = extendRegister(reg, measured[i]);
    if (bytesToHex(reg) === gotHex) return measured.slice(0, i + 1);
  }
  return undefined;
}
