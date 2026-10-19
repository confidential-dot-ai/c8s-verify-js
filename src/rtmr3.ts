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

/**
 * The policy the evidence's leaf was issued under: `"none"` when the evidence
 * carries no leaf, `"unstamped"` for a leaf without a matched-workload stamp,
 * else the stamped allowlist digest and whether a pinned mesh CA vouches for
 * the stamp.
 */
export type LeafPolicy =
  | { kind: "none" }
  | { kind: "unstamped" }
  | { kind: "stamped"; digest: string; vouched: boolean };

/**
 * Judge the replayed policy history the way `c8s verify --pin-policy` does,
 * and return what the verdict leaves unproven: a non-empty list makes it
 * partial. Without `pins`, a non-empty history is unproven. With them, every
 * entry and the leaf's issuing policy must be pinned (`policy_history_absent`,
 * `policy_history_not_pinned`); an unstamped leaf, a stamp no pinned CA
 * vouches for, or evidence no nonce of this check binds (`fresh` false) leave
 * the verdict partial.
 */
export function judgePolicyHistory(
  history: string[],
  pins: string[] | undefined,
  leaf: LeafPolicy,
  fresh: boolean,
  warnings: string[],
): string[] {
  if (pins === undefined) {
    if (history.length === 0) return [];
    warnings.push(
      `replayed ${history.length} measured policies, none judged: RTMR[3] proves which ` +
        "allowlist policies the node enforced since boot (see measuredPolicies), but no " +
        "policy pin checked them (pass pinPolicies)",
    );
    return [
      `the node's policy history: RTMR[3] replayed ${history.length} measured policies, ` +
        "but no policy over them was checked",
    ];
  }
  if (history.length === 0) {
    fail(
      "policy_history_absent",
      "no measured policy replayed against RTMR[3]: a node that does not measure its " +
        "policies (nriImagePolicy.measurePolicies) proves nothing about the policies it enforced",
    );
  }
  for (const digest of history) {
    if (!pins.includes(digest)) {
      fail(
        "policy_history_not_pinned",
        `the node enforced policy ${digest} since boot and it is not pinned; review it at ` +
          `/allowlist/objects/sha256/${digest.slice("sha256:".length)}`,
        { details: { digest, history: [...history] } },
      );
    }
  }
  const notProven: string[] = [];
  if (leaf.kind === "unstamped") {
    notProven.push(
      "the policy the leaf was issued under: the policy history is pinned, but the leaf " +
        "carries no matched-workload stamp, so its issuing policy was not checked",
    );
  } else if (leaf.kind === "stamped") {
    if (!pins.includes(leaf.digest)) {
      fail(
        "policy_history_not_pinned",
        `the leaf was issued under policy ${leaf.digest}, which is not pinned`,
        { details: { digest: leaf.digest } },
      );
    }
    if (!leaf.vouched) {
      notProven.push(
        "the policy the leaf was issued under: its matched-workload stamp is pinned, but it " +
          "is CA-vouched and no pinned mesh CA (meshCaPem) authenticated it",
      );
    }
  }
  if (!fresh) {
    notProven.push(
      "the node's current policy history: the history is pinned up to the evidence's " +
        "quote, which no nonce of this check binds, so a policy enforced since is not shown",
    );
  }
  return notProven;
}
