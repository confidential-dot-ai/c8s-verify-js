import { subtle } from "./crypto-env.js";
import { base64ToBytes, bytesToHex, bytesToUtf8 } from "./base64.js";
import { fail } from "./errors.js";
import { verifyECDSASignature, type Certificate } from "./x509.js";

/**
 * The `cds_state` bundle field: CDS's allowlist rollout state as standard
 * base64 of its exact JSON bytes, and an ASN.1 ECDSA signature over their
 * SHA-384 by the mesh CA key. The transcript commits SHA-384 of the same bytes.
 */
export interface SignedRolloutState {
  state: string;
  signature: string;
}

const POLICY_DIGEST = /^sha256:[0-9a-f]{64}$/;

/** Whether d is a policy digest "sha256:<64 lowercase hex>". */
function isPolicyDigest(d: unknown): d is string {
  return typeof d === "string" && POLICY_DIGEST.test(d);
}

/** CDS's allowlist rollout state. `bound` lists every policy digest that may run. */
export interface RolloutState {
  protocol: number;
  authority: string;
  position: number;
  head: string;
  allowlist_version: string;
  policy: string;
  bound: string[];
  pending?: string;
  lease_seconds: number;
  nonce?: string;
}

/** The decoded state bytes, or undefined when the bundle carries no state. */
export function rolloutStateBytes(
  signed: SignedRolloutState | null | undefined,
): Uint8Array | undefined {
  if (signed === undefined || signed === null) {
    return undefined;
  }
  if (typeof signed?.state !== "string" || typeof signed.signature !== "string") {
    fail("rollout_state_invalid", "cds_state must carry base64 state and signature strings");
  }
  try {
    return base64ToBytes(signed.state);
  } catch (cause) {
    fail("rollout_state_invalid", "cds_state.state is not standard base64", { cause });
  }
}

/** SHA-384 of the state bytes: the transcript's state_digest, empty without a state. */
export async function stateDigest(stateBytes: Uint8Array | undefined): Promise<Uint8Array> {
  if (stateBytes === undefined || stateBytes.length === 0) {
    return new Uint8Array(0);
  }
  return new Uint8Array(await subtle().digest("SHA-384", stateBytes));
}

/**
 * Verify the state against the transcript-committed mesh CA and the client
 * nonce, and parse it.
 */
export async function verifyRolloutState(
  signed: SignedRolloutState,
  stateBytes: Uint8Array,
  ca: Certificate,
  nonce: Uint8Array,
): Promise<RolloutState> {
  let signature: Uint8Array;
  try {
    signature = base64ToBytes(signed.signature);
  } catch (cause) {
    fail("rollout_state_invalid", "cds_state.signature is not standard base64", { cause });
  }
  if (!(await verifyECDSASignature(ca, stateBytes, signature, "SHA-384"))) {
    fail("rollout_state_invalid", "cds_state signature does not verify against the mesh CA");
  }
  let state: RolloutState;
  try {
    state = JSON.parse(bytesToUtf8(stateBytes)) as RolloutState;
  } catch (cause) {
    fail("rollout_state_invalid", "cds_state.state is not JSON", { cause });
  }
  if (!Array.isArray(state?.bound) || !state.bound.every(isPolicyDigest)) {
    fail("rollout_state_invalid", 'cds_state bound must list "sha256:<64 hex>" digests');
  }
  if (state.nonce !== bytesToHex(nonce)) {
    fail("rollout_state_invalid", "cds_state answers another nonce");
  }
  return state;
}

/**
 * Require every policy that may run to be one the caller pinned, and the
 * router to fence sessions on an activation lease.
 */
export function enforcePolicyPins(state: RolloutState | undefined, pins: string[]): void {
  if (state === undefined) {
    fail(
      "rollout_state_invalid",
      "pinned policies need a router serving the CDS rollout state (router.attest.pinnedAllowlist)",
    );
  }
  if (!(state.lease_seconds > 0)) {
    fail(
      "rollout_state_invalid",
      "CDS applies allowlist writes without an activation lease, so open sessions are not fenced",
    );
  }
  for (const digest of state.bound) {
    if (!pins.includes(digest)) {
      fail("policy_not_pinned", `policy ${digest} may be running and is not pinned`, {
        details: { digest },
      });
    }
  }
}

/**
 * Fetch one policy in the bound from the router and return its bytes only
 * when they hash to `digest` ("sha256:<hex>"): the alternative to pinning
 * policies out of band.
 */
export async function fetchPolicy(
  baseUrl: string,
  digest: string,
  fetchImpl: typeof fetch = fetch,
): Promise<Uint8Array> {
  if (!isPolicyDigest(digest)) {
    fail("invalid_request", `policy digest ${JSON.stringify(digest)} is not sha256:<64 hex>`);
  }
  const hex = digest.slice("sha256:".length);
  const res = await fetchImpl(new URL(`/.well-known/c8s/objects/sha256/${hex}`, baseUrl));
  if (!res.ok) {
    fail("verification_failed", `fetching policy ${digest} returned ${res.status}`);
  }
  const body = new Uint8Array(await res.arrayBuffer());
  const sum = bytesToHex(new Uint8Array(await subtle().digest("SHA-256", body)));
  if (sum !== hex) {
    fail("allowlist_denied", `the router served bytes for ${digest} that hash to sha256:${sum}`);
  }
  return body;
}
