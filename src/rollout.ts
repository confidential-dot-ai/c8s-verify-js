import { subtle } from "./crypto-env.js";
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToHex,
  bytesToUtf8,
  concatBytes,
  hexToBytes,
  utf8ToBytes,
} from "./base64.js";
import { fail } from "./errors.js";
import { verifyECDSASignature, type Certificate } from "./x509.js";

/**
 * The `cds_state` bundle field: CDS's allowlist rollout state as standard
 * base64 of its exact JSON bytes, and the mesh CA key's ASN.1 ECDSA signature
 * over SHA-384 of the challenge context, a zero byte and those bytes. The
 * transcript commits SHA-384 of the state bytes.
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
  /** Unix seconds bounding the signature's validity, on CDS's clock. */
  issued_at: number;
  expires_at: number;
  /** Hash of the key set that may write the allowlist, or "none". */
  operator_keys: string;
}

/** The context CDS signs a nonce-bound state under (c8s pkg/rolloutstate). */
const CHALLENGE_CONTEXT = "c8s/rollout-state-challenge/v1";

/** Clock skew allowed around a state's validity window, in seconds. */
const MAX_CLOCK_SKEW_SECONDS = 120;

/** `RolloutState.operator_keys` for an immutable allowlist. */
export const OPERATOR_KEYS_NONE = "none";

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
 * Verify the state against the transcript-committed mesh CA, the client
 * nonce and its validity window at `now`, and parse it.
 */
export async function verifyRolloutState(
  signed: SignedRolloutState,
  stateBytes: Uint8Array,
  ca: Certificate,
  nonce: Uint8Array,
  now: Date = new Date(),
): Promise<RolloutState> {
  let signature: Uint8Array;
  try {
    signature = base64ToBytes(signed.signature);
  } catch (cause) {
    fail("rollout_state_invalid", "cds_state.signature is not standard base64", { cause });
  }
  const signed_ = concatBytes(utf8ToBytes(CHALLENGE_CONTEXT), new Uint8Array([0]), stateBytes);
  if (!(await verifyECDSASignature(ca, signed_, signature, "SHA-384"))) {
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
  const t = Math.floor(now.getTime() / 1000);
  if (
    !(state.issued_at > 0) ||
    !(state.expires_at >= state.issued_at) ||
    state.issued_at > t + MAX_CLOCK_SKEW_SECONDS ||
    t > state.expires_at + MAX_CLOCK_SKEW_SECONDS
  ) {
    fail("rollout_state_invalid", "cds_state is outside its issued_at/expires_at window", {
      details: { issued_at: state.issued_at, expires_at: state.expires_at },
    });
  }
  return state;
}

/**
 * Require every policy that may run, and every policy the node enforced since
 * boot (`history`), to be one the caller pinned, and the router to fence
 * sessions on an activation lease.
 */
export function enforcePolicyPins(
  state: RolloutState | undefined,
  pins: string[],
  history: string[] = [],
): void {
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
  for (const digest of history) {
    if (!pins.includes(digest)) {
      fail(
        "policy_not_pinned",
        `the node enforced policy ${digest} since boot (RTMR[3]) and it is not pinned`,
        { details: { digest } },
      );
    }
  }
}

/**
 * Fold one policy digest into a TDX RTMR value the way the c8s NRI plugin
 * measures it: the event is SHA-384 of the "sha256:<hex>" string, and the
 * register becomes SHA-384(register || event).
 */
export async function extendRegister(reg: Uint8Array, digest: string): Promise<Uint8Array> {
  const event = new Uint8Array(await subtle().digest("SHA-384", utf8ToBytes(digest)));
  return new Uint8Array(await subtle().digest("SHA-384", concatBytes(reg, event)));
}

/**
 * The prefix of `measured` that, extended after `seedHex`, yields `gotHex`,
 * or undefined when none does. `measured` is read after the quote, so it may
 * hold extends the quote does not.
 */
export async function replayHistory(
  seedHex: string,
  measured: string[],
  gotHex: string,
): Promise<string[] | undefined> {
  let reg = hexToBytes(seedHex.toLowerCase());
  for (let i = 0; i < measured.length; i++) {
    reg = await extendRegister(reg, measured[i]);
    if (bytesToHex(reg) === gotHex.toLowerCase()) {
      return measured.slice(0, i + 1);
    }
  }
  return undefined;
}

const KEY_SET_DOMAIN = "c8s-operator-key-set-v1\u0000";

function pemBlocks(pem: string, type: string): Uint8Array[] {
  const re = new RegExp(`-----BEGIN ${type}-----([^-]+)-----END ${type}-----`, "g");
  return [...pem.matchAll(re)].map((m) => base64ToBytes(m[1].replace(/\s+/g, "")));
}

/**
 * c8s's operatorauth.KeySetHash: hex SHA-256 over a domain and the sorted,
 * deduplicated SHA-256 fingerprints of each key's SubjectPublicKeyInfo DER.
 */
export async function operatorKeySetHash(keysPem: string): Promise<string> {
  const fps: string[] = [];
  for (const der of pemBlocks(keysPem, "PUBLIC KEY")) {
    fps.push(bytesToHex(new Uint8Array(await subtle().digest("SHA-256", der))));
  }
  if (fps.length === 0) {
    fail("invalid_request", "operator keys hold no PUBLIC KEY block");
  }
  const unique = [...new Set(fps)].sort();
  const data = concatBytes(utf8ToBytes(KEY_SET_DOMAIN), ...unique.map(hexToBytes));
  return bytesToHex(new Uint8Array(await subtle().digest("SHA-256", data)));
}

const JWS_ALGS: Record<string, { hash: string; curve: string }> = {
  ES256: { hash: "SHA-256", curve: "P-256" },
  ES384: { hash: "SHA-384", curve: "P-384" },
  ES512: { hash: "SHA-512", curve: "P-521" },
};

/** c8s operatorauth.MaxTokenValidity, in seconds. */
const MAX_TOKEN_VALIDITY_SECONDS = 300;

/**
 * Check a stored c8s operator write token: an ES256/384/512 JWS under one of
 * `keysPem` whose htm, htu and pbh claims bind it to PUT /allowlist with
 * `policy`. Its expiry is not checked, since CDS enforced it when it accepted
 * the write.
 */
export async function verifyWriteToken(
  keysPem: string,
  token: string,
  policy: Uint8Array,
): Promise<boolean> {
  const parts = token.trim().split(".");
  if (parts.length !== 3) return false;
  let header: { alg?: string };
  let claims: { htm?: string; htu?: string; pbh?: string; iat?: number; exp?: number };
  try {
    header = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[0]))) as typeof header;
    claims = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[1]))) as typeof claims;
  } catch {
    return false;
  }
  const alg = JWS_ALGS[header.alg ?? ""];
  if (alg === undefined) return false;
  const pbh = bytesToBase64UrlNoPad(new Uint8Array(await subtle().digest("SHA-256", policy)));
  const validity = (claims.exp ?? 0) - (claims.iat ?? 0);
  if (
    claims.htm !== "PUT" ||
    claims.htu !== "/allowlist" ||
    claims.pbh !== pbh ||
    !((claims.iat ?? 0) > 0) ||
    !(validity > 0 && validity <= MAX_TOKEN_VALIDITY_SECONDS)
  ) {
    return false;
  }
  const signature = base64UrlToBytes(parts[2]);
  const message = utf8ToBytes(`${parts[0]}.${parts[1]}`);
  for (const der of pemBlocks(keysPem, "PUBLIC KEY")) {
    let key: CryptoKey;
    try {
      key = await subtle().importKey("spki", der, { name: "ECDSA", namedCurve: alg.curve }, false, [
        "verify",
      ]);
    } catch {
      continue;
    }
    if (await subtle().verify({ name: "ECDSA", hash: alg.hash }, key, signature, message)) {
      return true;
    }
  }
  return false;
}

function bytesToBase64UrlNoPad(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Require every policy in the bound and the node's measured history to carry
 * the operator's signature under the key set the attested state names. The
 * key set is `keysPem` when given, else the one the router serves.
 */
export async function enforceOperatorSignatures(
  state: RolloutState,
  history: string[],
  baseUrl: string,
  fetchImpl: typeof fetch,
  keysPem?: string,
): Promise<void> {
  let keys = keysPem;
  if (keys === undefined) {
    const res = await fetchImpl(new URL("/.well-known/c8s/operator-keys", baseUrl));
    if (!res.ok) {
      fail("verification_failed", `fetching the operator keys returned ${res.status}`);
    }
    keys = await res.text();
  }
  const hash = await operatorKeySetHash(keys);
  if (hash !== state.operator_keys) {
    fail(
      "policy_not_pinned",
      `the attested state names operator key set ${JSON.stringify(state.operator_keys)}, not this one (${hash})`,
    );
  }
  for (const digest of [...new Set([...state.bound, ...history])]) {
    const body = await fetchPolicy(baseUrl, digest, fetchImpl);
    const hex = digest.slice("sha256:".length);
    const res = await fetchImpl(
      new URL(`/.well-known/c8s/objects/sha256/${hex}/signature`, baseUrl),
    );
    if (!res.ok || !(await verifyWriteToken(keys, await res.text(), body))) {
      fail("policy_not_pinned", `policy ${digest} carries no valid operator signature`, {
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
