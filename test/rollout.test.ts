import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { readFileSync } from "node:fs";

import {
  enforcePolicyPins,
  extendRegister,
  fetchPolicy,
  operatorKeySetHash,
  replayHistory,
  verifyWriteToken,
  rolloutStateBytes,
  verifyRolloutState,
  type RolloutState,
} from "../src/rollout.js";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  hexToBytes,
  utf8ToBytes,
} from "../src/base64.js";
import { C8sVerifyError } from "../src/errors.js";
import { parseCertificate } from "../src/x509.js";
import { loadFixtures, signState, stateWindow } from "./helpers.js";

const P = `sha256:${"a".repeat(64)}`;
const Q = `sha256:${"b".repeat(64)}`;

function state(overrides: Partial<RolloutState> = {}): RolloutState {
  return {
    protocol: 1,
    authority: "sha256:aa",
    position: 1,
    head: "sha256:bb",
    allowlist_version: "2",
    policy: Q,
    bound: [P, Q],
    lease_seconds: 30,
    operator_keys: "none",
    ...stateWindow(),
    ...overrides,
  };
}

const code = (want: string) => (e: unknown) => e instanceof C8sVerifyError && e.code === want;

test("verifies a CA-signed state bound to the nonce", async () => {
  const { caKeyPem, caDer } = await loadFixtures();
  const nonce = new Uint8Array(32).fill(7);
  const bytes = utf8ToBytes(JSON.stringify(state({ nonce: bytesToHex(nonce) })));
  const signed = {
    state: bytesToBase64(bytes),
    signature: signState(bytes, caKeyPem),
  };
  const decoded = rolloutStateBytes(signed)!;
  const ca = parseCertificate(caDer);
  assert.deepEqual((await verifyRolloutState(signed, decoded, ca, nonce)).bound, [P, Q]);
  await assert.rejects(
    () => verifyRolloutState(signed, decoded, ca, new Uint8Array(32)),
    code("rollout_state_invalid"),
  );

  const badBytes = utf8ToBytes(JSON.stringify(state({ bound: ["P"], nonce: bytesToHex(nonce) })));
  const badSigned = {
    state: bytesToBase64(badBytes),
    signature: signState(badBytes, caKeyPem),
  };
  await assert.rejects(
    () => verifyRolloutState(badSigned, badBytes, ca, nonce),
    code("rollout_state_invalid"),
  );
  assert.equal(rolloutStateBytes(null), undefined);
});

test("enforces policy pins", () => {
  enforcePolicyPins(state(), [P, Q]);
  assert.throws(() => enforcePolicyPins(state(), [P]), code("policy_not_pinned"));
  assert.throws(
    () => enforcePolicyPins(state({ lease_seconds: 0 }), [P, Q]),
    code("rollout_state_invalid"),
  );
  assert.throws(() => enforcePolicyPins(undefined, [P]), code("rollout_state_invalid"));
});

test("fetchPolicy keeps only bytes that hash to the digest", async () => {
  const policy = utf8ToBytes('{"workloads":{}}');
  const digest = `sha256:${createHash("sha256").update(policy).digest("hex")}`;
  const serve = (body: Uint8Array) =>
    (() => Promise.resolve(new Response(body))) as unknown as typeof fetch;
  assert.deepEqual(await fetchPolicy("https://router.example", digest, serve(policy)), policy);
  await assert.rejects(
    () => fetchPolicy("https://router.example", digest, serve(utf8ToBytes("tampered"))),
    code("allowlist_denied"),
  );
  for (const bad of ["md5:x", `sha256:${"A".repeat(64)}`, 42 as unknown as string]) {
    await assert.rejects(() => fetchPolicy("https://router.example", bad), code("invalid_request"));
  }
});

test("verifies a c8s operator write token and key-set hash", async () => {
  const v = JSON.parse(
    readFileSync(
      new URL("../test-vectors/operator_signature_vector.json", import.meta.url),
      "utf8",
    ),
  ) as { operator_keys_pem: string; operator_keys_hash: string; policy_b64: string; token: string };
  assert.equal(await operatorKeySetHash(v.operator_keys_pem), v.operator_keys_hash);
  const policy = base64ToBytes(v.policy_b64);
  assert.equal(await verifyWriteToken(v.operator_keys_pem, v.token, policy), true);
  assert.equal(await verifyWriteToken(v.operator_keys_pem, v.token, utf8ToBytes("{}")), false);
  const [h, c] = v.token.split(".");
  assert.equal(
    await verifyWriteToken(v.operator_keys_pem, `${h}.${c}.${"A".repeat(86)}`, policy),
    false,
  );
});

test("replays the measured history onto the RTMR[3] pin", async () => {
  const seed = "5e".repeat(48);
  const reg = bytesToHex(await extendRegister(hexToBytes(seed), P));
  assert.deepEqual(await replayHistory(seed, [P, Q], reg), [P]);
  assert.equal(await replayHistory(seed, [Q], reg), undefined);
  assert.throws(
    () => enforcePolicyPins(state(), [P, Q], [`sha256:${"c".repeat(64)}`]),
    code("policy_not_pinned"),
  );
});

test("refuses a state outside its validity window", async () => {
  const { caKeyPem, caDer } = await loadFixtures();
  const nonce = new Uint8Array(32).fill(7);
  const old = Math.floor(Date.now() / 1000) - 3600;
  const bytes = utf8ToBytes(
    JSON.stringify(state({ nonce: bytesToHex(nonce), issued_at: old, expires_at: old + 60 })),
  );
  const signed = { state: bytesToBase64(bytes), signature: signState(bytes, caKeyPem) };
  await assert.rejects(
    () => verifyRolloutState(signed, bytes, parseCertificate(caDer), nonce),
    code("rollout_state_invalid"),
  );
});
