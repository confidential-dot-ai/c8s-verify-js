import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, sign } from "node:crypto";

import {
  enforcePolicyPins,
  fetchPolicy,
  rolloutStateBytes,
  verifyRolloutState,
  type RolloutState,
} from "../src/rollout.js";
import { bytesToBase64, bytesToHex, utf8ToBytes } from "../src/base64.js";
import { C8sVerifyError } from "../src/errors.js";
import { parseCertificate } from "../src/x509.js";
import { loadFixtures } from "./helpers.js";

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
    signature: bytesToBase64(sign("sha384", bytes, { key: caKeyPem, dsaEncoding: "der" })),
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
    signature: bytesToBase64(sign("sha384", badBytes, { key: caKeyPem, dsaEncoding: "der" })),
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
