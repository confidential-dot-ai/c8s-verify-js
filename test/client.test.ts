// C8sClient request-shaping tests with an injected fetch — no server needed.

import { test } from "node:test";
import assert from "node:assert/strict";

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { C8sClient } from "../src/index.js";
import { C8sVerifyError } from "../src/errors.js";
import { generateNonce } from "../src/nonce.js";
import { generateXWingKeyPair } from "../src/keyagreement.js";

/** A fetch stub that records request URLs and returns an empty JSON body. */
function captureFetch(urls: string[]): typeof fetch {
  return (input: RequestInfo | URL) => {
    urls.push(input instanceof Request ? input.url : String(input));
    return Promise.resolve(
      new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    );
  };
}

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const readAllowlist = () => readFile(join(FIXTURES, "cds-allowlist.json"));

test("fetchAttestation POSTs attest-pq with only nonce and xwing_ek — no negotiation", async () => {
  const urls: string[] = [];
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: ["measurement"],
    meshCaPem: "pinned CA",
    fetch: captureFetch(urls),
  });
  const keyPair = await generateXWingKeyPair();
  await client.fetchAttestation(generateNonce(), keyPair);
  const url = new URL(urls[0]);
  assert.equal(url.pathname, "/.well-known/c8s/attest-pq");
  // The challenge travels in the body, not the query — no negotiation surface.
  assert.deepEqual([...url.searchParams.keys()], []);
});

// ---------------------------------------------------------------------------
// Anchor rules: meshCaPem (specific-cluster) OR allowlist (deployment-class)
// ---------------------------------------------------------------------------

test("requires an anchor: neither meshCaPem nor allowlist is refused", () => {
  assert.throws(
    () =>
      new C8sClient({
        baseUrl: "http://lb.test",
        measurements: ["m"],
        fetch: captureFetch([]),
      }),
    (e: unknown) =>
      e instanceof C8sVerifyError &&
      e.code === "invalid_request" &&
      e.message.includes("requires an anchor"),
  );
});

test("an empty allowlist is no anchor", () => {
  for (const allowlist of ["", new Uint8Array(0)]) {
    assert.throws(
      () =>
        new C8sClient({
          baseUrl: "http://lb.test",
          measurements: ["m"],
          allowlist,
          fetch: captureFetch([]),
        }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
    );
  }
});

test("an allowlist alone anchors a deployment-class client", async () => {
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: ["m"],
    allowlist: new Uint8Array(await readAllowlist()),
    fetch: captureFetch([]),
  });
  assert.equal(client.policy.meshCaPem, undefined);
  assert.ok(client.policy.allowlist);
});

test("both anchors together are accepted", async () => {
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: ["m"],
    meshCaPem: "pinned CA",
    allowlist: new Uint8Array(await readAllowlist()),
    fetch: captureFetch([]),
  });
  assert.equal(client.policy.meshCaPem, "pinned CA");
  assert.ok(client.policy.allowlist);
});

test("workloadName passes through to the verification policy", () => {
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: ["m"],
    meshCaPem: "pinned CA",
    workloadName: "sglang-dev",
    fetch: captureFetch([]),
  });
  assert.equal(client.policy.workloadName, "sglang-dev");
});

test("generation passes through to the verification policy", () => {
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: ["m"],
    meshCaPem: "pinned CA",
    generation: "genoa",
    fetch: captureFetch([]),
  });
  assert.equal(client.policy.generation, "genoa");
});

test("tdxImage passes through to the verification policy", () => {
  const tdxImage = { mrtd: "1a".repeat(48), rtmr1: "2b".repeat(48), rtmr2: "3c".repeat(48) };
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: ["m"],
    platform: "tdx",
    meshCaPem: "pinned CA",
    tdxImage,
    fetch: captureFetch([]),
  });
  assert.deepEqual(client.policy.tdxImage, tdxImage);
});
