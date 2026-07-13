// C8sClient request-shaping tests with an injected fetch — no server needed.

import { test } from "node:test";
import assert from "node:assert/strict";

import { C8sClient } from "../src/index.js";
import { generateNonce } from "../src/nonce.js";

/** A fetch stub that records request URLs and returns an empty JSON body. */
function captureFetch(urls: string[]): typeof fetch {
  return (input: RequestInfo | URL) => {
    urls.push(input instanceof Request ? input.url : String(input));
    return Promise.resolve(
      new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    );
  };
}

test("fetchAttestation requests the current protocol without version negotiation", async () => {
  const urls: string[] = [];
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: ["measurement"],
    meshCaPem: "pinned CA",
    fetch: captureFetch(urls),
  });
  await client.fetchAttestation(generateNonce());
  const url = new URL(urls[0]);
  assert.equal(url.pathname, "/.well-known/c8s/attestation");
  assert.equal(url.searchParams.get("binding"), null);
  // 32-byte nonce is 43 chars of unpadded base64url.
  assert.equal(url.searchParams.get("nonce")?.length, 43);
});
