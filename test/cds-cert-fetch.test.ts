import { test } from "node:test";
import assert from "node:assert/strict";

import { C8sClient, type C8sClientOptions } from "../src/index.js";

const PEM = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n";

type FetchHandler = (url: string, init?: unknown) => unknown;

/** Build a client whose fetch records the URLs it is asked for. These tests
 *  exercise only fetchCdsCert (no attestation), so the insecure entry point —
 *  which skips the measurement / mesh-CA pins — is the right constructor. */
function clientWith(handler: FetchHandler, opts: Partial<C8sClientOptions> = {}) {
  const calls: string[] = [];
  const fetch = ((url: string, init?: unknown) => {
    calls.push(url);
    return Promise.resolve(handler(url, init));
  }) as unknown as typeof globalThis.fetch;
  return {
    calls,
    client: C8sClient.insecure({ baseUrl: "https://lb.example", fetch, ...opts }),
  };
}

test("fetchCdsCert: returns the PEM the discovery endpoint serves", async () => {
  const { client, calls } = clientWith(() => ({
    ok: true,
    text() {
      return PEM;
    },
  }));
  const pem = await client.fetchCdsCert();
  assert.equal(pem, PEM);
  assert.deepEqual(calls, ["https://lb.example/.well-known/cds-cert.pem"]);
});

test("fetchCdsCert: returns null on a non-2xx response (e.g. discovery disabled)", async () => {
  const { client } = clientWith(() => ({
    ok: false,
    status: 404,
    text() {
      return "not found";
    },
  }));
  assert.equal(await client.fetchCdsCert(), null);
});

test("fetchCdsCert: returns null when the body is not a PEM (e.g. an HTML error page)", async () => {
  const { client } = clientWith(() => ({
    ok: true,
    text() {
      return "<html>404</html>";
    },
  }));
  assert.equal(await client.fetchCdsCert(), null);
});

test("fetchCdsCert: returns null on a network error (best-effort, never throws)", async () => {
  const { client } = clientWith(() => {
    throw new Error("ECONNREFUSED");
  });
  assert.equal(await client.fetchCdsCert(), null);
});

test("fetchCdsCert: disabled via cdsCertPath=null makes no request", async () => {
  const { client, calls } = clientWith(
    () => ({
      ok: true,
      text() {
        return PEM;
      },
    }),
    { cdsCertPath: null },
  );
  assert.equal(await client.fetchCdsCert(), null);
  assert.deepEqual(calls, []);
});

test("cdsCertPath is overridable", async () => {
  const { client, calls } = clientWith(
    () => ({
      ok: true,
      text() {
        return PEM;
      },
    }),
    { cdsCertPath: "/custom/leaf.pem" },
  );
  await client.fetchCdsCert();
  assert.deepEqual(calls, ["https://lb.example/custom/leaf.pem"]);
});
