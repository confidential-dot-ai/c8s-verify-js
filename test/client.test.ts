// C8sClient request-shaping tests with an injected fetch — no server needed.

import { test } from "node:test";
import assert from "node:assert/strict";

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { C8sClient, Session } from "../src/index.js";
import { C8sVerifyError } from "../src/errors.js";
import { generateNonce } from "../src/nonce.js";
import { deriveChannel, generateXWingKeyPair } from "../src/keyagreement.js";
import { cborDecode, cborEncode } from "../src/cbor.js";
import type { WireRecord } from "../src/channel.js";
import type { AttestationResult } from "../src/verify.js";

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

// ---------------------------------------------------------------------------
// Session.fetch: the router routes by the sealed Host and an origin-form path
// ---------------------------------------------------------------------------

interface SentEnvelope {
  method: string;
  path: string;
  headers: [string, string][];
}

/**
 * A Session against `baseUrl` whose tunnel stub opens each sealed request,
 * records its envelope, and seals an empty 200 back.
 */
async function tunnelSession(baseUrl: string, sent: SentEnvelope[]): Promise<Session> {
  const secret = new Uint8Array(32).fill(0x07);
  const transcript = new Uint8Array(48).fill(0x33);
  const sessionId = new Uint8Array(16).fill(0x0f);
  const client = await deriveChannel("client", secret, transcript, sessionId);
  const server = await deriveChannel("server", secret, transcript, sessionId);
  const stub = async (_input: RequestInfo | URL, init?: RequestInit) => {
    const record = cborDecode(init?.body as Uint8Array) as unknown as WireRecord;
    sent.push(cborDecode(await server.openRequest(record)) as unknown as SentEnvelope);
    const reply = await server.sealResponse(cborEncode({ status: 200 }), record.seq);
    return new Response(cborEncode({ seq: reply.seq, ct: reply.ct }), { status: 200 });
  };
  return new Session({
    baseUrl,
    prefix: "/.well-known/c8s",
    fetch: stub,
    channel: client,
    sessionId: "session",
    attestation: {} as AttestationResult,
  });
}

const hosts = (envelope: SentEnvelope) =>
  envelope.headers.filter(([name]) => name.toLowerCase() === "host").map(([, value]) => value);

test("fetch seals Host from the base URL when the caller sends none", async () => {
  const cases = [
    { baseUrl: "https://lb.test", want: "lb.test" },
    { baseUrl: "https://lb.test:443", want: "lb.test" },
    { baseUrl: "https://lb.test:8443", want: "lb.test:8443" },
    { baseUrl: "http://lb.test:80", want: "lb.test" },
    { baseUrl: "http://[::1]:8080", want: "[::1]:8080" },
  ];
  for (const { baseUrl, want } of cases) {
    const sent: SentEnvelope[] = [];
    const session = await tunnelSession(baseUrl, sent);
    await session.fetch("/v1/chat", { headers: { accept: "text/plain" } });
    assert.deepEqual(hosts(sent[0]), [want], baseUrl);
  }
});

test("fetch keeps a caller Host of any case and adds none", async () => {
  for (const headers of [{ HOST: "api.test" }, [["host", "api.test"]] as [string, string][]]) {
    const sent: SentEnvelope[] = [];
    const session = await tunnelSession("https://lb.test", sent);
    await session.fetch("/", { headers });
    assert.deepEqual(hosts(sent[0]), ["api.test"]);
  }
});

test("fetch refuses an empty Host and an Upgrade before sealing", async () => {
  const sent: SentEnvelope[] = [];
  const session = await tunnelSession("https://lb.test", sent);
  const cases: Record<string, string>[] = [{ Host: "" }, { host: "  " }, { Upgrade: "websocket" }];
  for (const headers of cases) {
    await assert.rejects(
      () => session.fetch("/", { headers }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      JSON.stringify(headers),
    );
  }
  assert.equal(sent.length, 0);
});

test("fetch refuses more than one Host before sealing", async () => {
  const sent: SentEnvelope[] = [];
  const session = await tunnelSession("https://lb.test", sent);
  await assert.rejects(
    () =>
      session.fetch("/", {
        headers: [
          ["Host", "a.test"],
          ["host", "b.test"],
        ],
      }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
  assert.equal(sent.length, 0);
});

test("fetch refuses a path that is not in origin form before sealing", async () => {
  const sent: SentEnvelope[] = [];
  const session = await tunnelSession("https://lb.test", sent);
  for (const path of ["", "v1/chat", "https://other.test/v1", "*"]) {
    await assert.rejects(
      () => session.fetch(path),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      path,
    );
  }
  assert.equal(sent.length, 0);
});

test("a base URL with no host to resolve against is refused at construction", () => {
  for (const baseUrl of ["/lb", "/", "localhost:8080", "lb.test:8443", "file:///x"]) {
    assert.throws(
      () =>
        new C8sClient({
          baseUrl,
          measurements: ["m"],
          meshCaPem: "pinned CA",
          fetch: captureFetch([]),
        }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      baseUrl,
    );
  }
});

test("routeDigests are validated at construction and reach the policy", () => {
  const options = {
    baseUrl: "http://lb.test",
    measurements: ["m"],
    meshCaPem: "pinned CA",
    fetch: captureFetch([]),
  };
  const pins = ["ab".repeat(32), "cd".repeat(32)];
  assert.deepEqual(new C8sClient({ ...options, routeDigests: pins }).policy.routeDigests, pins);
  for (const routeDigests of [[], ["AB".repeat(32)], ["ab".repeat(31)]]) {
    assert.throws(
      () => new C8sClient({ ...options, routeDigests }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      JSON.stringify(routeDigests),
    );
  }
});
