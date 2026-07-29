// C8sClient request-shaping tests with an injected fetch — no server needed.

import { test } from "node:test";
import assert from "node:assert/strict";

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { C8sClient, attestCDSIdentity, decodePEM, MemoryCDSIdentityCache } from "../src/index.js";
import { C8sVerifyError } from "../src/errors.js";
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
  assert.deepEqual([...url.searchParams.keys()], ["nonce"]);
  // 32-byte nonce is 43 chars of unpadded base64url.
  assert.equal(url.searchParams.get("nonce")?.length, 43);
});

// ---------------------------------------------------------------------------
// Deriving the mesh CA from attested CDS claims
// ---------------------------------------------------------------------------
//
// The point of the whole CDS roll-up: the mesh CA stops being a file an
// operator sent you and becomes a value hardware vouched for. CDS's RA-TLS
// certificate commits SHA-256 of the CA it issues under, that commitment is
// folded into REPORTDATA, so a verified CDS identity authenticates the CA.

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const readFixture = (name: string) => readFile(join(FIXTURES, name), "utf8");
// demo/fixtures/mesh-ca.crt is a real CA from a different (demo) cluster —
// the ideal decoy: structurally valid, and not the one the claims name.
const readDecoyCA = () =>
  readFile(
    join(dirname(fileURLToPath(import.meta.url)), "..", "demo", "fixtures", "mesh-ca.crt"),
    "utf8",
  );

const CDS_MRTD =
  "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1";
// Inside the live fixture certificate's 24h validity window.
const CDS_AT = new Date("2026-07-29T12:00:00Z");

const cdsPolicy = () => ({ measurements: [CDS_MRTD], at: CDS_AT });

/** A client in derived mode, with a fetch that is never expected to be used. */
async function derivingClient(extra: Record<string, unknown> = {}) {
  const certificatePem = await readFixture("cds-identity.pem");
  return new C8sClient({
    baseUrl: "http://lb.test",
    measurements: [CDS_MRTD],
    cdsIdentity: { certificatePem, policy: cdsPolicy() },
    fetch: captureFetch([]),
    ...extra,
  });
}

/** An attestation bundle serving `blocks` as the certificate chain. */
const bundleServing = (blocks: string[]) =>
  ({ cds_cert_pem: blocks.join("") }) as unknown as Parameters<C8sClient["deriveMeshCaPem"]>[0];

test("requires exactly one anchor: meshCaPem or cdsIdentity, never both", () => {
  const base = { baseUrl: "http://lb.test", measurements: ["m"], fetch: captureFetch([]) };
  assert.throws(
    () =>
      new C8sClient({
        ...base,
        meshCaPem: "pinned",
        cdsIdentity: { certificatePem: "x", policy: { measurements: ["m"] } },
      }),
    (e: unknown) =>
      e instanceof C8sVerifyError && e.code === "invalid_request" && e.message.includes("not both"),
  );
});

test("requires an anchor at all", () => {
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

test("cdsIdentity needs either an attested identity or a certificatePem", () => {
  assert.throws(
    () =>
      new C8sClient({
        baseUrl: "http://lb.test",
        measurements: ["m"],
        fetch: captureFetch([]),
        cdsIdentity: {} as never,
      }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
});

test("derives the mesh CA from attested claims and pins exactly that certificate", async () => {
  const client = await derivingClient();
  const leaf = await readFixture("cds-identity.pem"); // stands in as the served leaf
  const trueCa = await readFixture("cds-mesh-ca.pem");

  const derived = await client.deriveMeshCaPem(bundleServing([leaf, trueCa]));

  // Exactly one block, and it is the CA the attested claims name.
  const blocks = decodePEM(derived, "CERTIFICATE");
  assert.equal(blocks.length, 1, "the derived anchor must be a single certificate");
  assert.deepEqual(blocks[0], decodePEM(trueCa, "CERTIFICATE")[0]);
});

// The structural kill for the multi-block bypass: even when the server serves a
// bundle, only the block whose digest the claims commit to is pinned. The
// others are not "also trusted" — they are simply not selected.
test("selects only the digest-matching block out of a served multi-cert chain", async () => {
  const client = await derivingClient();
  const leaf = await readFixture("cds-identity.pem");
  const trueCa = await readFixture("cds-mesh-ca.pem");
  const decoy = await readDecoyCA();

  const derived = await client.deriveMeshCaPem(bundleServing([leaf, decoy, trueCa, decoy]));
  const blocks = decodePEM(derived, "CERTIFICATE");
  assert.equal(blocks.length, 1);
  assert.deepEqual(blocks[0], decodePEM(trueCa, "CERTIFICATE")[0]);
  assert.notDeepEqual(blocks[0], decodePEM(decoy, "CERTIFICATE")[0]);
});

test("refuses to derive when no served certificate matches the attested digest", async () => {
  const client = await derivingClient();
  const leaf = await readFixture("cds-identity.pem");
  const decoy = await readDecoyCA();
  await assert.rejects(
    client.deriveMeshCaPem(bundleServing([leaf, decoy])),
    (e: unknown) =>
      e instanceof C8sVerifyError &&
      e.code === "mesh_ca_denied" &&
      e.message.includes("matches the attested mesh-CA digest"),
  );
});

test("refuses to derive when the server serves no CA at all", async () => {
  const client = await derivingClient();
  await assert.rejects(
    client.deriveMeshCaPem(bundleServing([await readFixture("cds-identity.pem")])),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "mesh_ca_denied",
  );
});

// A pre-attested identity is the cache-friendly path: attest once, hand the
// result to as many clients as you like.
test("accepts an already-attested CDSIdentity instead of re-attesting", async () => {
  const identity = await attestCDSIdentity(await readFixture("cds-identity.pem"), cdsPolicy());
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: [CDS_MRTD],
    cdsIdentity: { identity },
    fetch: captureFetch([]),
  });
  const derived = await client.deriveMeshCaPem(
    bundleServing([await readFixture("cds-identity.pem"), await readFixture("cds-mesh-ca.pem")]),
  );
  assert.deepEqual(
    decodePEM(derived, "CERTIFICATE")[0],
    decodePEM(await readFixture("cds-mesh-ca.pem"), "CERTIFICATE")[0],
  );
});

test("a cache passed with cdsIdentity is used, and a second derivation hits it", async () => {
  const cache = new MemoryCDSIdentityCache();
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: [CDS_MRTD],
    cdsIdentity: {
      certificatePem: await readFixture("cds-identity.pem"),
      policy: cdsPolicy(),
      cache,
    },
    fetch: captureFetch([]),
  });
  const served = bundleServing([
    await readFixture("cds-identity.pem"),
    await readFixture("cds-mesh-ca.pem"),
  ]);
  await client.deriveMeshCaPem(served);
  // The cache key defaults to the baseUrl, and the entry lands only after full
  // verification passes.
  assert.ok(cache.get("http://lb.test"), "derivation should have populated the cache");
  await assert.doesNotReject(client.deriveMeshCaPem(served));
});

test("a pinned client refuses to derive", async () => {
  const client = new C8sClient({
    baseUrl: "http://lb.test",
    measurements: ["m"],
    meshCaPem: "pinned",
    fetch: captureFetch([]),
  });
  await assert.rejects(
    client.deriveMeshCaPem(bundleServing([])),
    (e: unknown) => e instanceof C8sVerifyError && e.message.includes("nothing to derive"),
  );
});

test("derived mode leaves policy.meshCaPem unset until a connection resolves it", async () => {
  const client = await derivingClient();
  assert.equal(client.policy.meshCaPem, undefined);
});
