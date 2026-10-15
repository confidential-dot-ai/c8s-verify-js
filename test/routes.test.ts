// Operator-signed route manifests: the c8s vectors, and the C8sClient flow
// that checks the published manifest against the digest the evidence binds.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { C8sClient, verifyPublishedRoutes, type RouteFloor } from "../src/index.js";
import { C8sVerifyError, type C8sErrorCode } from "../src/errors.js";
import { normalizePath } from "../src/routes.js";
import { base64ToBytes, base64UrlToBytes, bytesToBase64, bytesToBase64Url } from "../src/base64.js";
import { hexToBytes } from "../src/base64.js";
import { decodePEM, encodePEM } from "../src/pem.js";
import type { XWingKeyPair } from "../src/keyagreement.js";
import { DEMO_MEASUREMENTS } from "../demo/config.js";
import { buildBundle, loadFixtures } from "./helpers.js";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "..", "test-vectors");

interface SharedVectors {
  operator_public_key_pem: string;
  other_public_key_pem: string;
  valid: {
    name: string;
    envelope: string;
    route_digest: string;
    revision: number;
    hosts: string[];
  }[];
  invalid: { name: string; envelope: string; c8s_error: string }[];
}

interface EdgeVectors {
  operator_keys_pem: string;
  envelopes: {
    name: string;
    envelope: string;
    valid: boolean;
    route_digest?: string;
    revision?: number;
  }[];
  manifests: { name: string; manifest_b64: string; valid: boolean; revision?: number }[];
  normalize: { raw: string; ok: boolean; path?: string }[];
  select: { manifest: string; cases: { host: string; target: string; route: string | null }[] };
}

const shared = async () =>
  JSON.parse(await readFile(join(VECTORS, "route_v2_vectors.json"), "utf8")) as SharedVectors;
const edge = async () =>
  JSON.parse(await readFile(join(VECTORS, "route_v2_edge_vectors.json"), "utf8")) as EdgeVectors;

const hasCode = (code: C8sErrorCode) => (e: unknown) =>
  e instanceof C8sVerifyError && e.code === code;

/** An operator key that signs manifests the way `c8s routes put` does. */
async function operator() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const segment = (v: unknown) => bytesToBase64Url(new TextEncoder().encode(JSON.stringify(v)));
  return {
    pem: encodePEM(spki, "PUBLIC KEY"),
    async envelope(manifest: Uint8Array): Promise<string> {
      const pbh = new Uint8Array(await crypto.subtle.digest("SHA-256", manifest));
      const input = `${segment({ alg: "ES256", typ: "JWT" })}.${segment({
        exp: 1,
        htm: "PUT",
        htu: "/routes",
        iat: 1,
        pbh: bytesToBase64Url(pbh),
      })}`;
      const sig = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        new TextEncoder().encode(input),
      );
      const token = `${input}.${bytesToBase64Url(new Uint8Array(sig))}`;
      return JSON.stringify({ manifest: bytesToBase64(manifest), token });
    },
  };
}

// ---------------------------------------------------------------------------
// Vectors generated with the c8s pkg/routes code
// ---------------------------------------------------------------------------

test("shared vectors: valid envelopes verify with the c8s digest and revision", async () => {
  const v = await shared();
  for (const c of v.valid) {
    const r = await verifyPublishedRoutes(c.envelope, v.operator_public_key_pem);
    assert.equal(r.routeDigest, c.route_digest, c.name);
    assert.equal(r.revision, c.revision, c.name);
    for (const host of c.hosts) assert.ok(r.routes(host, "/"), `${c.name}: ${host}`);
    await assert.rejects(
      () => verifyPublishedRoutes(c.envelope, v.other_public_key_pem),
      hasCode("route_manifest_denied"),
      `${c.name} under another key`,
    );
  }
});

test("shared vectors: invalid envelopes are refused", async () => {
  const v = await shared();
  for (const c of v.invalid) {
    await assert.rejects(
      () => verifyPublishedRoutes(c.envelope, v.operator_public_key_pem),
      (e: unknown) =>
        e instanceof C8sVerifyError &&
        (e.code === "route_manifest_denied" || e.code === "route_manifest_invalid"),
      `${c.name} (c8s: ${c.c8s_error})`,
    );
  }
});

test("edge vectors: envelopes get the c8s verdict", async () => {
  const v = await edge();
  for (const c of v.envelopes) {
    const got = await verifyPublishedRoutes(c.envelope, v.operator_keys_pem).then(
      (r) => r,
      (e: unknown) => {
        assert.ok(e instanceof C8sVerifyError, `${c.name}: ${String(e)}`);
        return undefined;
      },
    );
    assert.equal(got !== undefined, c.valid, c.name);
    if (got !== undefined) {
      assert.equal(got.routeDigest, c.route_digest, c.name);
      assert.equal(got.revision, c.revision, c.name);
    }
  }
});

test("edge vectors: manifests get the c8s verdict", async () => {
  const v = await edge();
  const key = await operator();
  for (const c of v.manifests) {
    const envelope = await key.envelope(base64ToBytes(c.manifest_b64));
    const got = await verifyPublishedRoutes(envelope, key.pem).then(
      (r) => r.revision,
      (e: unknown) => {
        assert.ok(hasCode("route_manifest_denied")(e), `${c.name}: ${String(e)}`);
        return undefined;
      },
    );
    assert.equal(got !== undefined, c.valid, c.name);
    if (got !== undefined) assert.equal(got, c.revision, c.name);
  }
});

test("edge vectors: path normalization", async () => {
  for (const c of (await edge()).normalize) {
    assert.equal(normalizePath(c.raw), c.ok ? c.path : undefined, JSON.stringify(c.raw));
  }
});

test("edge vectors: route selection", async () => {
  const v = await edge();
  const key = await operator();
  const envelope = await key.envelope(new TextEncoder().encode(v.select.manifest));
  const routes = await verifyPublishedRoutes(envelope, key.pem);
  for (const c of v.select.cases) {
    assert.equal(routes.routes(c.host, c.target), c.route !== null, `${c.host} ${c.target}`);
  }
});

test("operator keys must be ECDSA PUBLIC KEY blocks on a supported curve", async () => {
  const rsa = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const rsaPem = encodePEM(
    new Uint8Array(await crypto.subtle.exportKey("spki", rsa.publicKey)),
    "PUBLIC KEY",
  );
  const v = await shared();
  const { envelope } = v.valid[0];
  const p256 = decodePEM(v.operator_public_key_pem, "PUBLIC KEY")[0];
  const cases: Record<string, string> = {
    empty: "",
    "certificate only": (await loadFixtures()).meshCaPem,
    "RSA key": rsaPem,
    "not DER": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
    "point not uncompressed": encodePEM(
      p256.map((b, i) => (i === p256.length - 65 ? 0x02 : b)),
      "PUBLIC KEY",
    ),
    "data after the key": encodePEM(new Uint8Array([...p256, 0]), "PUBLIC KEY"),
  };
  for (const [name, pem] of Object.entries(cases)) {
    await assert.rejects(
      () => verifyPublishedRoutes(envelope, pem),
      hasCode("invalid_request"),
      name,
    );
  }
});

// ---------------------------------------------------------------------------
// C8sClient with routeOperatorKeys
// ---------------------------------------------------------------------------

type Publication = { status: number; body: string } | Error;

interface RouteServer {
  fetch: typeof fetch;
  publicationFetches: () => number;
  tunnelCalls: () => number;
}

/**
 * A mock router: attest-pq returns a bundle whose transcript binds
 * `routeDigest` (hex); each publication GET takes the next entry.
 */
function routeServer(
  routeDigest: string | (() => string),
  publications: Publication[],
): RouteServer {
  let fetches = 0;
  let tunnel = 0;
  const f = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.endsWith("/attest-pq")) {
      const req = JSON.parse(init?.body as string) as { nonce: string; xwing_ek: string };
      const { bundle } = await buildBundle(base64UrlToBytes(req.nonce), {
        clientKeyPair: { ek: base64UrlToBytes(req.xwing_ek) } as XWingKeyPair,
        routeDigest: hexToBytes(typeof routeDigest === "string" ? routeDigest : routeDigest()),
      });
      return new Response(JSON.stringify(bundle), { status: 200 });
    }
    if (url.endsWith("/.well-known/c8s/routes")) {
      assert.equal(init?.cache, "no-store");
      const next = publications[fetches++];
      if (next === undefined) throw new Error("unexpected publication fetch");
      if (next instanceof Error) throw next;
      return new Response(next.body, { status: next.status });
    }
    if (url.endsWith("/tunnel")) {
      tunnel++;
      return new Response("", { status: 502 });
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  return { fetch: f, publicationFetches: () => fetches, tunnelCalls: () => tunnel };
}

async function routeClient(fetchFn: typeof fetch, keys: string, routeFloor?: RouteFloor) {
  return new C8sClient({
    baseUrl: "https://app.example",
    measurements: DEMO_MEASUREMENTS,
    requireFreshness: false,
    meshCaPem: (await loadFixtures()).meshCaPem,
    routeOperatorKeys: keys,
    routeFloor,
    fetch: fetchFn,
  });
}

const ok = (body: string): Publication => ({ status: 200, body });

test("connect checks the published manifest against the evidence", async () => {
  const v = await shared();
  const [r12, r13] = v.valid;
  const d12 = r12.route_digest;
  const d13 = r13.route_digest;
  const withDuplicateToken = r12.envelope.replace(/}$/, `,"token":"x"}`);
  const cases: {
    name: string;
    bound: string;
    publications: Publication[];
    keys?: string;
    floor?: RouteFloor;
    want: number | C8sErrorCode;
  }[] = [
    { name: "matching publication", bound: d12, publications: [ok(r12.envelope)], want: 12 },
    {
      name: "untrusted key",
      bound: d12,
      publications: [ok(r12.envelope)],
      keys: v.other_public_key_pem,
      want: "route_manifest_denied",
    },
    {
      name: "tampered manifest",
      bound: d12,
      publications: [ok(v.invalid[1].envelope)],
      want: "route_manifest_denied",
    },
    {
      name: "mismatch, then a newer revision that matches",
      bound: d13,
      publications: [ok(r12.envelope), ok(r13.envelope)],
      want: 13,
    },
    {
      name: "mismatch, then the same revision",
      bound: d13,
      publications: [ok(r12.envelope), ok(r12.envelope)],
      want: "route_manifest_denied",
    },
    {
      name: "mismatch, then a lower revision, even one that matches",
      bound: d12,
      publications: [ok(r13.envelope), ok(r12.envelope)],
      want: "route_manifest_denied",
    },
    {
      name: "mismatch, then a newer revision that does not match",
      bound: "5a".repeat(32),
      publications: [ok(r12.envelope), ok(r13.envelope)],
      want: "route_denied",
    },
    {
      name: "floor above the published revision",
      bound: d12,
      publications: [ok(r12.envelope)],
      floor: { revision: 13, digest: d13 },
      want: "route_manifest_denied",
    },
    {
      name: "floor at the published revision with another digest",
      bound: d12,
      publications: [ok(r12.envelope)],
      floor: { revision: 12, digest: d13 },
      want: "route_manifest_denied",
    },
    {
      name: "first fetch below the floor, then the bound revision",
      bound: d13,
      publications: [ok(r12.envelope), ok(r13.envelope)],
      floor: { revision: 13, digest: d13 },
      want: 13,
    },
    {
      name: "floor at the published manifest",
      bound: d12,
      publications: [ok(r12.envelope)],
      floor: { revision: 12, digest: d12 },
      want: 12,
    },
    {
      name: "publication off",
      bound: d12,
      publications: [{ status: 404, body: "" }],
      want: "route_manifest_unavailable",
    },
    {
      name: "server error",
      bound: d12,
      publications: [{ status: 503, body: r12.envelope }],
      want: "route_manifest_unavailable",
    },
    {
      name: "network failure",
      bound: d12,
      publications: [new TypeError("fetch failed")],
      want: "route_manifest_unavailable",
    },
    {
      name: "malformed envelope",
      bound: d12,
      publications: [ok(`{"manifest":"","token":"a.b.c"`)],
      want: "route_manifest_invalid",
    },
    {
      name: "duplicate envelope member",
      bound: d12,
      publications: [ok(withDuplicateToken)],
      want: "route_manifest_invalid",
    },
    {
      name: "oversized body",
      bound: d12,
      publications: [ok(" ".repeat((4 << 20) + 1))],
      want: "route_manifest_invalid",
    },
  ];
  for (const c of cases) {
    const server = routeServer(c.bound, c.publications);
    const client = await routeClient(server.fetch, c.keys ?? v.operator_public_key_pem, c.floor);
    if (typeof c.want === "number") {
      const session = await client.connect();
      assert.equal(session.attestation.routePolicy, "operator-signed", c.name);
      assert.equal(session.attestation.routeRevision, c.want, c.name);
      assert.equal(session.attestation.routeDigest, c.bound, c.name);
      assert.deepEqual(client.routeFloor, { revision: c.want, digest: c.bound }, c.name);
    } else {
      await assert.rejects(() => client.connect(), hasCode(c.want), c.name);
      assert.deepEqual(client.routeFloor, c.floor, `${c.name}: floor unchanged`);
    }
    assert.equal(server.publicationFetches(), c.publications.length, `${c.name}: fetches`);
  }
});

test("connect keeps the accepted revision and refuses a later rollback", async () => {
  const v = await shared();
  const [r12, r13] = v.valid;
  let bound = r13.route_digest;
  const server = routeServer(() => bound, [ok(r13.envelope), ok(r12.envelope)]);
  const client = await routeClient(server.fetch, v.operator_public_key_pem);
  await client.connect();
  assert.deepEqual(client.routeFloor, { revision: 13, digest: r13.route_digest });

  bound = r12.route_digest;
  await assert.rejects(() => client.connect(), hasCode("route_manifest_denied"));
  assert.deepEqual(client.routeFloor, { revision: 13, digest: r13.route_digest });
  assert.equal(server.publicationFetches(), 2);
});

test("a connect that loses a race to a newer revision does not lower the floor", async () => {
  const v = await shared();
  const [r12, r13] = v.valid;
  let bound = r12.route_digest;
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  let reached!: () => void;
  const atPublication = new Promise<void>((resolve) => (reached = resolve));
  // The held first fetch reaches the server after the second one.
  const server = routeServer(() => bound, [ok(r13.envelope), ok(r12.envelope)]);
  let publications = 0;
  const f: typeof fetch = async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.endsWith("/routes") && publications++ === 0) {
      reached();
      await held;
    }
    return server.fetch(input, init);
  };
  const client = await routeClient(f, v.operator_public_key_pem);
  const first = client.connect();
  await atPublication;
  bound = r13.route_digest;
  await client.connect();
  assert.deepEqual(client.routeFloor, { revision: 13, digest: r13.route_digest });
  release();
  await assert.rejects(first, hasCode("route_manifest_denied"));
  assert.deepEqual(client.routeFloor, { revision: 13, digest: r13.route_digest });
});

test("a session refuses requests the attested manifest does not route", async () => {
  const v = await shared();
  const r12 = v.valid[0];
  const server = routeServer(r12.route_digest, [ok(r12.envelope)]);
  const session = await (await routeClient(server.fetch, v.operator_public_key_pem)).connect();
  for (const [path, headers] of [
    ["/", { Host: "other.example" }],
    ["/a//b", {}],
    ["/%2F", {}],
  ] as [string, Record<string, string>][]) {
    await assert.rejects(
      () => session.fetch(path, { headers }),
      hasCode("route_unmatched"),
      `${path} ${JSON.stringify(headers)}`,
    );
  }
  assert.equal(server.tunnelCalls(), 0);
  // Routed: the request reaches the tunnel, whose stub answers 502.
  await assert.rejects(() => session.fetch("/admin/users"), hasCode("channel_error"));
  assert.equal(server.tunnelCalls(), 1);
});

test("routeOperatorKeys options are validated at construction", async () => {
  const v = await shared();
  const base = {
    baseUrl: "https://app.example",
    measurements: ["m"],
    meshCaPem: "pinned CA",
    fetch: routeServer("", []).fetch,
  };
  const keys = v.operator_public_key_pem;
  const digest = v.valid[0].route_digest;
  const cases: Record<string, ConstructorParameters<typeof C8sClient>[0]> = {
    "with routeDigests": { ...base, routeOperatorKeys: keys, routeDigests: [digest] },
    "floor without keys": { ...base, routeFloor: { revision: 1, digest } },
    "floor revision 0": { ...base, routeOperatorKeys: keys, routeFloor: { revision: 0, digest } },
    "floor revision 1.5": {
      ...base,
      routeOperatorKeys: keys,
      routeFloor: { revision: 1.5, digest },
    },
    "floor digest upper case": {
      ...base,
      routeOperatorKeys: keys,
      routeFloor: { revision: 1, digest: digest.toUpperCase() },
    },
    "no PUBLIC KEY block": { ...base, routeOperatorKeys: "pinned CA" },
    "PUBLIC KEY block not base64": {
      ...base,
      routeOperatorKeys: "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n",
    },
    "floor null": { ...base, routeOperatorKeys: keys, routeFloor: null as unknown as RouteFloor },
  };
  for (const [name, opts] of Object.entries(cases)) {
    assert.throws(() => new C8sClient(opts), hasCode("invalid_request"), name);
  }
  const client = new C8sClient({
    ...base,
    routeOperatorKeys: keys,
    routeFloor: { revision: 3, digest },
  });
  assert.deepEqual(client.routeFloor, { revision: 3, digest });
});
