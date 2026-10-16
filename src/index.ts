// c8s-verify: public API.
//
// Verify that a remote API is served by a genuine, TEE-attested, CDS-issued C8s
// Load Balancer, then talk to it over a post-quantum over-encrypted channel that
// terminates inside the LB's enclave — so a malicious TLS-terminating proxy in
// front of the LB cannot read or forge application traffic.
//
//   const client = new C8sClient({ baseUrl, measurements: [...], meshCaPem });
//   const session = await client.connect();
//   console.log(session.attestation.measurement);
//   const res = await session.fetch("/v1/chat", { method: "POST", body: "..." });

import { generateNonce } from "./nonce.js";
import {
  validateRouteDigests,
  verifyAttestation,
  type AttestationBundle,
  type AttestationResult,
  type SnpMinTcb,
  type VerifyPolicy,
} from "./verify.js";
import {
  deriveChannel,
  generateXWingKeyPair,
  xwingDecapsulate,
  type XWingKeyPair,
} from "./keyagreement.js";
import type { Channel, WireRecord } from "./channel.js";
import { cborEncode, cborDecode } from "./cbor.js";
import { bytesToBase64Url, bytesToUtf8, utf8ToBytes } from "./base64.js";
import { C8sVerifyError, fail } from "./errors.js";
import type { TdxImage } from "./manifest.js";
import type { TdxCollateral, TdxTcbStatus } from "./tdx-tcb.js";
import {
  MAX_ROUTE_PUBLICATION_BYTES,
  checkRouteFloor,
  importRouteOperatorKeys,
  parseRouteOperatorKeys,
  validateRouteFloor,
  verifySignedRoutes,
  type PublishedRoutes,
  type RouteFloor,
} from "./routes.js";

export { C8sVerifyError } from "./errors.js";
export type { C8sErrorCode } from "./errors.js";
export { BINDING_ATTEST_PQ, TRANSCRIPT_DOMAIN_TAG } from "./identity.js";
export type { MeshIdentityProof } from "./identity.js";
export { verifyAttestation, verifyEvidence } from "./verify.js";
export type {
  VerifyPolicy,
  AttestationBundle,
  AttestationResult,
  EvidenceResult,
  VerifyEvidenceOptions,
  CertInfo,
  WorkloadInfo,
  SnpMinTcb,
} from "./verify.js";
// The matched-workload stamp: parse the mesh leaf's .1.5 extension and the
// allowlist document it pins. verifyAttestation applies these automatically
// when the policy pins workloadName/allowlist; they are exported for callers
// that verify certificates through their own transport.
export {
  OID_MATCHED_WORKLOAD,
  parseMatchedWorkload,
  parseAllowlist,
  resolveWorkload,
  allowlistDigestHex,
} from "./workload.js";
export type { MatchedWorkload, AllowlistDocument, AllowlistWorkload } from "./workload.js";
// The TDX image pin: parse a published build-artifact manifest into the
// mrtd+rtmr1+rtmr2 tuple `tdxImage` enforces.
export { parseImageManifest } from "./manifest.js";
export type { TdxImage } from "./manifest.js";
export type { TdxCollateral, TdxTcbResult, TdxTcbStatus } from "./tdx-tcb.js";
// Signed route manifests: verify a /.well-known/c8s/routes body yourself.
export { verifyPublishedRoutes } from "./routes.js";
export type { PublishedRoutes, RouteFloor } from "./routes.js";
export { decodePEM, decodeOnePEM, encodePEM } from "./pem.js";
export { generateNonce } from "./nonce.js";
export { initVerifier, verifySnp, verifyAzSnp, verifyAzTdx, verifyTdx } from "./wasm-loader.js";
export type { Evidence, SnpEvidence, AzSnpEvidence, AzTdxEvidence, TdxEvidence } from "./hcl.js";

const WELL_KNOWN = "/.well-known/c8s";

export interface C8sClientOptions {
  baseUrl: string;
  /** Accepted launch digests (hex SHA-384). Required unless `tdxImage` is set; mutually exclusive with it. */
  measurements?: string[];
  platform?: string;
  /**
   * SEV-SNP processor generation ("milan" | "genoa" | "turin"), pinned out of
   * band; `platform: "snp"` only. Optional — the generation selects the VCEK
   * chain the report is verified against, so an unpinned one is authenticated
   * by that chain rather than believed. See `VerifyPolicy.generation`.
   */
  generation?: string;
  requireFreshness?: boolean;
  /**
   * Mesh CA pinned out of band — the specific-cluster anchor. At least one of
   * `meshCaPem` and `allowlist` is required; both together is fine.
   *
   * Multiple PEM blocks mean *each block is independently trusted* as an
   * anchor: the identity proof selects whichever one it names. That is
   * occasionally what you want during a CA rotation, and a footgun the rest
   * of the time, so prefer a single block.
   */
  meshCaPem?: string;
  /**
   * Exact canonical allowlist bytes, pinned out of band — the
   * deployment-class anchor. A string is UTF-8-encoded verbatim, never
   * parsed-and-reserialized. Requires the mesh leaf's matched-workload stamp
   * to commit SHA-256 of exactly these bytes and resolves the stamped name in
   * the document; the mesh CA is then derived from the identity transcript's
   * commitment instead of pinned (`attestation.trustClass` reports which
   * verdict you got).
   */
  allowlist?: Uint8Array | string;
  /**
   * Expected matched-workload name on the mesh leaf. Optional; enforced
   * against the CA-vouched stamp after the chain check, which either anchor
   * provides.
   */
  workloadName?: string;
  at?: Date;
  fetch?: typeof fetch;
  wellKnownPrefix?: string;
  /**
   * Expected TDX RTMR[3] (96 hex chars), pinned out of band. Optional but
   * strongly recommended: `measurements` proves the node runs the audited
   * build, not that it is *your* node — the images are reproducible, so anyone
   * can stand up an instance with the same launch digest. RTMR[3] carries the
   * operator key bound at launch, which is unique to a deployment and, unlike
   * `meshCaPem`, survives reinstalls and image rebuilds. Requires
   * `platform: "tdx"`.
   */
  expectedRtmr3?: string;
  /**
   * The complete TDX guest-image pin: the mrtd+rtmr1+rtmr2 tuple published
   * with the image build (feed the manifest file to `parseImageManifest`).
   * `measurements` alone pins only MRTD — the TDVF firmware — while the guest
   * kernel and rootfs land in RTMR[1]/RTMR[2], so only the tuple identifies
   * the image. Replaces `measurements`. Required for a TDX deployment-class
   * verdict (no `meshCaPem`); strongly recommended otherwise. Requires a TDX
   * platform.
   */
  tdxImage?: TdxImage;
  /**
   * Minimum SEV-SNP TCB floor, pinned from AMD security bulletins. A genuine,
   * correctly-measured guest on platform firmware below the floor is
   * rejected (`tcb_denied`). SNP platforms only. See `VerifyPolicy.minTcb`.
   */
  minTcb?: SnpMinTcb;
  /**
   * DER AMD KDS CRL for the deployment's processor generation, fetched or
   * stapled by the caller. Supplying it makes endorsement-key revocation part
   * of every connection's verdict. SNP platforms only. See
   * `VerifyPolicy.snpCrl`.
   */
  snpCrl?: Uint8Array;
  /**
   * Require the revocation collateral to be verified for the verdict to pass
   * (production policy). Requires `snpCrl` or `tdxCollateral`. See
   * `VerifyPolicy.requireCollateral`.
   */
  requireCollateral?: boolean;
  /**
   * Intel PCS collateral for the TDX quote, fetched by the caller. Supplying
   * it makes PCK revocation and the TCB status part of every connection's
   * verdict (`attestation.tdxTcb`). `platform: "tdx"` only. See
   * `VerifyPolicy.tdxCollateral`.
   */
  tdxCollateral?: TdxCollateral;
  /**
   * TDX TCB statuses to accept, default `["UpToDate"]`. Requires
   * `tdxCollateral`. See `VerifyPolicy.tdxTcbStatuses`.
   */
  tdxTcbStatuses?: TdxTcbStatus[];
  /**
   * Accepted route digests (64 lowercase hex each, as `c8s routes digest`
   * prints them). Optional; any one must match the digest the evidence
   * binds. See `VerifyPolicy.routeDigests`. Excludes `routeOperatorKeys`.
   */
  routeDigests?: string[];
  /**
   * Operator public keys (PEM PUBLIC KEY blocks, ECDSA P-256, P-384 or
   * P-521) the route manifest must be signed under. Optional. Before each
   * handshake, `connect` fetches the manifest the router publishes at
   * `/.well-known/c8s/routes`, verifies it under these keys and requires its
   * digest to be the one the evidence binds, fetching once more on a
   * mismatch. Requires route publication on the router, and CORS on that
   * path for a browser. Excludes `routeDigests`. A malformed key fails construction; a
   * point WebCrypto refuses fails every `connect`, before the handshake.
   */
  routeOperatorKeys?: string;
  /**
   * The revision and digest of the manifest last accepted, to refuse a
   * rollback: an older revision, or this revision with another digest.
   * Requires `routeOperatorKeys`. The client raises the floor in memory as it
   * accepts newer revisions, and retries a connection below it once, in case
   * a replica lags; read `routeFloor` to persist it.
   */
  routeFloor?: RouteFloor;
}

export interface RequestInit {
  method?: string;
  /**
   * Request headers: a plain record, or ordered [name, value] pairs when a
   * field repeats (Cookie). Duplicate pairs reach the backend intact. Without
   * a `Host` field, `Host` is the base URL's host; more than one is refused.
   * Names and values must be strings.
   */
  headers?: Record<string, string> | [string, string][];
  body?: string | Uint8Array;
}

export interface TunnelResponse {
  status: number;
  /** First value of each field. Use headersList for repeated fields. */
  headers: Record<string, string>;
  /** Every header field in response order as [name, value] pairs. */
  headersList: [string, string][];
  bytes: Uint8Array;
  text: () => string;
}

/** Response envelope decoded from a sealed tunnel record. */
interface ResponseEnvelope {
  status: number;
  headers?: [string, string][];
  body?: Uint8Array;
}

interface SessionOptions {
  baseUrl: string;
  prefix: string;
  fetch: typeof fetch;
  channel: Channel;
  sessionId: string;
  attestation: AttestationResult;
  /** The operator-signed manifest the evidence binds; requests it does not route are refused. */
  routes?: PublishedRoutes;
}

export class C8sClient {
  readonly baseUrl: string;
  readonly prefix: string;
  readonly fetch: typeof fetch;
  /** Verification policy applied to every connection. */
  readonly policy: VerifyPolicy;
  private readonly routeKeys?: Promise<CryptoKey[]>;
  private floor?: RouteFloor;

  constructor(opts: C8sClientOptions) {
    if (!opts?.baseUrl) {
      throw new C8sVerifyError("invalid_request", "baseUrl is required");
    }
    // At least one anchor: a pinned mesh CA (specific-cluster), pinned
    // canonical allowlist bytes enforced against the workload stamp
    // (deployment-class), or both. verifyAttestation re-validates the shapes;
    // refusing an anchorless client here means the misconfiguration surfaces
    // at construction, not at the first connection.
    const hasPem = typeof opts.meshCaPem === "string" && opts.meshCaPem.trim() !== "";
    const hasAllowlist = opts.allowlist !== undefined && opts.allowlist.length > 0;
    if (!hasPem && !hasAllowlist) {
      throw new C8sVerifyError(
        "invalid_request",
        "verification requires an anchor: pass meshCaPem to pin the mesh CA out of band " +
          "(specific-cluster), or allowlist with the exact canonical allowlist bytes to enforce " +
          "against the mesh leaf's matched-workload stamp (deployment-class), or both",
      );
    }
    validateRouteDigests(opts.routeDigests);
    if (opts.routeDigests !== undefined && opts.routeOperatorKeys !== undefined) {
      throw new C8sVerifyError(
        "invalid_request",
        "pass one of routeDigests and routeOperatorKeys: each is a complete route digest check",
      );
    }
    if (opts.routeFloor !== undefined && opts.routeOperatorKeys === undefined) {
      throw new C8sVerifyError("invalid_request", "routeFloor requires routeOperatorKeys");
    }
    validateRouteFloor(opts.routeFloor);
    if (opts.routeOperatorKeys !== undefined) {
      this.routeKeys = importRouteOperatorKeys(parseRouteOperatorKeys(opts.routeOperatorKeys));
      // connect awaits it; until then, keep a rejection from going unhandled.
      this.routeKeys.catch(() => undefined);
      this.floor = opts.routeFloor && { ...opts.routeFloor };
    }
    let baseUrl = opts.baseUrl;
    while (baseUrl.endsWith("/")) baseUrl = baseUrl.slice(0, -1);
    this.baseUrl = baseUrl;
    originHost(this.baseUrl);
    this.prefix = opts.wellKnownPrefix ?? WELL_KNOWN;
    const f = opts.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!f) {
      throw new C8sVerifyError("invalid_request", "no fetch implementation available");
    }
    this.fetch = f;
    this.policy = {
      measurements: opts.measurements,
      platform: opts.platform,
      generation: opts.generation,
      requireFreshness: opts.requireFreshness,
      meshCaPem: hasPem ? opts.meshCaPem : undefined,
      allowlist: opts.allowlist,
      workloadName: opts.workloadName,
      at: opts.at,
      expectedRtmr3: opts.expectedRtmr3,
      tdxImage: opts.tdxImage,
      minTcb: opts.minTcb,
      snpCrl: opts.snpCrl,
      requireCollateral: opts.requireCollateral,
      tdxCollateral: opts.tdxCollateral,
      tdxTcbStatuses: opts.tdxTcbStatuses,
      routeDigests: opts.routeDigests,
    };
  }

  private _url(path: string): string {
    return `${this.baseUrl}${path}`;
  }

  /** The rollback floor: the newest manifest accepted under `routeOperatorKeys`. */
  get routeFloor(): RouteFloor | undefined {
    return this.floor && { ...this.floor };
  }

  /**
   * Check the route digest the evidence binds against the manifest the router
   * publishes, re-fetching once on a mismatch.
   */
  private async verifyRoutes(
    published: Promise<PublishedRoutes>,
    keys: CryptoKey[],
    digest: string,
  ): Promise<PublishedRoutes> {
    const first = await published;
    if (first.routeDigest === digest) return first;
    // The publication may have come from a replica on another revision.
    const fresh = await this.publishedRoutes(keys);
    if (fresh.routeDigest !== digest) {
      fail(
        "route_denied",
        `the evidence binds route digest ${digest}, the published manifest has ${fresh.routeDigest}`,
        { details: { expected: [fresh.routeDigest], got: digest } },
      );
    }
    return fresh;
  }

  /**
   * Raise the floor to an accepted manifest. Synchronous, so the check sees
   * any floor another connect raised while this one awaited.
   */
  private raiseRouteFloor(routes: PublishedRoutes): void {
    checkRouteFloor(routes, this.floor);
    if (this.floor === undefined || routes.revision > this.floor.revision) {
      this.floor = { revision: routes.revision, digest: routes.routeDigest };
    }
  }

  /** Fetch the route publication and verify it under the keys. */
  private async publishedRoutes(keys: CryptoKey[]): Promise<PublishedRoutes> {
    const url = `${this._url(this.prefix)}/routes`;
    let res: Response;
    let body: Uint8Array | undefined;
    try {
      // The operator signature authenticates the body, so no transport trust
      // is needed; a cached copy would only hide newer revisions.
      res = await this.fetch(url, { headers: { accept: "application/json" }, cache: "no-store" });
      body = res.status === 200 ? await readCapped(res, MAX_ROUTE_PUBLICATION_BYTES) : undefined;
    } catch (e) {
      fail("route_manifest_unavailable", `GET ${url} failed`, { cause: e });
    }
    if (res.status !== 200) {
      try {
        await res.body?.cancel();
      } catch {
        // Releasing the connection is best effort; the status is the error.
      }
    }
    if (res.status === 404) {
      fail(
        "route_manifest_unavailable",
        `GET ${url} returned 404: the router publishes no route manifest (publication off, or none applied yet)`,
        { details: { status: 404 } },
      );
    }
    if (res.status !== 200) {
      fail("route_manifest_unavailable", `GET ${url} returned HTTP ${res.status}`, {
        details: { status: res.status },
      });
    }
    if (body === undefined) {
      fail(
        "route_manifest_invalid",
        `GET ${url} returned more than ${MAX_ROUTE_PUBLICATION_BYTES} bytes`,
      );
    }
    return verifySignedRoutes(body, keys);
  }

  /**
   * POST the client-first attest-pq request — the fresh nonce and our X-Wing
   * encapsulation key — and return the bundle. There is no fallback, alias,
   * or version parameter: the endpoint is the version selector, and a server
   * that does not serve it is a server this client cannot verify.
   */
  async fetchAttestation(nonce: Uint8Array, keyPair: XWingKeyPair): Promise<AttestationBundle> {
    const res = await this.fetch(`${this._url(this.prefix)}/attest-pq`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        nonce: bytesToBase64Url(nonce),
        xwing_ek: bytesToBase64Url(keyPair.ek),
      }),
    });
    if (!res.ok) {
      fail("verification_failed", `attestation endpoint returned HTTP ${res.status}`);
    }
    return (await res.json()) as AttestationBundle;
  }

  /**
   * Run the full flow in one round trip: send our key exchange, verify the
   * returned evidence (which commits both sides of it), decapsulate, and
   * derive the over-encrypted channel. The session is live on return.
   */
  async connect(): Promise<Session> {
    try {
      return await this.connectOnce();
    } catch (e) {
      // A handshake and publication that agree on a revision below the floor
      // most likely reached a replica that has not caught up: try once more.
      if (!(e instanceof C8sVerifyError) || e.details.reason !== "below_floor") throw e;
      return this.connectOnce();
    }
  }

  private async connectOnce(): Promise<Session> {
    const routeKeys = await this.routeKeys;
    // Requested before the handshake, as c8s verify does: a manifest the
    // router applies between this request and admission shows up as a
    // mismatch the re-fetch resolves.
    const published = routeKeys && this.publishedRoutes(routeKeys);
    // Awaited after the transcript verifies; a failed handshake must not
    // leave its rejection unhandled.
    void published?.catch(() => undefined);
    const nonce = generateNonce();
    const keyPair = await generateXWingKeyPair();
    const bundle = await this.fetchAttestation(nonce, keyPair);
    let attestation = await verifyAttestation(bundle, nonce, this.policy, keyPair.ek);
    let routes: PublishedRoutes | undefined;
    if (routeKeys !== undefined && published !== undefined) {
      routes = await this.verifyRoutes(published, routeKeys, attestation.routeDigest);
      attestation = {
        ...attestation,
        routePolicy: "operator-signed",
        routeRevision: routes.revision,
      };
    }

    const sharedSecret = await xwingDecapsulate(keyPair, attestation.keyExchange.xwingCt);
    const channel = await deriveChannel(
      "client",
      sharedSecret,
      attestation.keyAgreementContext,
      attestation.keyExchange.sessionId,
    );
    if (routes !== undefined) this.raiseRouteFloor(routes);

    return new Session({
      baseUrl: this.baseUrl,
      prefix: this.prefix,
      fetch: this.fetch,
      channel,
      sessionId: bundle.session_id,
      attestation,
      routes,
    });
  }
}

/**
 * An established, verified, over-encrypted session with the LB.
 */
export class Session {
  readonly baseUrl: string;
  readonly prefix: string;
  private readonly _fetch: typeof fetch;
  readonly channel: Channel;
  readonly sessionId: string;
  /** Verification result: measurement, platform, cert info, warnings, ... */
  readonly attestation: AttestationResult;
  private readonly _host: string;
  private readonly _routes?: PublishedRoutes;

  constructor(o: SessionOptions) {
    this.baseUrl = o.baseUrl;
    this._host = originHost(o.baseUrl);
    this.prefix = o.prefix;
    this._fetch = o.fetch;
    this.channel = o.channel;
    this.sessionId = o.sessionId;
    this.attestation = o.attestation;
    this._routes = o.routes;
  }

  /**
   * Channel-binding exporter (32 bytes): derived by both ends from the shared
   * secret under the attested transcript, never sent on the wire. The sidecar
   * hands the backend the same value as the X-C8s-Exporter header, so an
   * application can bind bearer credentials to this exact channel.
   */
  get exporter(): Uint8Array {
    return this.channel.exporter;
  }

  /**
   * Make an over-encrypted request to the LB. The entire request — method, path,
   * headers, and body — is sealed with AES-256-GCM and sent to the tunnel
   * endpoint, so a TLS-terminating proxy in front of the LB sees only ciphertext.
   * The LB enclave decrypts it, forwards the plaintext request to the backend
   * (over the cluster raTLS mesh), and seals the response back.
   *
   * The router routes by the sealed `Host` header, so `path` must be in origin
   * form (start with `/`) and the headers may carry at most one `Host`. With
   * `routeOperatorKeys`, a request the attested manifest routes to no backend
   * is refused (`route_unmatched`); connect again to attest a newer manifest.
   */
  async fetch(path: string, init: RequestInit = {}): Promise<TunnelResponse> {
    if (typeof path !== "string" || !path.startsWith("/")) {
      fail("invalid_request", `request path must start with "/", got ${JSON.stringify(path)}`);
    }
    const method = (init.method ?? "GET").toUpperCase();
    const bodyBytes =
      init.body === undefined
        ? new Uint8Array(0)
        : typeof init.body === "string"
          ? utf8ToBytes(init.body)
          : init.body;
    const headerPairs = withHost(
      Array.isArray(init.headers) ? init.headers : Object.entries(init.headers ?? {}),
      this._host,
    );
    if (this._routes !== undefined) {
      const host = headerPairs.find(([name]) => name.toLowerCase() === "host")?.[1] ?? "";
      if (!this._routes.routes(host, path)) {
        fail(
          "route_unmatched",
          `the attested route manifest (revision ${this._routes.revision}) routes no backend for ` +
            `Host ${JSON.stringify(host)} and path ${JSON.stringify(path)}`,
        );
      }
    }

    const envelope = {
      method,
      path,
      headers: headerPairs,
      body: bodyBytes,
    };
    const reqRecord = await this.channel.sealRequest(cborEncode(envelope));

    const res = await this._fetch(`${this.baseUrl}${this.prefix}/tunnel`, {
      method: "POST",
      headers: { "content-type": "application/cbor", "x-c8s-session": this.sessionId },
      body: cborEncode({ seq: reqRecord.seq, ct: reqRecord.ct }),
    });
    if (!res.ok) {
      fail("channel_error", `over-encrypted request returned HTTP ${res.status}`);
    }
    const respRecord = cborDecode(new Uint8Array(await res.arrayBuffer())) as unknown as WireRecord;
    const respEnvelope = cborDecode(
      await this.channel.openResponse(respRecord, reqRecord.seq),
    ) as unknown as ResponseEnvelope;
    const headersList = responseHeaderPairs(respEnvelope.headers);
    const bytes = respEnvelope.body ?? new Uint8Array(0);
    return {
      status: respEnvelope.status,
      headers: firstValues(headersList),
      headersList,
      bytes,
      text: () => bytesToUtf8(bytes),
    };
  }
}

/**
 * The Host a sealed request defaults to: the base URL's host, with its port
 * when non-default. A relative base URL resolves against the page.
 */
function originHost(baseUrl: string): string {
  let url: URL | undefined;
  try {
    url = new URL(baseUrl);
  } catch {
    try {
      const page: unknown = globalThis.location?.href;
      if (typeof page === "string") url = new URL(baseUrl, page);
    } catch {
      // Reported below with the expected form; a runtime may throw on `location`.
    }
  }
  if (url === undefined || !["http:", "https:"].includes(url.protocol) || url.host === "") {
    fail(
      "invalid_request",
      `baseUrl ${JSON.stringify(baseUrl)} must be https://HOST[:PORT] (or http), or a path ` +
        "resolved against the page",
    );
  }
  return url.host;
}

/** Return the request headers with exactly one Host field: the caller's, or `host` appended. */
function withHost(pairs: [string, string][], host: string): [string, string][] {
  let hosts = 0;
  for (const pair of pairs) {
    if (!Array.isArray(pair) || typeof pair[0] !== "string" || typeof pair[1] !== "string") {
      fail("invalid_request", "request headers must be [name, value] string pairs");
    }
    const name = pair[0].toLowerCase();
    if (name === "upgrade") {
      fail("invalid_request", "the tunnel carries one buffered response, not a protocol upgrade");
    }
    if (name === "host") {
      if (pair[1].trim() === "") fail("invalid_request", "request Host header is empty");
      hosts++;
    }
  }
  if (hosts > 1) {
    fail("invalid_request", `request carries ${hosts} Host headers; the router accepts one`);
  }
  if (hosts === 1) return pairs;
  return [...pairs, ["Host", host]];
}

/** Read a response body, or undefined once it exceeds max bytes. */
async function readCapped(res: Response, max: number): Promise<Uint8Array | undefined> {
  if (res.body === null) return new Uint8Array(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > max) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

/** First value of each field, for the collapsed record view. */
function firstValues(pairs: [string, string][]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of pairs) {
    if (!(name in out)) out[name] = value;
  }
  return out;
}

/** Validate a response envelope's header pair list, refusing anything else. */
function responseHeaderPairs(headers: ResponseEnvelope["headers"]): [string, string][] {
  if (headers === undefined || headers === null) return [];
  if (!Array.isArray(headers)) {
    fail("channel_error", "malformed headers in response envelope");
  }
  for (const pair of headers) {
    if (
      !Array.isArray(pair) ||
      pair.length !== 2 ||
      typeof pair[0] !== "string" ||
      typeof pair[1] !== "string"
    ) {
      fail("channel_error", "malformed header pair in response envelope");
    }
  }
  return headers;
}
