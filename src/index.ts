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
export { decodePEM, decodeOnePEM, encodePEM } from "./pem.js";
export { generateNonce } from "./nonce.js";
export { initVerifier, verifySnp, verifyAzSnp, verifyAzTdx, verifyTdx } from "./wasm-loader.js";
export type { Evidence, SnpEvidence, AzSnpEvidence, AzTdxEvidence, TdxEvidence } from "./hcl.js";

const WELL_KNOWN = "/.well-known/c8s";

export interface C8sClientOptions {
  baseUrl: string;
  measurements: string[];
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
   * the image. Required for a TDX deployment-class verdict (no `meshCaPem`);
   * strongly recommended otherwise. Requires `platform: "tdx"`.
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
   * (production policy). Requires `snpCrl`. See
   * `VerifyPolicy.requireCollateral`.
   */
  requireCollateral?: boolean;
}

export interface RequestInit {
  method?: string;
  /**
   * Request headers: a plain record, or ordered [name, value] pairs when a
   * field repeats (Cookie). Duplicate pairs reach the backend intact.
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
}

export class C8sClient {
  readonly baseUrl: string;
  readonly prefix: string;
  readonly fetch: typeof fetch;
  /** Verification policy applied to every connection. */
  readonly policy: VerifyPolicy;

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
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
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
    };
  }

  private _url(path: string): string {
    return `${this.baseUrl}${path}`;
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
    const nonce = generateNonce();
    const keyPair = await generateXWingKeyPair();
    const bundle = await this.fetchAttestation(nonce, keyPair);
    const attestation = await verifyAttestation(bundle, nonce, this.policy, keyPair.ek);

    const sharedSecret = await xwingDecapsulate(keyPair, attestation.keyExchange.xwingCt);
    const channel = await deriveChannel(
      "client",
      sharedSecret,
      attestation.keyAgreementContext,
      attestation.keyExchange.sessionId,
    );

    return new Session({
      baseUrl: this.baseUrl,
      prefix: this.prefix,
      fetch: this.fetch,
      channel,
      sessionId: bundle.session_id,
      attestation,
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

  constructor(o: SessionOptions) {
    this.baseUrl = o.baseUrl;
    this.prefix = o.prefix;
    this._fetch = o.fetch;
    this.channel = o.channel;
    this.sessionId = o.sessionId;
    this.attestation = o.attestation;
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
   */
  async fetch(path: string, init: RequestInit = {}): Promise<TunnelResponse> {
    const method = (init.method ?? "GET").toUpperCase();
    const bodyBytes =
      init.body === undefined
        ? new Uint8Array(0)
        : typeof init.body === "string"
          ? utf8ToBytes(init.body)
          : init.body;
    const headerPairs: [string, string][] = Array.isArray(init.headers)
      ? init.headers
      : Object.entries(init.headers ?? {});

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
