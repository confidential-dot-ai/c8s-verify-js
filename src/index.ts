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
  type VerifyPolicy,
} from "./verify.js";
import { clientKeyAgreement } from "./keyagreement.js";
import { Channel, requestAAD, responseAAD, type WireRecord } from "./channel.js";
import { cborEncode, cborDecode } from "./cbor.js";
import { bytesToBase64Url, bytesToUtf8, utf8ToBytes } from "./base64.js";
import { C8sVerifyError, fail } from "./errors.js";
import {
  attestCDSIdentity,
  attestCDSIdentityCached,
  selectAttestedMeshCA,
  type CDSIdentity,
  type CDSPolicy,
} from "./cdsidentity.js";
import type { CDSIdentityCache } from "./cdscache.js";
import { decodePEM, encodePEM } from "./pem.js";

export { C8sVerifyError } from "./errors.js";
export { PROTOCOL_VERSION } from "./identity.js";
export type { MeshIdentityProof } from "./identity.js";
export { verifyAttestation, verifyEvidence } from "./verify.js";
export type {
  VerifyPolicy,
  AttestationBundle,
  AttestationResult,
  EvidenceResult,
  VerifyEvidenceOptions,
  CertInfo,
} from "./verify.js";
export {
  attestCDSIdentity,
  attestCDSIdentityCached,
  cdsIdentityPEM,
  verifyMeshCA,
  selectAttestedMeshCA,
  verifyAllowlist,
  parseConfigClaims,
  hasDigest,
} from "./cdsidentity.js";
export type {
  CDSIdentity,
  CachedCDSIdentity,
  CDSPolicy,
  ConfigClaims,
  DiscoveryDocument,
} from "./cdsidentity.js";
// Caching a verified CDS identity: skips re-attestation while the certificate
// is unchanged, and remembers the last verified notBefore so a replayed older
// certificate is refused instead of silently rolling the allowlist back.
export { MemoryCDSIdentityCache, StorageCDSIdentityCache, isCacheEntry } from "./cdscache.js";
export type { CDSCacheEntry, CDSIdentityCache, WebStorageLike } from "./cdscache.js";
// decodePEM to hand DER to verifyMeshCA (which takes bytes, so it hashes
// exactly what it was given); encodePEM to turn a derived CA back into the
// single-block PEM a VerifyPolicy pins.
export { decodePEM, decodeOnePEM, encodePEM } from "./pem.js";
export { generateNonce } from "./nonce.js";
export { initVerifier, verifySnp, verifyAzSnp, verifyAzTdx, verifyTdx } from "./wasm-loader.js";
export type { Evidence, SnpEvidence, AzSnpEvidence, AzTdxEvidence, TdxEvidence } from "./hcl.js";

const WELL_KNOWN = "/.well-known/c8s";

/**
 * How the client obtains the mesh CA when it is derived rather than pinned.
 *
 * Either an identity you already attested (so a cached verdict can be reused
 * across clients), or the raw `cds_identity` PEM from the front door's
 * discovery document plus the policy to attest it under.
 */
export type CDSIdentityOption =
  | {
      /** A CDSIdentity you already obtained from attestCDSIdentity(Cached). */
      identity: CDSIdentity;
      certificatePem?: never;
    }
  | {
      /** `cds_identity.certificate_pem` from the discovery document. */
      certificatePem: string;
      /** Pins to attest it under. `measurements` is required, as everywhere. */
      policy: CDSPolicy;
      /** Optional cache; when given, attestCDSIdentityCached is used. */
      cache?: CDSIdentityCache;
      /** Cache key. Defaults to the client's baseUrl. */
      cacheKey?: string;
      identity?: never;
    };

export interface C8sClientOptions {
  baseUrl: string;
  measurements: string[];
  platform?: string;
  requireFreshness?: boolean;
  /**
   * Mesh CA pinned out of band. Mutually exclusive with `cdsIdentity` —
   * exactly one of the two is required.
   *
   * Multiple PEM blocks mean *each block is independently trusted* as an
   * anchor: the identity proof selects whichever one it names. That is
   * occasionally what you want during a CA rotation, and a footgun the rest of
   * the time, so prefer a single block — or `cdsIdentity`, which derives the
   * anchor and can only ever pin one certificate.
   */
  meshCaPem?: string;
  /**
   * Derive the mesh CA from attested CDS claims instead of pinning it.
   *
   * CDS's RA-TLS certificate commits the SHA-256 of the CA it issues under, and
   * that commitment is bound into hardware evidence. So a verified CDS identity
   * authenticates the CA, and the anchor stops being a file an operator sent
   * you. The client matches the attested digest against the CA the server
   * serves alongside its leaf and pins exactly that one certificate — not the
   * served chain, which would trust every block in it.
   *
   * Mutually exclusive with `meshCaPem`.
   */
  cdsIdentity?: CDSIdentityOption;
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
}

export interface RequestInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
}

export interface TunnelResponse {
  status: number;
  headers: Record<string, string>;
  bytes: Uint8Array;
  text: () => string;
}

/** Response envelope decoded from a sealed tunnel record. */
interface ResponseEnvelope {
  status: number;
  headers?: Record<string, string>;
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

/** The client's policy before the mesh CA is known (derived mode resolves it). */
export type BaseVerifyPolicy = Omit<VerifyPolicy, "meshCaPem"> & { meshCaPem?: string };

export class C8sClient {
  readonly baseUrl: string;
  readonly prefix: string;
  readonly fetch: typeof fetch;
  /**
   * Verification policy. In derived mode `meshCaPem` is absent here and is
   * resolved per connection from attested claims — reading it is not a way to
   * discover the anchor; read `session.attestation.cert.caSha256` instead.
   */
  readonly policy: BaseVerifyPolicy;
  private readonly cdsIdentity?: CDSIdentityOption;

  constructor(opts: C8sClientOptions) {
    if (!opts?.baseUrl) {
      throw new C8sVerifyError("invalid_request", "baseUrl is required");
    }
    // Exactly one anchor source. Both is ambiguous — we would have to pick, and
    // picking silently is how a caller ends up believing the stronger option is
    // in force while the weaker one decides. Neither leaves nothing to chain to.
    const hasPem = typeof opts.meshCaPem === "string" && opts.meshCaPem.trim() !== "";
    const hasCds = opts.cdsIdentity !== undefined;
    if (hasPem && hasCds) {
      throw new C8sVerifyError(
        "invalid_request",
        "pass either meshCaPem or cdsIdentity, not both: they are two different answers to " +
          "'which CA anchors this cluster', and silently preferring one would misreport which " +
          "check actually ran",
      );
    }
    if (!hasPem && !hasCds) {
      throw new C8sVerifyError(
        "invalid_request",
        "verification requires an anchor: pass meshCaPem to pin the mesh CA out of band, or " +
          "cdsIdentity to derive it from attested CDS claims",
      );
    }
    if (hasCds) {
      const cds = opts.cdsIdentity!;
      if (cds.identity === undefined && typeof cds.certificatePem !== "string") {
        throw new C8sVerifyError(
          "invalid_request",
          "cdsIdentity needs either an attested identity or a certificatePem plus policy",
        );
      }
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.prefix = opts.wellKnownPrefix ?? WELL_KNOWN;
    const f = opts.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!f) {
      throw new C8sVerifyError("invalid_request", "no fetch implementation available");
    }
    this.fetch = f;
    this.cdsIdentity = opts.cdsIdentity;
    this.policy = {
      measurements: opts.measurements,
      platform: opts.platform,
      requireFreshness: opts.requireFreshness,
      meshCaPem: hasPem ? opts.meshCaPem : undefined,
      at: opts.at,
      expectedRtmr3: opts.expectedRtmr3,
    };
  }

  /**
   * Derive the mesh CA anchor from attested CDS claims, as a single-block PEM.
   *
   * Attests the CDS identity, then finds the certificate the server served
   * alongside its leaf whose SHA-256 the attested claims commit to, and returns
   * THAT ONE certificate re-encoded on its own. Re-encoding is the point:
   * reusing the served chain as the pin would trust every block in it, whereas
   * hardware vouched for exactly one.
   *
   * Public because a caller should be able to see, and log, which certificate
   * the derivation actually chose.
   *
   * @throws when the client was configured with `meshCaPem` instead
   */
  async deriveMeshCaPem(bundle: AttestationBundle): Promise<string> {
    if (this.cdsIdentity === undefined) {
      fail("invalid_request", "this client pins meshCaPem out of band; nothing to derive");
    }
    const opt = this.cdsIdentity;
    let identity: CDSIdentity;
    if (opt.certificatePem === undefined) {
      identity = opt.identity;
    } else if (opt.cache !== undefined) {
      identity = await attestCDSIdentityCached(
        opt.certificatePem,
        opt.policy,
        opt.cache,
        opt.cacheKey ?? this.baseUrl,
      );
    } else {
      identity = await attestCDSIdentity(opt.certificatePem, opt.policy);
    }

    // The served chain is leaf-first; everything after it is a CA candidate.
    // Only the block whose digest the attested claims name is selected.
    const served = decodePEM(bundle?.cds_cert_pem ?? "", "CERTIFICATE");
    if (served.length === 0) {
      fail("identity_binding", "attestation response omitted cds_cert_pem");
    }
    const caDer = await selectAttestedMeshCA(identity, served.slice(1));
    return encodePEM(caDer, "CERTIFICATE");
  }

  /** The effective policy for one bundle: configured, or derived per connection. */
  private async resolvePolicy(bundle: AttestationBundle): Promise<VerifyPolicy> {
    if (this.policy.meshCaPem !== undefined) {
      return this.policy as VerifyPolicy;
    }
    return { ...this.policy, meshCaPem: await this.deriveMeshCaPem(bundle) };
  }

  private _url(path: string): string {
    return `${this.baseUrl}${path}`;
  }

  /**
   * Fetch the LB attestation bundle for a fresh nonce.
   */
  async fetchAttestation(nonce: Uint8Array): Promise<AttestationBundle> {
    const params = new URLSearchParams({ nonce: bytesToBase64Url(nonce) });
    const url = `${this._url(this.prefix)}/attestation?${params.toString()}`;
    const res = await this.fetch(url, { headers: { accept: "application/json" } });
    if (!res.ok) {
      fail("verification_failed", `attestation endpoint returned HTTP ${res.status}`);
    }
    return (await res.json()) as AttestationBundle;
  }

  /**
   * Run the full flow: fetch attestation, verify it, and establish the
   * over-encrypted channel.
   */
  async connect(): Promise<Session> {
    const nonce = generateNonce();
    const bundle = await this.fetchAttestation(nonce);
    const policy = await this.resolvePolicy(bundle);
    const attestation = await verifyAttestation(bundle, nonce, policy);

    const { key, handshake } = await clientKeyAgreement(
      attestation.sessionPubKey,
      attestation.keyAgreementContext,
    );

    // Register the channel with the LB; it derives the identical key.
    const hsRes = await this.fetch(`${this._url(this.prefix)}/handshake`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: bytesToBase64Url(nonce),
        client_x25519: bytesToBase64Url(handshake.clientX25519),
        mlkem_ct: bytesToBase64Url(handshake.mlkemCiphertext),
      }),
    });
    if (!hsRes.ok) {
      fail("channel_error", `handshake endpoint returned HTTP ${hsRes.status}`);
    }
    const { session_id: sessionId } = (await hsRes.json()) as { session_id?: string };
    if (!sessionId) fail("channel_error", "handshake did not return a session id");

    return new Session({
      baseUrl: this.baseUrl,
      prefix: this.prefix,
      fetch: this.fetch,
      channel: new Channel(key),
      sessionId,
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

    const envelope = {
      method,
      path,
      headers: init.headers ?? {},
      body: bodyBytes,
    };
    const reqRecord = await this.channel.seal(cborEncode(envelope), requestAAD());

    const res = await this._fetch(`${this.baseUrl}${this.prefix}/tunnel`, {
      method: "POST",
      headers: { "content-type": "application/cbor", "x-c8s-session": this.sessionId },
      body: cborEncode(reqRecord),
    });
    if (!res.ok) {
      fail("channel_error", `over-encrypted request returned HTTP ${res.status}`);
    }
    const respRecord = cborDecode(new Uint8Array(await res.arrayBuffer())) as unknown as WireRecord;
    const respEnvelope = cborDecode(
      await this.channel.open(respRecord, responseAAD()),
    ) as unknown as ResponseEnvelope;
    const bytes = respEnvelope.body ?? new Uint8Array(0);
    return {
      status: respEnvelope.status,
      headers: respEnvelope.headers ?? {},
      bytes,
      text: () => bytesToUtf8(bytes),
    };
  }
}
