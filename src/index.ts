// c8s-verify: public API.
//
// Verify that a remote API is served by a genuine, TEE-attested, CDS-issued C8s
// Load Balancer, then talk to it over a post-quantum over-encrypted channel that
// terminates inside the LB's enclave — so a malicious TLS-terminating proxy in
// front of the LB cannot read or forge application traffic.
//
//   const client = new C8sClient({ baseUrl, measurements: [...] });
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
import { IDENTITY_BINDING_V2 } from "./identity.js";

export { C8sVerifyError } from "./errors.js";
export { verifyAttestation, verifyEvidence, expectedReportData } from "./verify.js";
export type {
  VerifyPolicy,
  AttestationBundle,
  AttestationResult,
  EvidenceResult,
  VerifyEvidenceOptions,
  CertInfo,
} from "./verify.js";
export { generateNonce } from "./nonce.js";
export { initVerifier, verifySnp, verifyAzSnp } from "./wasm-loader.js";
export type { Evidence, SnpEvidence, AzSnpEvidence } from "./hcl.js";

const WELL_KNOWN = "/.well-known/c8s";
// The CDS leaf cert is served by nginx as a static discovery file (sibling of
// mesh-ca.pem), NOT under the attest prefix. The cds-attest sidecar no longer
// embeds it in the attestation bundle (it would freeze a copy that goes stale
// when get-cert rotates the LB leaf); nginx serves the live cert here and
// hot-reloads it on renewal, so the client fetches it from here when the bundle
// omits it.
const CDS_CERT_PATH = "/.well-known/cds-cert.pem";

export interface C8sClientOptions {
  baseUrl: string;
  measurements?: string[];
  platform?: string;
  requireFreshness?: boolean;
  /** default true: require PQ session keys to be bound to the pinned mesh identity */
  requireClusterIdentity?: boolean;
  meshCaPem?: string;
  at?: Date;
  fetch?: typeof fetch;
  wellKnownPrefix?: string;
  cdsCertPath?: string | null;
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

export class C8sClient {
  readonly baseUrl: string;
  readonly prefix: string;
  readonly fetch: typeof fetch;
  readonly policy: VerifyPolicy;
  readonly cdsCertPath: string | null;

  constructor(opts: C8sClientOptions) {
    if (!opts?.baseUrl) {
      throw new C8sVerifyError("invalid_request", "baseUrl is required");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.prefix = opts.wellKnownPrefix ?? WELL_KNOWN;
    // Where to fetch the CDS leaf cert when the bundle omits it. Pass null/""
    // to disable (e.g. an offline bundle that carries its own cds_cert_pem).
    this.cdsCertPath = opts.cdsCertPath === undefined ? CDS_CERT_PATH : opts.cdsCertPath;
    const f = opts.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!f) {
      throw new C8sVerifyError("invalid_request", "no fetch implementation available");
    }
    this.fetch = f;
    this.policy = {
      measurements: opts.measurements ?? [],
      platform: opts.platform,
      requireFreshness: opts.requireFreshness,
      requireClusterIdentity: opts.requireClusterIdentity,
      meshCaPem: opts.meshCaPem,
      at: opts.at,
    };
  }

  private _url(path: string): string {
    return `${this.baseUrl}${path}`;
  }

  /**
   * Fetch the LB attestation bundle for a fresh nonce.
   */
  async fetchAttestation(nonce: Uint8Array): Promise<AttestationBundle> {
    const params = new URLSearchParams({ nonce: bytesToBase64Url(nonce) });
    if (this.policy.requireClusterIdentity !== false) {
      params.set("binding", IDENTITY_BINDING_V2);
    }
    const url = `${this._url(this.prefix)}/attestation?${params.toString()}`;
    const res = await this.fetch(url, { headers: { accept: "application/json" } });
    if (!res.ok) {
      fail("verification_failed", `attestation endpoint returned HTTP ${res.status}`);
    }
    return (await res.json()) as AttestationBundle;
  }

  /**
   * Fetch the statically-served CDS leaf cert (PEM) for legacy v1 responses.
   * Best-effort: returns null on any network/HTTP error or non-PEM body. V2
   * requires the exact attestation-bound chain in its response and never relies
   * on this fallback.
   */
  async fetchCdsCert(): Promise<string | null> {
    if (!this.cdsCertPath) return null;
    try {
      const res = await this.fetch(this._url(this.cdsCertPath), {
        headers: { accept: "application/x-pem-file, text/plain" },
      });
      if (!res.ok) return null;
      const pem = await res.text();
      return pem.includes("BEGIN CERTIFICATE") ? pem : null;
    } catch {
      return null;
    }
  }

  /**
   * Run the full flow: fetch attestation, verify it, and establish the
   * over-encrypted channel.
   */
  async connect(): Promise<Session> {
    const nonce = generateNonce();
    const bundle = await this.fetchAttestation(nonce);
    // The cds-attest sidecar no longer embeds the leaf in the bundle (it would
    // go stale on LB cert rotation); pull the live one nginx serves statically
    // so the chain-to-mesh-CA check in verifyAttestation can run.
    if (!bundle.cds_cert_pem) {
      const pem = await this.fetchCdsCert();
      if (pem) bundle.cds_cert_pem = pem;
    }
    const attestation = await verifyAttestation(bundle, nonce, this.policy);

    const { key, handshake } = await clientKeyAgreement(
      attestation.sessionPubKey,
      nonce,
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
