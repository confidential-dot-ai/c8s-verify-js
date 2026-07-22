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
export { initVerifier, verifySnp, verifyAzSnp, verifyAzTdx } from "./wasm-loader.js";
export type { Evidence, SnpEvidence, AzSnpEvidence, AzTdxEvidence } from "./hcl.js";

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
  /**
   * Pinned launch-measurement allowlist (hex SHA-384) — the enclave's code
   * identity. Required and non-empty. To run without it, use
   * {@link C8sClient.insecure}.
   */
  measurements: string[];
  /**
   * Pinned mesh CA (PEM) — your cluster's identity. Required. To run without
   * it, use {@link C8sClient.insecure}.
   */
  meshCaPem: string;
  platform?: string;
  requireFreshness?: boolean;
  at?: Date;
  fetch?: typeof fetch;
  wellKnownPrefix?: string;
  cdsCertPath?: string | null;
}

/**
 * Options for {@link C8sClient.insecure}. Either pin may be omitted; each pin
 * you omit is WAIVED, and every waived check is re-surfaced as a warning on
 * `session.attestation.warnings`. Not safe against a malicious TLS-terminating
 * proxy — offline demo / early bring-up only.
 */
export type InsecureClientOptions = Omit<C8sClientOptions, "measurements" | "meshCaPem"> & {
  measurements?: string[];
  meshCaPem?: string;
};

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

  /**
   * Construct a client that FAILS CLOSED: it requires a non-empty measurement
   * allowlist (the enclave's code identity) and a pinned mesh CA (your cluster
   * identity). Omit either and construction throws. For the deliberately
   * degraded offline / bring-up mode, use {@link C8sClient.insecure}.
   */
  constructor(opts: C8sClientOptions) {
    if (!opts?.baseUrl) {
      throw new C8sVerifyError("invalid_request", "baseUrl is required");
    }

    // The insecure waivers ride on the options object but are intentionally not
    // part of the public C8sClientOptions type: only C8sClient.insecure() sets
    // them, so the strict path is the only default and every opt-out is an
    // explicit, greppable C8sClient.insecure(...) call site.
    const waive = opts as C8sClientOptions & {
      allowAnyMeasurement?: boolean;
      allowUnpinnedMeshCa?: boolean;
    };
    const measurements = opts.measurements ?? [];
    const allowAnyMeasurement = waive.allowAnyMeasurement === true;
    const allowUnpinnedMeshCa = waive.allowUnpinnedMeshCa === true;

    if (measurements.length === 0 && !allowAnyMeasurement) {
      throw new C8sVerifyError(
        "invalid_request",
        "measurements is required and must be non-empty — it pins the enclave's launch " +
          "measurement (its code identity). To run without it use C8sClient.insecure() " +
          "(insecure: accepts any genuine SNP enclave running any code).",
      );
    }
    if (!opts.meshCaPem && !allowUnpinnedMeshCa) {
      throw new C8sVerifyError(
        "invalid_request",
        "meshCaPem is required — it pins your cluster's mesh CA (its cluster identity). " +
          "To run without it use C8sClient.insecure() (insecure: a malicious proxy can " +
          "present its own CA).",
      );
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
      measurements,
      platform: opts.platform,
      requireFreshness: opts.requireFreshness,
      meshCaPem: opts.meshCaPem,
      at: opts.at,
      allowAnyMeasurement,
      allowUnpinnedMeshCa,
    };
  }

  /**
   * Deliberately-degraded client that SKIPS whichever pin you omit — the launch
   * measurement (code identity) and/or the mesh CA (cluster identity). A pin you
   * DO pass is still enforced; each pin you omit is waived and re-surfaced as a
   * warning on `session.attestation.warnings`.
   *
   * NOT safe against a malicious TLS-terminating proxy: with no pinned
   * measurement you accept any genuine SNP enclave running any code, and with no
   * pinned mesh CA a proxy can present its own CA. Offline demo / early bring-up
   * only — never production.
   */
  static insecure(opts: InsecureClientOptions): C8sClient {
    const measurements = opts.measurements ?? [];
    return new C8sClient({
      ...opts,
      measurements,
      allowAnyMeasurement: measurements.length === 0,
      allowUnpinnedMeshCa: !opts.meshCaPem,
    } as unknown as C8sClientOptions);
  }

  private _url(path: string): string {
    return `${this.baseUrl}${path}`;
  }

  /**
   * Fetch the LB attestation bundle for a fresh nonce.
   */
  async fetchAttestation(nonce: Uint8Array): Promise<AttestationBundle> {
    const url = `${this._url(this.prefix)}/attestation?nonce=${bytesToBase64Url(nonce)}`;
    const res = await this.fetch(url, { headers: { accept: "application/json" } });
    if (!res.ok) {
      fail("verification_failed", `attestation endpoint returned HTTP ${res.status}`);
    }
    return (await res.json()) as AttestationBundle;
  }

  /**
   * Fetch the statically-served CDS leaf cert (PEM). Best-effort: returns null
   * on any network/HTTP error or non-PEM body so connect() degrades to the
   * "cert not verified" warning instead of failing closed. The cert's trust is
   * the pinned mesh CA it chains to, so fetching it over the plain hop is safe.
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

    const { key, handshake } = await clientKeyAgreement(attestation.sessionPubKey, nonce);

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
