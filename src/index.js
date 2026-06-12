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
import { verifyAttestation } from "./verify.js";
import { clientKeyAgreement } from "./keyagreement.js";
import { Channel, requestAAD, responseAAD } from "./channel.js";
import { cborEncode, cborDecode } from "./cbor.js";
import { bytesToBase64Url, bytesToUtf8, utf8ToBytes } from "./base64.js";
import { C8sVerifyError, fail } from "./errors.js";

export { C8sVerifyError } from "./errors.js";
export { verifyAttestation, verifyEvidence, expectedReportData } from "./verify.js";
export { generateNonce } from "./nonce.js";
export { initVerifier, verifySnp, verifyAzSnp } from "./wasm-loader.js";

const WELL_KNOWN = "/.well-known/c8s";

/**
 * @typedef {import("./verify.js").VerifyPolicy & {
 *   baseUrl: string,
 *   fetch?: typeof fetch,
 *   wellKnownPrefix?: string,
 * }} C8sClientOptions
 */

export class C8sClient {
  /** @param {C8sClientOptions} opts */
  constructor(opts) {
    if (!opts || !opts.baseUrl) {
      throw new C8sVerifyError("invalid_request", "baseUrl is required");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.prefix = opts.wellKnownPrefix ?? WELL_KNOWN;
    this.fetch = opts.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!this.fetch) {
      throw new C8sVerifyError("invalid_request", "no fetch implementation available");
    }
    /** @type {import("./verify.js").VerifyPolicy} */
    this.policy = {
      measurements: opts.measurements ?? [],
      platform: opts.platform,
      requireFreshness: opts.requireFreshness,
      meshCaPem: opts.meshCaPem,
      at: opts.at,
    };
  }

  /** @param {string} path */
  _url(path) {
    return `${this.baseUrl}${path}`;
  }

  /**
   * Fetch the LB attestation bundle for a fresh nonce.
   * @param {Uint8Array} nonce
   * @returns {Promise<import("./verify.js").AttestationBundle>}
   */
  async fetchAttestation(nonce) {
    const url = `${this._url(this.prefix)}/attestation?nonce=${bytesToBase64Url(nonce)}`;
    const res = await this.fetch(url, { headers: { accept: "application/json" } });
    if (!res.ok) {
      fail("verification_failed", `attestation endpoint returned HTTP ${res.status}`);
    }
    return /** @type {any} */ (await res.json());
  }

  /**
   * Run the full flow: fetch attestation, verify it, and establish the
   * over-encrypted channel.
   * @returns {Promise<Session>}
   */
  async connect() {
    const nonce = generateNonce();
    const bundle = await this.fetchAttestation(nonce);
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
    const { session_id: sessionId } = await hsRes.json();
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
  /**
   * @param {{
   *   baseUrl: string, prefix: string, fetch: typeof fetch, channel: Channel,
   *   sessionId: string, attestation: object
   * }} o
   */
  constructor(o) {
    this.baseUrl = o.baseUrl;
    this.prefix = o.prefix;
    this._fetch = o.fetch;
    this.channel = o.channel;
    this.sessionId = o.sessionId;
    /** Verification result: measurement, platform, cert info, warnings, ... */
    this.attestation = o.attestation;
  }

  /**
   * Make an over-encrypted request to the LB. The entire request — method, path,
   * headers, and body — is sealed with AES-256-GCM and sent to the tunnel
   * endpoint, so a TLS-terminating proxy in front of the LB sees only ciphertext.
   * The LB enclave decrypts it, forwards the plaintext request to the backend
   * (over the cluster raTLS mesh), and seals the response back.
   *
   * @param {string} path
   * @param {{ method?: string, headers?: Record<string,string>, body?: string|Uint8Array }} [init]
   * @returns {Promise<{ status: number, headers: Record<string,string>, bytes: Uint8Array, text: () => string }>}
   */
  async fetch(path, init = {}) {
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
    const respRecord = cborDecode(new Uint8Array(await res.arrayBuffer()));
    const respEnvelope = cborDecode(await this.channel.open(respRecord, responseAAD()));
    const bytes = respEnvelope.body ?? new Uint8Array(0);
    return {
      status: respEnvelope.status,
      headers: respEnvelope.headers ?? {},
      bytes,
      text: () => bytesToUtf8(bytes),
    };
  }
}
