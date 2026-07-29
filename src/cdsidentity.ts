// Attesting CDS in the browser: the trust root a client verifies ONCE and caches.
//
// Until now `meshCaPem` had to be "pinned out of band" (verify.ts says so in the
// error message) — the mesh CA was trusted because an operator sent you the
// file, and every downstream check rested on that unverified anchor.
//
// CDS's own RA-TLS certificate carries hardware evidence over its config-claims,
// and those claims commit the digest of the mesh CA it issues under and of the
// allowlist it is serving. Verify that certificate and the anchor becomes
// derived rather than assumed.
//
// The certificate is fetched from the front door's discovery document
// (`cds_identity`), not from CDS, which is cluster-internal and unreachable from
// a browser. That is safe because it is self-authenticating: the evidence binds
// its own public key AND the exact claims bytes it carries, so a substituted or
// edited copy simply fails here.

import { readTLV, readChildren, TAG, type DERNode } from "./asn1.js";
import { bytesToHex, constantTimeEqual } from "./base64.js";
import { subtle } from "./crypto-env.js";
import { fail } from "./errors.js";
import { decodePEM } from "./pem.js";
import { verifyTdx } from "./wasm-loader.js";
import { fingerprintSHA256, parseCertificate, type Certificate } from "./x509.js";
import type { WasmVerifyResult } from "./verify.js";

/** RA-TLS extension OIDs (c8s pkg/ratls, the 1.3.6.1.4.1.59888 arc). */
const OID_RATLS_ATTESTATION = "1.3.6.1.4.1.59888.1.1";
const OID_RATLS_CONFIG_CLAIMS = "1.3.6.1.4.1.59888.1.3";

/** Width of every digest carried in config-claims (SHA-256). */
const CLAIMS_DIGEST_SIZE = 32;

/**
 * Tags the config-claims REPORTDATA transcript. Must match c8s pkg/ratls
 * `claimsDomainSep` byte for byte — "c8s/config-claims/v1" and a NUL.
 */
const CLAIMS_DOMAIN_SEP = new TextEncoder().encode("c8s/config-claims/v1\0");

/** Parsed config-claims. Absent fields read as the all-zero sentinel. */
export interface ConfigClaims {
  operatorKeysDigest: Uint8Array;
  seedDigest: Uint8Array;
  workloadDigest: Uint8Array;
  /** v2+; sentinel on v1. */
  meshCaDigest: Uint8Array;
  /** v3+; sentinel on v1/v2. */
  allowlistDigest: Uint8Array;
  version: number;
}

/** A VERIFIED CDS attestation — what the client caches. */
export interface CDSIdentity {
  /**
   * SHA-256 of the certificate DER: the cache key and the invalidation signal
   * in one. CDS re-issues whenever the live allowlist changes, so an unchanged
   * fingerprint means unchanged policy — the cached verdict stays valid with no
   * staleness window to tune, and a changed one is exactly when to re-attest.
   */
  fingerprint: string;
  launchDigest: string;
  claims: ConfigClaims;
  notAfter: Date;
}

/** What the caller pins when attesting CDS. */
export interface CDSPolicy {
  /**
   * Accepted hex launch measurements. Empty accepts any genuine TEE, which
   * proves the CA came from real confidential hardware but NOT from your
   * cluster.
   */
  measurements?: string[];
  /** Expected TDX RTMR[3] as 96 hex chars — pins the deployment, not just the image. */
  expectedRtmr3?: string;
}

/** The subset of /v1/discovery this module reads. */
export interface DiscoveryDocument {
  cds_identity?: {
    certificate_pem: string;
    certificate_sha256?: string;
    observed_at?: string;
  };
}

const isSentinel = (d: Uint8Array): boolean => d.every((b) => b === 0);

/** True when the claims actually carry this digest (not the "unset" sentinel). */
export const hasDigest = (d: Uint8Array): boolean =>
  d.length === CLAIMS_DIGEST_SIZE && !isSentinel(d);

/**
 * Pull `cds_identity` out of a discovery document.
 *
 * Its absence is an explicit failure rather than a silent fallback: a client
 * that quietly reverted to an out-of-band pin would report the same verdict for
 * a materially weaker check.
 */
export function cdsIdentityPEM(doc: DiscoveryDocument): string {
  const pem = doc?.cds_identity?.certificate_pem;
  if (!pem) {
    fail(
      "cds_identity_missing",
      "discovery document carries no cds_identity: this cluster predates it, so CDS cannot be " +
        "attested and the mesh CA can only be pinned out of band",
    );
  }
  return pem;
}

/**
 * Verify a CDS RA-TLS certificate and return what it vouches for.
 *
 * Fails closed on every path: a missing extension, evidence that does not bind
 * this certificate's key and claims, a launch digest outside the policy, or an
 * RTMR[3] mismatch all throw rather than returning a partial result.
 */
export async function attestCDSIdentity(
  certPEM: string | Uint8Array,
  policy: CDSPolicy = {},
): Promise<CDSIdentity> {
  const der = typeof certPEM === "string" ? decodePEM(certPEM, "CERTIFICATE")[0] : certPEM;
  if (!der) fail("cds_identity_invalid", "cds_identity is not a PEM CERTIFICATE");

  let cert: Certificate;
  try {
    cert = parseCertificate(der);
  } catch (err) {
    fail("cds_identity_invalid", `cannot parse cds_identity: ${(err as Error).message}`);
  }

  const attExt = cert.extensions.get(OID_RATLS_ATTESTATION);
  if (!attExt) {
    fail(
      "cds_identity_invalid",
      `cds_identity carries no RA-TLS attestation extension (${OID_RATLS_ATTESTATION}) — ` +
        "this is not a CDS RA-TLS certificate; a mesh-issued leaf is not one",
    );
  }
  const claimsDER = cert.extensions.get(OID_RATLS_CONFIG_CLAIMS);
  if (!claimsDER) {
    fail(
      "cds_identity_invalid",
      `cds_identity carries no config-claims extension (${OID_RATLS_CONFIG_CLAIMS}), so it ` +
        "vouches for no mesh CA or allowlist and cannot serve as a trust root",
    );
  }

  const envelope = attestationEnvelope(attExt);
  if (envelope.platform !== "tdx") {
    fail(
      "unsupported",
      `cds_identity platform is "${envelope.platform}"; only TDX is verified in the browser today`,
    );
  }

  // REPORTDATA must bind BOTH the certificate's public key and the exact claims
  // bytes it carries. Binding the key alone would let an attacker graft a
  // different claims extension onto genuine evidence and have it read as
  // attested.
  const expectedReportData = await reportDataForKeyAndClaims(cert.spki, claimsDER);

  const expectedRtmr3 = policy.expectedRtmr3 ? decodeRtmr3(policy.expectedRtmr3) : undefined;

  let raw: string;
  try {
    // The WASM core takes the platform-specific evidence object ({quote,
    // cc_eventlog}), not the {platform, evidence} envelope that wraps it — the
    // platform tag has already been dispatched on above.
    raw = await verifyTdx(
      JSON.stringify(envelope.evidence),
      expectedReportData,
      undefined,
      expectedRtmr3,
    );
  } catch (err) {
    fail("cds_identity_denied", `cds_identity attestation failed: ${(err as Error).message}`);
  }

  const result = JSON.parse(raw) as WasmVerifyResult;

  // The WASM core REPORTS these; enforcing them is the caller's job. Both are
  // required explicitly true, so a core that never ran a check (null/undefined)
  // is refused rather than read as success.
  if (result.signature_valid !== true) {
    fail("cds_identity_denied", "cds_identity hardware signature is not valid");
  }
  // The binding is the load-bearing check: without it the evidence is a genuine
  // quote from some TEE, unconnected to THIS certificate's key and claims — so
  // an attacker could pair real evidence with a forged mesh-CA or allowlist
  // digest and have it read as attested.
  if (result.report_data_match !== true) {
    fail(
      "cds_identity_denied",
      "cds_identity evidence does not bind this certificate's public key and config-claims " +
        "(report_data mismatch): the quote is not vouching for these claims",
      { details: { expected: bytesToHex(expectedReportData) } },
    );
  }

  // The WASM core only REPORTS rtmr3_match; enforcing it is the caller's job.
  // Requiring an explicit true means a verifier that never ran the check
  // (undefined/null) is refused rather than silently reported as pinned.
  if (expectedRtmr3 !== undefined && result.rtmr3_match !== true) {
    fail(
      "cds_identity_denied",
      result.rtmr3_match === false
        ? "cds_identity RTMR[3] does not match the pinned value: a genuine TEE, but not the " +
            "deployment the pin was taken from"
        : "cds_identity RTMR[3] was not checked by the verifier, so the pin cannot be reported " +
            "as enforced",
    );
  }

  const launchDigest = String(result.claims.launch_digest).toLowerCase();
  const allowed = (policy.measurements ?? []).map((m) => m.trim().toLowerCase()).filter(Boolean);
  if (allowed.length > 0 && !allowed.includes(launchDigest)) {
    fail(
      "cds_identity_denied",
      `cds_identity launch measurement ${launchDigest} is not in the allowlist`,
      { details: { measurement: launchDigest } },
    );
  }

  return {
    fingerprint: await fingerprintSHA256(der),
    launchDigest,
    claims: parseConfigClaims(claimsDER),
    notAfter: cert.notAfter,
  };
}

/**
 * Check a served mesh CA against the digest CDS attested to issuing under.
 *
 * This is the step that retires the out-of-band pin: the CA is accepted because
 * attested hardware vouched for its digest, not because someone sent the file.
 */
export async function verifyMeshCA(id: CDSIdentity, caDER: Uint8Array): Promise<void> {
  if (!hasDigest(id.claims.meshCaDigest)) {
    fail(
      "mesh_ca_not_attested",
      "attested claims carry no mesh-CA digest (claims v1), so the mesh CA cannot be derived",
    );
  }
  const got = new Uint8Array(await subtle().digest("SHA-256", caDER.slice()));
  if (!constantTimeEqual(got, id.claims.meshCaDigest)) {
    fail(
      "mesh_ca_denied",
      `served mesh CA digest ${bytesToHex(got)} does not match the attested value ` +
        `${bytesToHex(id.claims.meshCaDigest)} — this CA is not the one the verified CDS issues ` +
        "under (CDS regenerates its mesh CA on restart, and the front door serves a cached copy " +
        "until its certificate renews)",
    );
  }
}

/**
 * Check the EXACT bytes of a `GET /allowlist` response against the attested
 * live-allowlist digest.
 *
 * The response is hashed verbatim — no JSON parse, no re-serialization. CDS
 * commits SHA-256 over the canonical bytes it serves, so re-encoding would
 * produce a different digest for semantically identical content and the
 * mismatch would look like tampering rather than a serialization bug.
 */
export async function verifyAllowlist(id: CDSIdentity, rawResponse: Uint8Array): Promise<void> {
  if (!hasDigest(id.claims.allowlistDigest)) {
    fail(
      "allowlist_not_attested",
      "attested claims carry no live-allowlist digest (claims v1/v2), so the served allowlist " +
        "cannot be checked against them",
    );
  }
  const got = new Uint8Array(await subtle().digest("SHA-256", rawResponse.slice()));
  if (!constantTimeEqual(got, id.claims.allowlistDigest)) {
    fail(
      "allowlist_denied",
      `served allowlist digest ${bytesToHex(got)} does not match the attested value ` +
        `${bytesToHex(id.claims.allowlistDigest)} — the admission policy served is not the one ` +
        "CDS attested to (hash the raw response bytes, not a re-serialized copy)",
    );
  }
}

/**
 * Recompute the REPORTDATA transcript c8s binds:
 *
 *   SHA-384( "c8s/config-claims/v1\0" || framed(pubkey) || framed(claims) || framed(nonce) )
 *
 * where framed(x) is an 8-byte big-endian length followed by x, the pubkey is
 * the PKIX SubjectPublicKeyInfo DER, and the nonce is EMPTY for a self-signed
 * serving certificate (c8s provider.go passes nil). Domain separation plus
 * length framing is what stops the fields being re-split into an equivalent
 * byte stream.
 */
async function reportDataForKeyAndClaims(
  spkiDER: Uint8Array,
  claimsDER: Uint8Array,
): Promise<Uint8Array> {
  const fields = [spkiDER, claimsDER, new Uint8Array(0)];
  let total = CLAIMS_DOMAIN_SEP.length;
  for (const f of fields) total += 8 + f.length;

  const buf = new Uint8Array(total);
  let off = 0;
  buf.set(CLAIMS_DOMAIN_SEP, off);
  off += CLAIMS_DOMAIN_SEP.length;
  for (const f of fields) {
    // 8-byte big-endian length. Lengths here are far below 2^32, so the high
    // word is always zero; write it explicitly rather than relying on that.
    const view = new DataView(buf.buffer, buf.byteOffset + off, 8);
    view.setUint32(0, 0);
    view.setUint32(4, f.length);
    off += 8;
    buf.set(f, off);
    off += f.length;
  }
  return new Uint8Array(await subtle().digest("SHA-384", buf));
}

/**
 * Read the attestation-api evidence envelope out of the RA-TLS extension.
 *
 * The extension is SEQUENCE { teeType INTEGER, report OCTET STRING, certChain
 * OCTET STRING }, and for TDX `report` always holds a JSON envelope rather than
 * a raw quote.
 */
function attestationEnvelope(extValue: Uint8Array): { platform: string; evidence: unknown } {
  const seq = readTLV(extValue, 0);
  if (seq.tag !== TAG.SEQUENCE) {
    fail("cds_identity_invalid", "RA-TLS attestation extension is not a SEQUENCE");
  }
  const parts: DERNode[] = readChildren(extValue, seq);
  const report = parts[1];
  if (report?.tag !== TAG.OCTET_STRING) {
    fail("cds_identity_invalid", "RA-TLS attestation extension has no report OCTET STRING");
  }

  const text = new TextDecoder().decode(report.content).trim();
  if (!text.startsWith("{")) {
    fail(
      "unsupported",
      "RA-TLS attestation extension carries a raw hardware report rather than a JSON evidence " +
        "envelope; only envelope-carrying platforms are verified here",
    );
  }
  let envelope: { platform?: string; evidence?: unknown };
  try {
    envelope = JSON.parse(text) as { platform?: string; evidence?: unknown };
  } catch (err) {
    fail("cds_identity_invalid", `cannot parse evidence envelope: ${(err as Error).message}`);
  }
  if (!envelope.platform || envelope.evidence === undefined) {
    fail("cds_identity_invalid", "evidence envelope is missing platform or evidence");
  }
  return { platform: envelope.platform, evidence: envelope.evidence };
}

/**
 * Decode the config-claims extension, accepting v1, v2 and v3.
 *
 * Fields a version predates read as the sentinel, so a client asking for a
 * property those claims never carried gets an explicit failure rather than a
 * zero value that quietly compares equal to nothing.
 */
export function parseConfigClaims(der: Uint8Array): ConfigClaims {
  const seq = readTLV(der, 0);
  if (seq.tag !== TAG.SEQUENCE) {
    fail("cds_identity_invalid", "config-claims extension is not a SEQUENCE");
  }
  const parts = readChildren(der, seq);
  const versionNode = parts[0];
  if (versionNode?.tag !== TAG.INTEGER) {
    fail("cds_identity_invalid", "config-claims extension has no version INTEGER");
  }
  let version = 0;
  for (const b of versionNode.content) version = version * 256 + b;

  const expected: Record<number, number> = { 1: 4, 2: 5, 3: 6 };
  const want = expected[version];
  if (want === undefined) {
    fail(
      "unsupported",
      `unsupported config-claims version ${version} (supported: 1, 2, 3) — the cluster is newer ` +
        "than this build; upgrade rather than ignoring the claims",
    );
  }
  if (parts.length !== want) {
    fail(
      "cds_identity_invalid",
      `config-claims v${version} has ${parts.length} fields, expected ${want}`,
    );
  }

  const digest = (idx: number): Uint8Array => {
    const node = parts[idx];
    if (node?.tag !== TAG.OCTET_STRING || node.content.length !== CLAIMS_DIGEST_SIZE) {
      fail(
        "cds_identity_invalid",
        `config-claims field ${idx} is not a ${CLAIMS_DIGEST_SIZE}-byte OCTET STRING`,
      );
    }
    return node.content;
  };
  const sentinel = () => new Uint8Array(CLAIMS_DIGEST_SIZE);

  return {
    version,
    operatorKeysDigest: digest(1),
    seedDigest: digest(2),
    workloadDigest: digest(3),
    meshCaDigest: version >= 2 ? digest(4) : sentinel(),
    allowlistDigest: version >= 3 ? digest(5) : sentinel(),
  };
}

/** Decode a 96-hex-char RTMR[3] pin. A malformed pin is an error, never a skipped check. */
function decodeRtmr3(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (!/^[0-9a-f]{96}$/.test(clean)) {
    fail("invalid_request", "expectedRtmr3 must be 96 hex characters (48 bytes)");
  }
  const out = new Uint8Array(48);
  for (let i = 0; i < 48; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
