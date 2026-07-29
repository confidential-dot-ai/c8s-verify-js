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
import { entryDate, type CDSCacheEntry, type CDSIdentityCache } from "./cdscache.js";
import { subtle } from "./crypto-env.js";
import { fail } from "./errors.js";
import { decodeOnePEM } from "./pem.js";
import { verifyTdx } from "./wasm-loader.js";
import {
  fingerprintSHA256,
  parseCertificate,
  verifyECDSASignature,
  type Certificate,
} from "./x509.js";
import type { WasmVerifyResult } from "./verify.js";

/**
 * The hardware verifier, behind a mutable binding.
 *
 * Only reason it is not a direct import: the cached path's contract is that a
 * fingerprint hit never reaches the WASM core, and the only way to *prove* a
 * function was not called is to count its calls. Tests swap this; nothing else
 * should, so it is deliberately absent from the package index.
 *
 * @internal
 */
export const verifierSeam = { verifyTdx };

/** ECDSA-with-SHA-256 / SHA-384, the two algorithms c8s RA-TLS certificates use. */
const SELF_SIG_HASH: Record<string, "SHA-256" | "SHA-384"> = {
  "1.2.840.10045.4.3.2": "SHA-256",
  "1.2.840.10045.4.3.3": "SHA-384",
};

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
  /**
   * Issuance time. Trustworthy only because attestCDSIdentity verifies the
   * certificate's self-signature against the SPKI that REPORTDATA binds — the
   * validity window itself is outside the transcript. It is what makes
   * monotonic rollback detection possible (see cdscache.ts).
   */
  notBefore: Date;
  notAfter: Date;
}

/** What the caller pins when attesting CDS. */
export interface CDSPolicy {
  /**
   * Accepted hex launch measurements. Required and non-empty.
   *
   * Without it, attestation proves "a genuine TEE running something" — the
   * c8s images are reproducible and open source, so anyone can stand up an
   * instance and be attested. An unpinned CDS identity therefore vouches for a
   * mesh CA and an allowlist belonging to a cluster you have never heard of,
   * which reads exactly like success. verifyAttestation has refused an empty
   * allowlist since it existed; this is the same rule.
   */
  measurements: string[];
  /** Expected TDX RTMR[3] as 96 hex chars — pins the deployment, not just the image. */
  expectedRtmr3?: string;
  /**
   * Validity reference time (default now). Injectable so verification is a
   * pure function of its inputs — tests pin it, and a caller with a trusted
   * clock source can supply that instead of the host's.
   */
  at?: Date;
  /**
   * Accept a CDS certificate older than one already verified under this cache
   * key. Off by default: an older certificate is the downgrade case, where
   * every individual signature is genuine and the attack is the *age* of the
   * pair. Turn it on only for a deliberate re-bootstrap (cluster reinstalled,
   * CDS re-keyed), where the operator knows the identity legitimately went
   * backwards.
   */
  allowRollback?: boolean;
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

/** Message of a thrown value, without assuming it is an Error. */
const errMsg = (e: unknown): string => String((e as { message?: unknown })?.message ?? e);

/**
 * Normalise the measurement allowlist, refusing an empty one.
 *
 * An unpinned attestation is not a weaker check, it is a different check: it
 * answers "is this a genuine TEE" when the caller believes it answered "is this
 * MY cluster's CDS". Since the images are reproducible, anyone can satisfy the
 * former, and the mesh CA and allowlist derived from such an identity belong to
 * a cluster the caller never chose. verifyAttestation has always refused an
 * empty allowlist; a trust root has no business being laxer than the thing it
 * anchors.
 */
function requireMeasurements(policy: CDSPolicy): string[] {
  if (!policy || !Array.isArray(policy.measurements)) {
    fail("invalid_request", "attesting CDS requires a measurements allowlist");
  }
  if (policy.measurements.some((m) => typeof m !== "string")) {
    fail("invalid_request", "measurement allowlist entries must be strings");
  }
  const allowed = policy.measurements.map((m) => m.trim().toLowerCase()).filter(Boolean);
  if (allowed.length === 0) {
    fail(
      "invalid_request",
      "attesting CDS requires a non-empty measurements allowlist: without one this proves the " +
        "certificate came from some genuine TEE, not from your cluster — the c8s images are " +
        "reproducible, so anyone can stand up an instance that passes",
    );
  }
  return allowed;
}

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
 * this certificate's key and claims, a broken self-signature, a validity window
 * that does not contain `policy.at`, a launch digest outside the policy, or an
 * RTMR[3] mismatch all throw rather than returning a partial result.
 */
export async function attestCDSIdentity(
  certPEM: string | Uint8Array,
  policy: CDSPolicy,
): Promise<CDSIdentity> {
  const allowed = requireMeasurements(policy);

  // decodeOnePEM, not decodePEM(...)[0]: a discovery document shipping a bundle
  // would otherwise have its first certificate attested and the rest silently
  // dropped, and "which one did we actually verify?" is not a question a trust
  // root should leave open.
  let der: Uint8Array;
  if (typeof certPEM === "string") {
    try {
      der = decodeOnePEM(certPEM, "CERTIFICATE");
    } catch (err) {
      fail("cds_identity_invalid", `cds_identity is not a PEM CERTIFICATE: ${errMsg(err)}`);
    }
  } else {
    der = certPEM;
  }
  if (der.length === 0) fail("cds_identity_invalid", "cds_identity is empty");

  let cert: Certificate;
  try {
    cert = parseCertificate(der);
  } catch (err) {
    fail("cds_identity_invalid", `cannot parse cds_identity: ${errMsg(err)}`);
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

  // `!== undefined`, not a truthiness test: `expectedRtmr3: ""` used to be
  // falsy and so silently disabled the pin, which is exactly the "configured
  // but enforcing nothing" state the rest of this library refuses. Matches
  // verify.ts, which rejects an empty pin with invalid_request.
  const expectedRtmr3 =
    policy.expectedRtmr3 !== undefined ? decodeRtmr3(policy.expectedRtmr3) : undefined;

  let raw: string;
  try {
    // The WASM core takes the platform-specific evidence object ({quote,
    // cc_eventlog}), not the {platform, evidence} envelope that wraps it — the
    // platform tag has already been dispatched on above.
    raw = await verifierSeam.verifyTdx(
      JSON.stringify(envelope.evidence),
      expectedReportData,
      undefined,
      expectedRtmr3,
    );
  } catch (err) {
    fail("cds_identity_denied", `cds_identity attestation failed: ${errMsg(err)}`);
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

  // Only NOW is the certificate body worth reading. REPORTDATA covers the SPKI
  // and the config-claims bytes and nothing else — the validity window, serial,
  // subject and issuer are all outside it. What ties them to the attested key is
  // the self-signature: the certificate signs its own tbsCertificate with the
  // key the quote just vouched for, so verifying it against `cert.spki`
  // (attested, one check ago) upgrades the whole body from attacker-chosen to
  // TEE-asserted. Skipping this is not a formality — without it, anyone holding
  // a genuine CDS certificate can rewrite its notAfter to 2099 and replay the
  // pair forever, because the quote keeps matching.
  await verifySelfSignature(cert);

  // With the window now trustworthy, enforce it. Expiry is the ONLY bound on
  // replaying an old-but-internally-consistent (certificate, allowlist) pair,
  // so an unchecked window means unbounded downgrade.
  const at = policy.at ?? new Date();
  if (at < cert.notBefore) {
    fail(
      "cds_identity_expired",
      `cds_identity is not yet valid: notBefore ${cert.notBefore.toISOString()} is after the ` +
        `reference time ${at.toISOString()}`,
      { details: { notBefore: cert.notBefore.toISOString(), at: at.toISOString() } },
    );
  }
  if (at > cert.notAfter) {
    fail(
      "cds_identity_expired",
      `cds_identity expired at ${cert.notAfter.toISOString()} (reference time ` +
        `${at.toISOString()}): CDS re-issues this certificate on every allowlist change, so an ` +
        "expired one is a stale snapshot of the admission policy, not the policy in force",
      { details: { notAfter: cert.notAfter.toISOString(), at: at.toISOString() } },
    );
  }

  const launchDigest = String(result.claims.launch_digest).toLowerCase();
  if (!allowed.includes(launchDigest)) {
    fail(
      "cds_identity_denied",
      `cds_identity launch measurement ${launchDigest} is not in the allowlist`,
      { details: { measurement: launchDigest, allowed } },
    );
  }

  return {
    fingerprint: await fingerprintSHA256(der),
    launchDigest,
    claims: parseConfigClaims(claimsDER),
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
  };
}

/**
 * Verify that a certificate signs its own tbsCertificate with its own key.
 *
 * CDS's RA-TLS certificate is self-signed and served without a chain, so there
 * is no issuer to defer to; the signature is meaningful precisely because the
 * key it verifies against is the one REPORTDATA bound. Call it only after the
 * report-data check has passed.
 */
async function verifySelfSignature(cert: Certificate): Promise<void> {
  const hash = SELF_SIG_HASH[cert.sigAlgOID];
  if (!hash) {
    fail(
      "cds_identity_unsigned",
      `cds_identity is signed with unsupported algorithm ${cert.sigAlgOID} (want ECDSA with ` +
        "SHA-256 or SHA-384), so its validity window cannot be authenticated",
    );
  }
  let ok: boolean;
  try {
    ok = await verifyECDSASignature(cert, cert.tbs, cert.signatureDER, hash);
  } catch (err) {
    fail("cds_identity_unsigned", `cds_identity self-signature is unverifiable: ${errMsg(err)}`);
  }
  if (!ok) {
    fail(
      "cds_identity_unsigned",
      "cds_identity is not self-signed by the attested key: the hardware evidence vouches for " +
        "this public key and config-claims, but the certificate body around them (validity " +
        "window, serial, subject) has been altered and is not covered by the quote",
    );
  }
}

/** A verified CDS identity, plus whether it came from cache or from the TEE. */
export interface CachedCDSIdentity extends CDSIdentity {
  /** True when this verdict was reconstructed from cache; no WASM ran. */
  cached: boolean;
}

/**
 * attestCDSIdentity with a fingerprint-keyed cache and rollback detection.
 *
 * Two things happen here that plain attestation cannot do.
 *
 * The cheap one: CDS re-issues its certificate whenever the live allowlist
 * changes, so the certificate fingerprint is a perfect invalidation signal.
 * Same fingerprint, still inside its validity window, same policy — the verdict
 * is unchanged by construction and the hardware verifier is skipped entirely.
 *
 * The one that matters: a single attestation cannot detect a replayed
 * *genuine* certificate. Yesterday's CDS certificate and yesterday's allowlist
 * are internally consistent, correctly signed, and vouched for by real
 * hardware; the only thing wrong with the pair is that a newer one exists.
 * Comparing each new certificate's notBefore against the last one verified
 * turns that into something checkable, and refusing a move backwards closes the
 * downgrade. `policy.allowRollback` is the deliberate escape hatch for a real
 * re-bootstrap.
 *
 * @param cacheKey identifies the cluster (e.g. its base URL) — NOT the
 * fingerprint, which is the value expected to change.
 */
export async function attestCDSIdentityCached(
  certPEM: string | Uint8Array,
  policy: CDSPolicy,
  cache: CDSIdentityCache,
  cacheKey: string,
): Promise<CachedCDSIdentity> {
  let der: Uint8Array;
  if (typeof certPEM === "string") {
    try {
      der = decodeOnePEM(certPEM, "CERTIFICATE");
    } catch (err) {
      fail("cds_identity_invalid", `cds_identity is not a PEM CERTIFICATE: ${errMsg(err)}`);
    }
  } else {
    der = certPEM;
  }

  const at = policy.at ?? new Date();
  const fingerprint = await fingerprintSHA256(der);
  const policyDigest = await policyDigestHex(policy);
  const prior = await cache.get(cacheKey);

  if (prior !== undefined) {
    const hit = await cacheHit(prior, der, fingerprint, policyDigest, at);
    if (hit) return hit;
  }

  // Cache miss, fingerprint change, policy change, or an entry that no longer
  // holds: full verification, hardware and all.
  const fresh = await attestCDSIdentity(der, policy);

  if (prior !== undefined && policy.allowRollback !== true) {
    // The floor is the LAST VERIFIED certificate's notBefore, not the cached
    // one's expiry: a certificate that has since expired still proves the
    // cluster had reached that point in time, so its issuance instant remains a
    // valid lower bound even once the certificate itself is useless.
    const priorNotBefore = entryDate(prior, "notBeforeISO");
    if (fresh.notBefore < priorNotBefore) {
      fail(
        "cds_identity_rollback",
        `cds_identity went backwards: the presented certificate ${fresh.fingerprint} was issued ` +
          `at ${fresh.notBefore.toISOString()}, older than the already-verified certificate ` +
          `${prior.fingerprintSha256Hex} issued at ${priorNotBefore.toISOString()}. Both are ` +
          "genuine and internally consistent — that is what a downgrade looks like: an older " +
          "allowlist replayed with the certificate that attests it. Set allowRollback to accept " +
          "this deliberately (cluster reinstalled or CDS re-keyed).",
        {
          details: {
            presentedFingerprint: fresh.fingerprint,
            presentedNotBefore: fresh.notBefore.toISOString(),
            cachedFingerprint: prior.fingerprintSha256Hex,
            cachedNotBefore: priorNotBefore.toISOString(),
          },
        },
      );
    }
  }

  // Written only now: an entry exists if and only if full verification passed,
  // so the rollback floor can never be raised by a certificate that was refused.
  await cache.set(cacheKey, {
    fingerprintSha256Hex: fresh.fingerprint,
    notBeforeISO: fresh.notBefore.toISOString(),
    notAfterISO: fresh.notAfter.toISOString(),
    meshCaDigestHex: bytesToHex(fresh.claims.meshCaDigest),
    allowlistDigestHex: bytesToHex(fresh.claims.allowlistDigest),
    launchDigestHex: fresh.launchDigest,
    policyDigestHex: policyDigest,
    verifiedAtISO: at.toISOString(),
  });

  return { ...fresh, cached: false };
}

/**
 * Decide whether a cached entry can stand in for full verification, and
 * reconstruct the verdict if so.
 *
 * Returns undefined for "re-verify" on every doubt. A cache is an optimisation;
 * anything it cannot justify completely is a miss, never a partial acceptance.
 */
async function cacheHit(
  prior: CDSCacheEntry,
  der: Uint8Array,
  fingerprint: string,
  policyDigest: string,
  at: Date,
): Promise<CachedCDSIdentity | undefined> {
  // Different certificate: CDS re-issued, so the claims may have moved. Miss.
  if (prior.fingerprintSha256Hex !== fingerprint) return undefined;
  // Different policy: the cached verdict was reached under different pins, and
  // serving it now would silently ignore a measurement or RTMR[3] pin the
  // caller has since added. Miss.
  if (prior.policyDigestHex !== policyDigest) return undefined;
  // Outside the cached window: fall through so the full path reports the
  // expiry with its own error code rather than inventing one here.
  const notBefore = entryDate(prior, "notBeforeISO");
  const notAfter = entryDate(prior, "notAfterISO");
  if (at < notBefore || at > notAfter) return undefined;

  let cert: Certificate;
  try {
    cert = parseCertificate(der);
  } catch {
    return undefined;
  }

  // A fingerprint match means these bytes ARE the bytes that were verified, so
  // in principle the entry alone would do. Re-checking the self-signature and
  // the claims anyway costs one ECDSA verify and no WASM, and it means a
  // forged or corrupted cache entry cannot make us accept a certificate that
  // was never attested — the cache stops being a trust root and goes back to
  // being an optimisation.
  try {
    await verifySelfSignature(cert);
  } catch {
    return undefined;
  }
  if (cert.notBefore.getTime() !== notBefore.getTime()) return undefined;
  if (cert.notAfter.getTime() !== notAfter.getTime()) return undefined;

  const claimsDER = cert.extensions.get(OID_RATLS_CONFIG_CLAIMS);
  if (!claimsDER) return undefined;
  let claims: ConfigClaims;
  try {
    claims = parseConfigClaims(claimsDER);
  } catch {
    return undefined;
  }
  if (bytesToHex(claims.meshCaDigest) !== prior.meshCaDigestHex) return undefined;
  if (bytesToHex(claims.allowlistDigest) !== prior.allowlistDigestHex) return undefined;

  return {
    fingerprint,
    launchDigest: prior.launchDigestHex,
    claims,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    cached: true,
  };
}

/**
 * Digest of the acceptance-governing parts of a policy.
 *
 * `measurements` and `expectedRtmr3` decide whether a certificate is accepted,
 * so a verdict is only reusable under the same values. `at` deliberately is not
 * included (it changes every call and is checked directly), nor is
 * `allowRollback` (it loosens nothing about the certificate itself).
 */
async function policyDigestHex(policy: CDSPolicy): Promise<string> {
  const measurements = (policy.measurements ?? [])
    .map((m) => m.trim().toLowerCase())
    .filter(Boolean)
    .sort();
  const rtmr3 = policy.expectedRtmr3 === undefined ? "" : policy.expectedRtmr3.trim().toLowerCase();
  // JSON rather than concatenation: it delimits and escapes the elements, so
  // ["ab","cd"] and ["abcd"] cannot serialize to the same string. Object key
  // order is fixed by the literal, and the array is sorted above, so the
  // encoding is a function of the policy's content alone. `v` versions the
  // scheme, so changing what is covered invalidates old entries rather than
  // silently reusing verdicts reached under a different rule.
  const canonical = JSON.stringify({ v: 1, measurements, rtmr3 });
  const digest = await subtle().digest("SHA-256", new TextEncoder().encode(canonical));
  return bytesToHex(new Uint8Array(digest));
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
 * Pick, out of several served certificates, the one the attested claims vouch
 * for — and refuse if none of them is it.
 *
 * This is what lets a client stop pinning the mesh CA out of band. The server
 * hands over a chain; exactly one block in it should hash to the attested
 * meshCADigest, and that block alone becomes the anchor. The others are not
 * "also trusted", they are simply not selected — which is the difference
 * between deriving an anchor and accepting a bundle.
 */
export async function selectAttestedMeshCA(
  id: CDSIdentity,
  candidates: Uint8Array[],
): Promise<Uint8Array> {
  if (!hasDigest(id.claims.meshCaDigest)) {
    fail(
      "mesh_ca_not_attested",
      "attested claims carry no mesh-CA digest (claims v1), so the mesh CA cannot be derived — " +
        "pin it out of band with meshCaPem, or upgrade the cluster",
    );
  }
  if (candidates.length === 0) {
    fail(
      "mesh_ca_denied",
      "the server served no CA certificate alongside its leaf, so there is nothing to match " +
        "against the attested mesh-CA digest",
    );
  }
  const seen: string[] = [];
  for (const der of candidates) {
    const got = new Uint8Array(await subtle().digest("SHA-256", der.slice()));
    if (constantTimeEqual(got, id.claims.meshCaDigest)) return der;
    seen.push(bytesToHex(got));
  }
  fail(
    "mesh_ca_denied",
    `none of the ${candidates.length} served CA certificate(s) matches the attested mesh-CA ` +
      `digest ${bytesToHex(id.claims.meshCaDigest)} (served: ${seen.join(", ")}) — the verified ` +
      "CDS does not issue under any CA this server presented",
    { details: { attested: bytesToHex(id.claims.meshCaDigest), served: seen } },
  );
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
    fail("cds_identity_invalid", `cannot parse evidence envelope: ${errMsg(err)}`);
  }
  if (!envelope.platform || envelope.evidence === undefined) {
    fail("cds_identity_invalid", "evidence envelope is missing platform or evidence");
  }
  return { platform: envelope.platform, evidence: envelope.evidence };
}

/** Number of bytes needed to represent a non-negative integer. */
function byteWidth(n: number): number {
  let w = 1;
  while (n > 0xff) {
    n = Math.floor(n / 256);
    w++;
  }
  return w;
}

/**
 * Assert that a node's length is written the one way DER permits.
 *
 * DER's whole promise is that a value has exactly one encoding, but the reader
 * in asn1.ts is permissive about *how* a length is written — 0x81 0xAD and
 * 0x82 0x00 0xAD both decode to 173. For most parsing that laxity is harmless.
 * Here it is not: the REPORTDATA transcript hashes the config-claims bytes
 * verbatim, so "these bytes mean these claims" has to be a bijection. Go's
 * UnmarshalConfigClaims buys the same property with a byte-exact re-encode
 * round-trip and calls the strictness load-bearing; this states the rule
 * directly instead.
 */
function requireMinimalLength(node: DERNode, what: string): void {
  const len = node.contentEnd - node.contentStart;
  const lengthBytes = node.headerLen - 1;
  const minimal = len < 0x80 ? 1 : 1 + byteWidth(len);
  if (lengthBytes !== minimal) {
    fail(
      "cds_identity_invalid",
      `${what} uses a non-minimal DER length (${lengthBytes} length octets for ${len} bytes, ` +
        `minimal is ${minimal}): two encodings of one value would let two distinct extension ` +
        "byte strings yield the same claims, and REPORTDATA binds the bytes",
    );
  }
}

/**
 * Decode the config-claims extension, accepting v1, v2 and v3.
 *
 * Fields a version predates read as the sentinel, so a client asking for a
 * property those claims never carried gets an explicit failure rather than a
 * zero value that quietly compares equal to nothing.
 *
 * The encoding is required to be the ONE canonical DER encoding of its version:
 * minimal lengths throughout, a minimal version INTEGER, and nothing after the
 * outer SEQUENCE. Parity with c8s pkg/ratls UnmarshalConfigClaims, and for the
 * same reason — "parses as vN" has to mean "is the one vN encoding", because
 * the attestation binds these bytes rather than their meaning.
 */
export function parseConfigClaims(der: Uint8Array): ConfigClaims {
  const seq = readTLV(der, 0);
  if (seq.tag !== TAG.SEQUENCE) {
    fail("cds_identity_invalid", "config-claims extension is not a SEQUENCE");
  }
  // Trailing bytes are not "extra data to ignore": they change the extension
  // value, and so the REPORTDATA preimage, while leaving the parsed claims
  // identical. Go rejects them; so do we.
  if (seq.end !== der.length) {
    fail(
      "cds_identity_invalid",
      `config-claims extension has ${der.length - seq.end} trailing bytes after the SEQUENCE`,
    );
  }
  requireMinimalLength(seq, "config-claims SEQUENCE");

  const parts = readChildren(der, seq);
  for (const [i, p] of parts.entries()) requireMinimalLength(p, `config-claims field ${i}`);

  const versionNode = parts[0];
  if (versionNode?.tag !== TAG.INTEGER) {
    fail("cds_identity_invalid", "config-claims extension has no version INTEGER");
  }
  // DER INTEGERs are minimally encoded two's-complement: never empty, and no
  // redundant leading byte. Without this, {02 01 03} and {02 02 00 03} both read
  // as version 3 — two byte strings, one meaning, which is exactly what must not
  // happen when the bytes are what the quote committed to.
  const v = versionNode.content;
  if (v.length === 0) {
    fail("cds_identity_invalid", "config-claims version INTEGER is empty");
  }
  if (v.length > 1 && (v[0] === 0x00 || v[0] === 0xff) && (v[0] & 0x80) === (v[1] & 0x80)) {
    fail(
      "cds_identity_invalid",
      "config-claims version INTEGER is not minimally encoded (redundant leading byte)",
    );
  }
  if (v[0] & 0x80) {
    fail("cds_identity_invalid", "config-claims version INTEGER is negative");
  }
  let version = 0;
  for (const b of v) version = version * 256 + b;

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
