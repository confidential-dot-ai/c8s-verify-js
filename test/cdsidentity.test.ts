import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  attestCDSIdentity,
  attestCDSIdentityCached,
  cdsIdentityPEM,
  hasDigest,
  parseConfigClaims,
  verifyAllowlist,
  verifyMeshCA,
  verifierSeam,
  type CDSIdentity,
} from "../src/cdsidentity.js";
import {
  MemoryCDSIdentityCache,
  StorageCDSIdentityCache,
  isCacheEntry,
  type CDSCacheEntry,
  type WebStorageLike,
} from "../src/cdscache.js";
import { C8sVerifyError } from "../src/errors.js";
import { decodePEM, encodePEM } from "../src/pem.js";
import { bytesToHex } from "../src/base64.js";
import { fingerprintSHA256, parseCertificate } from "../src/x509.js";

const OID_CONFIG_CLAIMS = "1.3.6.1.4.1.59888.1.3";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// LIVE-captured from a bare-metal Intel TDX c8s cluster: CDS's own self-signed
// RA-TLS certificate (config-claims v3), the mesh CA it issues under, and the
// exact bytes of GET /allowlist at the same moment. The three are
// self-consistent by construction — the certificate's meshCADigest and
// allowlistDigest are SHA-256 of the other two files — which is precisely the
// property under test.
const cdsIdentity = () => readFile(join(FIX, "cds-identity.pem"), "utf8");
const meshCA = async () => decodePEM(await readFile(join(FIX, "cds-mesh-ca.pem"), "utf8"))[0];
const allowlistBytes = () => readFile(join(FIX, "cds-allowlist.json"));

// The measurement this cluster's guest image launches with.
const MRTD =
  "9309eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1";
// RTMR[3] = SHA384(0x00*48 ‖ SHA384(operator_pubkey)) for this deployment.
const RTMR3 =
  "a9b91d920971de864899fb5925c4b5230bf88750dd59866d8d34aeb975e86761ea7488ade961908d9595b6202c9e6470";

// The fixture certificate's real validity window, read off the DER. Every test
// that must succeed pins `at` inside it: the certificate has a 24h TTL, so
// without a frozen reference time this whole suite would start failing on
// 2026-07-30 for reasons that have nothing to do with the code under test.
const CERT_NOT_BEFORE = new Date("2026-07-29T07:05:20Z");
const CERT_NOT_AFTER = new Date("2026-07-30T07:05:20Z");
const AT = new Date("2026-07-29T12:00:00Z"); // comfortably inside the window
const AFTER_EXPIRY = new Date("2026-07-31T00:00:00Z");
const BEFORE_ISSUANCE = new Date("2026-07-01T00:00:00Z");

async function attested(): Promise<CDSIdentity> {
  return attestCDSIdentity(await cdsIdentity(), { measurements: [MRTD], at: AT });
}

/** Assert a thrown value is a C8sVerifyError with this code, and (optionally) message. */
function isError(code: string, messageIncludes?: string) {
  return (err: unknown): true => {
    assert.ok(err instanceof C8sVerifyError, `expected C8sVerifyError, got ${String(err)}`);
    assert.equal(err.code, code, `wrong code; message was: ${err.message}`);
    if (messageIncludes !== undefined) {
      assert.ok(
        err.message.includes(messageIncludes),
        `expected message to name its cause (${JSON.stringify(messageIncludes)}), got: ${err.message}`,
      );
    }
    return true;
  };
}

/**
 * Rewrite the certificate's notAfter in place.
 *
 * UTCTime is fixed-width ASCII inside the DER, so this changes the validity
 * window without moving a single length octet — the SPKI and the config-claims
 * bytes, which are all REPORTDATA covers, are untouched. The hardware evidence
 * therefore still verifies; only the self-signature breaks. That is exactly the
 * attack the self-signature check exists to stop.
 */
function rewriteNotAfter(der: Uint8Array, utcTime: string): Uint8Array {
  const idx = Buffer.from(der).indexOf(Buffer.from("260730070520Z"));
  assert.ok(idx > 0, "fixture notAfter not found — has the fixture been regenerated?");
  assert.equal(utcTime.length, 13, "replacement must be the same width");
  const out = Uint8Array.from(der);
  out.set(new TextEncoder().encode(utcTime), idx);
  return out;
}

test("attests a live CDS certificate and returns its claims", async () => {
  const id = await attested();
  assert.equal(id.launchDigest, MRTD);
  assert.equal(id.claims.version, 3);
  assert.ok(hasDigest(id.claims.meshCaDigest), "no mesh-CA digest in attested claims");
  assert.ok(hasDigest(id.claims.allowlistDigest), "no live-allowlist digest in attested claims");
  assert.match(id.fingerprint, /^[0-9a-f]{64}$/);
  assert.equal(id.notBefore.getTime(), CERT_NOT_BEFORE.getTime());
  assert.equal(id.notAfter.getTime(), CERT_NOT_AFTER.getTime());
});

// Previously this test asserted only `launchDigest.length > 0`, which is true of
// any successful attestation and therefore proved nothing about the binding.
// Editing a byte INSIDE the config-claims extension, keeping every length
// identical, is the real check: the transcript is SHA-384 over the claims DER
// verbatim, so one flipped bit must break report_data and nothing else.
test("binds REPORTDATA to the certificate key AND its claims", async () => {
  const der = decodePEM(await cdsIdentity())[0];
  const raw = parseCertificate(der).extensions.get(OID_CONFIG_CLAIMS)!;
  assert.equal(parseConfigClaims(raw).version, 3);

  const offset = Buffer.from(der).indexOf(Buffer.from(raw));
  assert.ok(offset > 0, "claims extension not located in the DER");
  const tampered = Uint8Array.from(der);
  // Flip one bit of the attested meshCADigest — same length, same structure,
  // so nothing but the claims content changes.
  tampered[offset + raw.length - 40] ^= 0x01;

  await assert.rejects(
    attestCDSIdentity(tampered, { measurements: [MRTD], at: AT }),
    isError("cds_identity_denied", "report_data mismatch"),
  );
});

// The message, not just the code: cds_identity_denied covers attestation
// failure, bad signature, report-data mismatch, RTMR[3] and measurement, so a
// bare code assertion would stay green if this started failing for an unrelated
// reason — which is precisely how the earlier negative tests passed for years
// while checking nothing.
test("rejects a certificate outside the measurement policy", async () => {
  await assert.rejects(
    attestCDSIdentity(await cdsIdentity(), { measurements: ["ab".repeat(48)], at: AT }),
    isError("cds_identity_denied", `launch measurement ${MRTD} is not in the allowlist`),
  );
});

test("rejects a mismatched RTMR[3]: genuine TEE, wrong deployment", async () => {
  await assert.rejects(
    attestCDSIdentity(await cdsIdentity(), {
      measurements: [MRTD],
      expectedRtmr3: "11".repeat(48),
      at: AT,
    }),
    isError("cds_identity_denied", "RTMR[3] does not match expected_rtmr3"),
  );
});

test("accepts the matching RTMR[3]", async () => {
  const id = await attestCDSIdentity(await cdsIdentity(), {
    measurements: [MRTD],
    expectedRtmr3: RTMR3,
    at: AT,
  });
  assert.equal(id.launchDigest, MRTD);
});

// An empty pin used to be falsy and so silently disabled the check — the exact
// "configured but enforcing nothing" state this library refuses everywhere else.
test("refuses an empty expectedRtmr3 rather than silently dropping the pin", async () => {
  await assert.rejects(
    attestCDSIdentity(await cdsIdentity(), { measurements: [MRTD], expectedRtmr3: "", at: AT }),
    isError("invalid_request", "96 hex characters"),
  );
});

// This asserted nothing at all before (a bare `assert.rejects`), so it passed on
// any throw — including the DER parse error it actually produced, which says
// nothing about attestation.
test("rejects a tampered certificate — this is what makes relaying it safe", async () => {
  const der = decodePEM(await cdsIdentity())[0];
  const edited = Uint8Array.from(der);
  edited[Math.floor(edited.length / 2)] ^= 0xff;
  await assert.rejects(
    attestCDSIdentity(edited, { measurements: [MRTD], at: AT }),
    isError("cds_identity_denied", "cds_identity attestation failed"),
  );
});

// Regression test for the fail-open this branch shipped with: REPORTDATA covers
// only the SPKI and the config-claims bytes, so anyone holding a genuine CDS
// certificate could rewrite its notAfter and replay the (certificate,
// allowlist) pair forever. The quote still verified; nothing checked the
// certificate body.
test("rejects a certificate whose validity window was rewritten", async () => {
  const der = decodePEM(await cdsIdentity())[0];
  const forged = rewriteNotAfter(der, "270730070520Z"); // +1 year, same width

  // The forgery is effective: the window really did move.
  assert.equal(parseCertificate(forged).notAfter.toISOString(), "2027-07-30T07:05:20.000Z");

  await assert.rejects(
    attestCDSIdentity(forged, { measurements: [MRTD], at: AT }),
    isError("cds_identity_unsigned", "not self-signed by the attested key"),
  );
});

test("rejects an expired certificate", async () => {
  await assert.rejects(
    attestCDSIdentity(await cdsIdentity(), { measurements: [MRTD], at: AFTER_EXPIRY }),
    isError("cds_identity_expired", "expired at 2026-07-30T07:05:20.000Z"),
  );
});

test("rejects a certificate that is not yet valid", async () => {
  await assert.rejects(
    attestCDSIdentity(await cdsIdentity(), { measurements: [MRTD], at: BEFORE_ISSUANCE }),
    isError("cds_identity_expired", "not yet valid"),
  );
});

// decodeOnePEM, not decodePEM(...)[0]: silently attesting the first of several
// certificates leaves "which one did we verify?" open on a trust root.
test("refuses a PEM carrying more than one certificate", async () => {
  const bundle = (await cdsIdentity()) + encodePEM(await meshCA());
  await assert.rejects(
    attestCDSIdentity(bundle, { measurements: [MRTD], at: AT }),
    isError("cds_identity_invalid", "expected exactly one PEM CERTIFICATE block"),
  );
});

test("derives the mesh CA, and refuses any other CA", async () => {
  const id = await attested();
  await verifyMeshCA(id, await meshCA());

  // The CDS certificate itself is a certificate, but not THE mesh CA.
  const notTheCA = decodePEM(await cdsIdentity())[0];
  await assert.rejects(
    verifyMeshCA(id, notTheCA),
    isError("mesh_ca_denied", "does not match the attested value"),
  );
});

test("verifies the served allowlist, and catches a single extra byte", async () => {
  const id = await attested();
  const raw = new Uint8Array(await allowlistBytes());
  await verifyAllowlist(id, raw);

  // The trailing-newline mistake: semantically identical, different bytes.
  const plusNewline = new Uint8Array(raw.length + 1);
  plusNewline.set(raw);
  plusNewline[raw.length] = 0x0a;
  await assert.rejects(
    verifyAllowlist(id, plusNewline),
    isError("allowlist_denied", "does not match the attested value"),
  );
});

test("a re-serialized allowlist does not verify, even when equivalent", async () => {
  // Documents the footgun explicitly: JSON.stringify of the parsed document is
  // the same data and a different digest. Callers must hash the response.
  const id = await attested();
  const raw = new Uint8Array(await allowlistBytes());
  const reserialized = new TextEncoder().encode(
    JSON.stringify(JSON.parse(new TextDecoder().decode(raw))),
  );
  if (bytesToHex(reserialized) === bytesToHex(raw)) return; // nothing to prove
  await assert.rejects(verifyAllowlist(id, reserialized), isError("allowlist_denied"));
});

test("claims that predate a field cannot satisfy a request for it", async () => {
  const v1: CDSIdentity = {
    fingerprint: "0".repeat(64),
    launchDigest: MRTD,
    notBefore: CERT_NOT_BEFORE,
    notAfter: CERT_NOT_AFTER,
    claims: {
      version: 1,
      operatorKeysDigest: new Uint8Array(32),
      seedDigest: new Uint8Array(32),
      workloadDigest: new Uint8Array(32),
      meshCaDigest: new Uint8Array(32),
      allowlistDigest: new Uint8Array(32),
    },
  };
  await assert.rejects(
    verifyMeshCA(v1, await meshCA()),
    isError("mesh_ca_not_attested", "claims v1"),
  );
  await assert.rejects(
    verifyAllowlist(v1, new Uint8Array(await allowlistBytes())),
    isError("allowlist_not_attested", "claims v1/v2"),
  );
});

test("a discovery document without cds_identity is an explicit failure", () => {
  assert.throws(() => cdsIdentityPEM({}), isError("cds_identity_missing"));
});

test("rejects an unsupported claims version rather than ignoring the claims", () => {
  // SEQUENCE { INTEGER 9, ... } — a future version this build cannot read.
  const der = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x09]);
  assert.throws(() => parseConfigClaims(der), isError("unsupported", "version 9"));
});

/** A v3 claims body: version INTEGER followed by five 32-byte digests. */
function claimsBody(version: number[]): number[] {
  const d32 = (b: number) => [0x04, 0x20, ...Array<number>(32).fill(b)];
  return [...version, ...d32(1), ...d32(2), ...d32(3), ...d32(4), ...d32(5)];
}

// The property Go's UnmarshalConfigClaims spells out and enforces with a
// byte-exact re-encode round-trip: "parses as vN" must mean "IS the one vN
// encoding". It is load-bearing because REPORTDATA hashes the extension bytes
// verbatim — if two byte strings can decode to one ConfigClaims, then the value
// the quote committed to and the value policy is enforced against are no longer
// the same object. Every variant below used to be accepted, all five decoding to
// an identical ConfigClaims.
test("accepts only the one canonical DER encoding of a claims value", () => {
  const body = claimsBody([0x02, 0x01, 0x03]);
  const L = body.length; // 173 — long form, one length octet

  // The canonical encoding must still parse, or the rule is too strict.
  const canonical = new Uint8Array([0x30, 0x81, L, ...body]);
  assert.equal(parseConfigClaims(canonical).version, 3);

  const wideBody = claimsBody([0x02, 0x02, 0x00, 0x03]); // version 3, padded
  for (const [name, der, expect] of [
    ["two-byte length", [0x30, 0x82, 0x00, L, ...body], "non-minimal DER length"],
    ["three-byte length", [0x30, 0x83, 0, 0, L, ...body], "non-minimal DER length"],
    ["trailing bytes", [...canonical, 0xde, 0xad, 0xbe, 0xef], "trailing bytes"],
    ["padded version INTEGER", [0x30, 0x81, wideBody.length, ...wideBody], "minimally encoded"],
  ] as const) {
    assert.throws(
      () => parseConfigClaims(new Uint8Array(der)),
      isError("cds_identity_invalid", expect),
      `${name} must be refused`,
    );
  }

  // A non-minimal length on an INNER field, not just the outer SEQUENCE: the
  // first digest written as 0x04 0x81 0x20 instead of 0x04 0x20.
  const d32 = (b: number) => [0x04, 0x20, ...Array<number>(32).fill(b)];
  const fat = [
    0x02,
    0x01,
    0x03,
    0x04,
    0x81,
    0x20,
    ...Array<number>(32).fill(1), // long-form length on field 1
    ...d32(2),
    ...d32(3),
    ...d32(4),
    ...d32(5),
  ];
  assert.throws(
    () => parseConfigClaims(new Uint8Array([0x30, 0x81, fat.length, ...fat])),
    isError("cds_identity_invalid", "config-claims field 1 uses a non-minimal DER length"),
  );
});

test("rejects a negative or empty claims version INTEGER", () => {
  const body = claimsBody([0x02, 0x01, 0xff]); // -1
  assert.throws(
    () => parseConfigClaims(new Uint8Array([0x30, 0x81, body.length, ...body])),
    isError("cds_identity_invalid", "negative"),
  );
  const empty = claimsBody([0x02, 0x00]);
  assert.throws(
    () => parseConfigClaims(new Uint8Array([0x30, 0x81, empty.length, ...empty])),
    isError("cds_identity_invalid", "empty"),
  );
});

// The live fixture is the proof the rule is calibrated: real CDS output, from
// Go's asn1.Marshal, must sail through unchanged.
test("the live CDS certificate's claims are canonically encoded", async () => {
  const raw = parseCertificate(decodePEM(await cdsIdentity())[0]).extensions.get(
    OID_CONFIG_CLAIMS,
  )!;
  assert.equal(parseConfigClaims(raw).version, 3);
});

// ---------------------------------------------------------------------------
// Cache + rollback detection
// ---------------------------------------------------------------------------

/**
 * Count calls into the hardware verifier.
 *
 * The cached path's whole contract is "no WASM ran", and the only way to prove
 * a function was not called is to count it. Restores the real verifier on
 * dispose so one test cannot leak into the next.
 */
function countingVerifier(): { calls: () => number; restore: () => void } {
  const real = verifierSeam.verifyTdx;
  let calls = 0;
  verifierSeam.verifyTdx = async (...args: Parameters<typeof real>) => {
    calls++;
    return real(...args);
  };
  return { calls: () => calls, restore: () => (verifierSeam.verifyTdx = real) };
}

/** A prior entry for some OTHER certificate, issued at `notBefore`. */
function priorEntry(notBefore: Date, fingerprint = "aa".repeat(32)): CDSCacheEntry {
  return {
    fingerprintSha256Hex: fingerprint,
    notBeforeISO: notBefore.toISOString(),
    notAfterISO: new Date(notBefore.getTime() + 86_400_000).toISOString(),
    meshCaDigestHex: "bb".repeat(32),
    allowlistDigestHex: "cc".repeat(32),
    launchDigestHex: MRTD,
    policyDigestHex: "0".repeat(64),
    verifiedAtISO: notBefore.toISOString(),
  };
}

test("first attestation is a cache miss, runs the verifier, and stores the verdict", async () => {
  const cache = new MemoryCDSIdentityCache();
  const v = countingVerifier();
  try {
    const id = await attestCDSIdentityCached(
      await cdsIdentity(),
      { measurements: [MRTD], at: AT },
      cache,
      "cluster-a",
    );
    assert.equal(id.cached, false);
    assert.equal(id.launchDigest, MRTD);
    assert.equal(v.calls(), 1, "a cold cache must reach the hardware verifier");

    const stored = cache.get("cluster-a");
    assert.ok(stored, "verified identity was not cached");
    assert.equal(stored.fingerprintSha256Hex, id.fingerprint);
    assert.equal(stored.notBeforeISO, CERT_NOT_BEFORE.toISOString());
    assert.equal(stored.launchDigestHex, MRTD);
    assert.equal(stored.meshCaDigestHex, bytesToHex(id.claims.meshCaDigest));
  } finally {
    v.restore();
  }
});

test("an unchanged certificate is served from cache without touching the verifier", async () => {
  const cache = new MemoryCDSIdentityCache();
  const policy = { measurements: [MRTD], at: AT };
  const pem = await cdsIdentity();
  const first = await attestCDSIdentityCached(pem, policy, cache, "cluster-a");

  const v = countingVerifier();
  try {
    const second = await attestCDSIdentityCached(pem, policy, cache, "cluster-a");
    assert.equal(second.cached, true, "second call should be a cache hit");
    assert.equal(v.calls(), 0, "a cache hit must not reach the hardware verifier");
    // The reconstruction must be complete, not a stub: everything a caller
    // reads off a fresh verdict has to be there.
    assert.equal(second.fingerprint, first.fingerprint);
    assert.equal(second.launchDigest, MRTD);
    assert.equal(second.claims.version, 3);
    assert.deepEqual(second.claims.meshCaDigest, first.claims.meshCaDigest);
    assert.deepEqual(second.claims.allowlistDigest, first.claims.allowlistDigest);
    assert.equal(second.notBefore.getTime(), first.notBefore.getTime());
    // And it must still be usable for what attestation is FOR.
    await verifyMeshCA(second, await meshCA());
    await verifyAllowlist(second, new Uint8Array(await allowlistBytes()));
  } finally {
    v.restore();
  }
});

// A cached verdict is only valid for the policy that produced it. Serving it
// under a tightened policy would silently ignore a pin the caller just added.
test("a tightened policy is a cache miss, not a hit", async () => {
  const cache = new MemoryCDSIdentityCache();
  const pem = await cdsIdentity();
  await attestCDSIdentityCached(pem, { measurements: [MRTD], at: AT }, cache, "cluster-a");

  const v = countingVerifier();
  try {
    // Same certificate, but now an RTMR[3] pin is demanded.
    const again = await attestCDSIdentityCached(
      pem,
      { measurements: [MRTD], expectedRtmr3: RTMR3, at: AT },
      cache,
      "cluster-a",
    );
    assert.equal(again.cached, false, "adding a pin must force re-verification");
    assert.equal(v.calls(), 1);
  } finally {
    v.restore();
  }

  // ...and the newly added pin is genuinely enforced, not just re-run.
  await assert.rejects(
    attestCDSIdentityCached(
      pem,
      { measurements: [MRTD], expectedRtmr3: "11".repeat(48), at: AT },
      cache,
      "cluster-a",
    ),
    isError("cds_identity_denied", "RTMR[3] does not match expected_rtmr3"),
  );
});

test("a cached entry outside its validity window falls through and reports expiry", async () => {
  const cache = new MemoryCDSIdentityCache();
  const pem = await cdsIdentity();
  await attestCDSIdentityCached(pem, { measurements: [MRTD], at: AT }, cache, "cluster-a");

  // Same certificate, later clock: the cache must not paper over expiry.
  await assert.rejects(
    attestCDSIdentityCached(pem, { measurements: [MRTD], at: AFTER_EXPIRY }, cache, "cluster-a"),
    isError("cds_identity_expired", "expired at"),
  );
});

// The downgrade this whole mechanism exists for: an older certificate, its own
// signature perfectly valid, carrying an older allowlist digest.
test("refuses a certificate older than one already verified", async () => {
  const cache = new MemoryCDSIdentityCache();
  // A previously verified identity issued AFTER the fixture certificate.
  cache.set("cluster-a", priorEntry(new Date("2026-07-29T08:00:00Z")));

  await assert.rejects(
    attestCDSIdentityCached(
      await cdsIdentity(),
      { measurements: [MRTD], at: AT },
      cache,
      "cluster-a",
    ),
    isError("cds_identity_rollback", "went backwards"),
  );

  // The refused certificate must not have been written to the cache: a rejected
  // identity moving the rollback floor would be the bug the check prevents.
  assert.equal(cache.get("cluster-a")?.fingerprintSha256Hex, "aa".repeat(32));
});

test("the rollback error names both certificates and both timestamps", async () => {
  const cache = new MemoryCDSIdentityCache();
  cache.set("cluster-a", priorEntry(new Date("2026-07-29T08:00:00Z")));
  const err = await attestCDSIdentityCached(
    await cdsIdentity(),
    { measurements: [MRTD], at: AT },
    cache,
    "cluster-a",
  ).catch((e: unknown) => e as C8sVerifyError);

  assert.ok(err instanceof C8sVerifyError);
  assert.equal(err.details.cachedFingerprint, "aa".repeat(32));
  assert.equal(err.details.cachedNotBefore, "2026-07-29T08:00:00.000Z");
  assert.equal(err.details.presentedNotBefore, CERT_NOT_BEFORE.toISOString());
  assert.match(String(err.details.presentedFingerprint), /^[0-9a-f]{64}$/);
});

test("accepts a certificate newer than the one already verified, and updates the cache", async () => {
  const cache = new MemoryCDSIdentityCache();
  cache.set("cluster-a", priorEntry(new Date("2026-07-29T06:00:00Z")));

  const id = await attestCDSIdentityCached(
    await cdsIdentity(),
    { measurements: [MRTD], at: AT },
    cache,
    "cluster-a",
  );
  assert.equal(id.cached, false);
  assert.equal(id.notBefore.getTime(), CERT_NOT_BEFORE.getTime());

  const stored = cache.get("cluster-a");
  assert.equal(stored?.fingerprintSha256Hex, id.fingerprint);
  assert.equal(stored?.notBeforeISO, CERT_NOT_BEFORE.toISOString());
});

test("allowRollback lets an operator deliberately re-bootstrap", async () => {
  const cache = new MemoryCDSIdentityCache();
  cache.set("cluster-a", priorEntry(new Date("2026-07-29T08:00:00Z")));

  const id = await attestCDSIdentityCached(
    await cdsIdentity(),
    { measurements: [MRTD], at: AT, allowRollback: true },
    cache,
    "cluster-a",
  );
  assert.equal(id.cached, false);
  // The floor moves down to the accepted certificate — that is the point of
  // the flag, and why it is off by default.
  assert.equal(cache.get("cluster-a")?.notBeforeISO, CERT_NOT_BEFORE.toISOString());
});

// A rollback must be refused even when the older certificate is otherwise
// flawless: the point is that nothing about it is forged.
test("rollback is refused before the certificate's own merits are considered", async () => {
  const cache = new MemoryCDSIdentityCache();
  cache.set("cluster-a", priorEntry(new Date("2026-07-29T08:00:00Z")));
  const id = attestCDSIdentityCached(
    await cdsIdentity(),
    { measurements: [MRTD], expectedRtmr3: RTMR3, at: AT },
    cache,
    "cluster-a",
  );
  // Even with every pin satisfied, age alone is disqualifying.
  await assert.rejects(id, isError("cds_identity_rollback"));
});

// The cache must stay an optimisation, never become a trust root. A poisoned
// entry — same shape, same policy, pointing at a certificate that was never
// attested — must not buy a cached verdict, which is why the hit path re-checks
// the self-signature instead of taking the fingerprint's word for it.
test("a poisoned cache entry cannot smuggle in an unattested certificate", async () => {
  const cache = new MemoryCDSIdentityCache();
  const policy = { measurements: [MRTD], at: AT };
  const pem = await cdsIdentity();

  // Establish a legitimate entry so the stored policy digest is the real one.
  await attestCDSIdentityCached(pem, policy, cache, "cluster-a");

  // The attacker's certificate: genuine SPKI and claims (so the quote still
  // binds), validity window pushed out by a year (so it never expires).
  const forged = rewriteNotAfter(decodePEM(pem)[0], "270730070520Z");
  const forgedCert = parseCertificate(forged);
  const forgedClaims = parseConfigClaims(forgedCert.extensions.get(OID_CONFIG_CLAIMS)!);
  const forgedFingerprint = await fingerprintSHA256(forged);

  // Rewrite the cache to vouch for it, keeping the legitimate policy digest so
  // the only thing standing in the way is the signature.
  const poisoned = cache.get("cluster-a")!;
  cache.set("cluster-a", {
    ...poisoned,
    fingerprintSha256Hex: forgedFingerprint,
    notBeforeISO: forgedCert.notBefore.toISOString(),
    notAfterISO: forgedCert.notAfter.toISOString(),
    meshCaDigestHex: bytesToHex(forgedClaims.meshCaDigest),
    allowlistDigestHex: bytesToHex(forgedClaims.allowlistDigest),
  });

  const v = countingVerifier();
  try {
    await assert.rejects(
      attestCDSIdentityCached(forged, policy, cache, "cluster-a"),
      isError("cds_identity_unsigned", "not self-signed by the attested key"),
    );
    // It fell through to the full path rather than being served from cache.
    assert.equal(v.calls(), 1, "a rejected hit must re-verify, not short-circuit");
  } finally {
    v.restore();
  }
});

// ---------------------------------------------------------------------------
// Cache implementations
// ---------------------------------------------------------------------------

/** Minimal in-memory stand-in for the browser's localStorage. */
function stubStorage(): WebStorageLike & { raw: Map<string, string> } {
  const raw = new Map<string, string>();
  return {
    raw,
    getItem: (k) => raw.get(k) ?? null,
    setItem: (k, v) => void raw.set(k, v),
    removeItem: (k) => void raw.delete(k),
  };
}

test("StorageCDSIdentityCache round-trips an entry through Web Storage", () => {
  const storage = stubStorage();
  const cache = new StorageCDSIdentityCache(storage);
  const entry = priorEntry(CERT_NOT_BEFORE, "dd".repeat(32));

  assert.equal(cache.get("cluster-a"), undefined, "empty storage must read as a miss");
  cache.set("cluster-a", entry);
  assert.deepEqual(cache.get("cluster-a"), entry);

  // Namespaced, so it cannot collide with the host application's keys.
  assert.ok([...storage.raw.keys()].every((k) => k.startsWith("c8s-verify:cds-identity:")));

  cache.clear("cluster-a");
  assert.equal(cache.get("cluster-a"), undefined);
});

// A half-written or edited entry must read as a miss, never as a partial hit:
// a hit missing notBefore would silently disable the rollback floor.
test("StorageCDSIdentityCache treats a corrupt entry as a miss", () => {
  const storage = stubStorage();
  const cache = new StorageCDSIdentityCache(storage);
  const key = "c8s-verify:cds-identity:cluster-a";

  for (const bad of [
    "not json at all",
    "null",
    "[]",
    JSON.stringify({ fingerprintSha256Hex: "ab".repeat(32) }), // truncated
    JSON.stringify({ ...priorEntry(AT), notBeforeISO: "whenever" }), // unparseable date
    JSON.stringify({ ...priorEntry(AT), fingerprintSha256Hex: "short" }),
    JSON.stringify({ ...priorEntry(AT), fingerprintSha256Hex: "zz".repeat(32) }), // not hex
  ]) {
    storage.raw.set(key, bad);
    assert.equal(cache.get("cluster-a"), undefined, `should be a miss: ${bad.slice(0, 40)}`);
  }
});

test("StorageCDSIdentityCache survives storage that throws (private mode, full quota)", () => {
  const throwing: WebStorageLike = {
    getItem: () => {
      throw new Error("storage disabled");
    },
    setItem: () => {
      throw new Error("quota exceeded");
    },
    removeItem: () => {
      throw new Error("nope");
    },
  };
  const cache = new StorageCDSIdentityCache(throwing);
  // A failing cache costs a re-attestation, never a failed verification.
  assert.equal(cache.get("cluster-a"), undefined);
  assert.doesNotThrow(() => cache.set("cluster-a", priorEntry(AT)));
  assert.doesNotThrow(() => cache.clear("cluster-a"));
});

test("MemoryCDSIdentityCache hands back copies, so a caller cannot move the floor", () => {
  const cache = new MemoryCDSIdentityCache();
  const entry = priorEntry(new Date("2026-07-29T08:00:00Z"));
  cache.set("cluster-a", entry);

  const got = cache.get("cluster-a")!;
  got.notBeforeISO = "1970-01-01T00:00:00.000Z"; // try to lower the rollback floor
  assert.equal(cache.get("cluster-a")?.notBeforeISO, "2026-07-29T08:00:00.000Z");

  // Mutating the object that was stored must not reach inside either.
  entry.notBeforeISO = "1970-01-01T00:00:00.000Z";
  assert.equal(cache.get("cluster-a")?.notBeforeISO, "2026-07-29T08:00:00.000Z");
});

test("isCacheEntry accepts a well-formed entry and rejects everything else", () => {
  assert.equal(isCacheEntry(priorEntry(AT)), true);
  for (const bad of [undefined, null, 42, "x", {}, { fingerprintSha256Hex: 1 }]) {
    assert.equal(isCacheEntry(bad), false, `should reject ${JSON.stringify(bad)}`);
  }
});
