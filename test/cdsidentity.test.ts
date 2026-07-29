import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  attestCDSIdentity,
  cdsIdentityPEM,
  hasDigest,
  parseConfigClaims,
  verifyAllowlist,
  verifyMeshCA,
  type CDSIdentity,
} from "../src/cdsidentity.js";
import { C8sVerifyError } from "../src/errors.js";
import { decodePEM } from "../src/pem.js";
import { bytesToHex } from "../src/base64.js";

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

async function attested(): Promise<CDSIdentity> {
  return attestCDSIdentity(await cdsIdentity(), { measurements: [MRTD] });
}

test("attests a live CDS certificate and returns its claims", async () => {
  const id = await attested();
  assert.equal(id.launchDigest, MRTD);
  assert.equal(id.claims.version, 3);
  assert.ok(hasDigest(id.claims.meshCaDigest), "no mesh-CA digest in attested claims");
  assert.ok(hasDigest(id.claims.allowlistDigest), "no live-allowlist digest in attested claims");
  assert.match(id.fingerprint, /^[0-9a-f]{64}$/);
});

test("binds REPORTDATA to the certificate key AND its claims", async () => {
  // Nothing else in this suite proves the transcript is right: the framing is
  // reimplemented here from c8s pkg/ratls, and a wrong domain separator or
  // length prefix would make every verification fail. That it succeeds against
  // a real quote is the proof it matches byte for byte.
  const id = await attested();
  assert.ok(id.launchDigest.length > 0);
});

test("rejects a certificate outside the measurement policy", async () => {
  await assert.rejects(
    attestCDSIdentity(await cdsIdentity(), { measurements: ["ab".repeat(48)] }),
    (err: unknown) => {
      assert.ok(err instanceof C8sVerifyError);
      assert.equal(err.code, "cds_identity_denied");
      return true;
    },
  );
});

test("rejects a mismatched RTMR[3]: genuine TEE, wrong deployment", async () => {
  await assert.rejects(
    attestCDSIdentity(await cdsIdentity(), {
      measurements: [MRTD],
      expectedRtmr3: "11".repeat(48),
    }),
    (err: unknown) => {
      assert.ok(err instanceof C8sVerifyError);
      assert.equal(err.code, "cds_identity_denied");
      return true;
    },
  );
});

test("accepts the matching RTMR[3]", async () => {
  const id = await attestCDSIdentity(await cdsIdentity(), {
    measurements: [MRTD],
    expectedRtmr3: RTMR3,
  });
  assert.equal(id.launchDigest, MRTD);
});

test("rejects a tampered certificate — this is what makes relaying it safe", async () => {
  const pem = await cdsIdentity();
  const der = decodePEM(pem)[0];
  const edited = Uint8Array.from(der);
  edited[Math.floor(edited.length / 2)] ^= 0xff;
  await assert.rejects(attestCDSIdentity(edited, { measurements: [MRTD] }));
});

test("derives the mesh CA, and refuses any other CA", async () => {
  const id = await attested();
  await verifyMeshCA(id, await meshCA());

  // The CDS certificate itself is a certificate, but not THE mesh CA.
  const notTheCA = decodePEM(await cdsIdentity())[0];
  await assert.rejects(verifyMeshCA(id, notTheCA), (err: unknown) => {
    assert.ok(err instanceof C8sVerifyError);
    assert.equal(err.code, "mesh_ca_denied");
    return true;
  });
});

test("verifies the served allowlist, and catches a single extra byte", async () => {
  const id = await attested();
  const raw = new Uint8Array(await allowlistBytes());
  await verifyAllowlist(id, raw);

  // The trailing-newline mistake: semantically identical, different bytes.
  const plusNewline = new Uint8Array(raw.length + 1);
  plusNewline.set(raw);
  plusNewline[raw.length] = 0x0a;
  await assert.rejects(verifyAllowlist(id, plusNewline), (err: unknown) => {
    assert.ok(err instanceof C8sVerifyError);
    assert.equal(err.code, "allowlist_denied");
    return true;
  });
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
  await assert.rejects(verifyAllowlist(id, reserialized));
});

test("claims that predate a field cannot satisfy a request for it", async () => {
  const v1: CDSIdentity = {
    fingerprint: "0".repeat(64),
    launchDigest: MRTD,
    notAfter: new Date(),
    claims: {
      version: 1,
      operatorKeysDigest: new Uint8Array(32),
      seedDigest: new Uint8Array(32),
      workloadDigest: new Uint8Array(32),
      meshCaDigest: new Uint8Array(32),
      allowlistDigest: new Uint8Array(32),
    },
  };
  await assert.rejects(verifyMeshCA(v1, await meshCA()), (err: unknown) => {
    assert.ok(err instanceof C8sVerifyError);
    assert.equal(err.code, "mesh_ca_not_attested");
    return true;
  });
  await assert.rejects(
    verifyAllowlist(v1, new Uint8Array(await allowlistBytes())),
    (err: unknown) => {
      assert.ok(err instanceof C8sVerifyError);
      assert.equal(err.code, "allowlist_not_attested");
      return true;
    },
  );
});

test("a discovery document without cds_identity is an explicit failure", () => {
  assert.throws(
    () => cdsIdentityPEM({}),
    (err: unknown) => {
      assert.ok(err instanceof C8sVerifyError);
      assert.equal(err.code, "cds_identity_missing");
      return true;
    },
  );
});

test("rejects an unsupported claims version rather than ignoring the claims", () => {
  // SEQUENCE { INTEGER 9, ... } — a future version this build cannot read.
  const der = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x09]);
  assert.throws(
    () => parseConfigClaims(der),
    (err: unknown) => {
      assert.ok(err instanceof C8sVerifyError);
      assert.equal(err.code, "unsupported");
      return true;
    },
  );
});
