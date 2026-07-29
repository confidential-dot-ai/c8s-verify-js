import { test } from "node:test";
import assert from "node:assert/strict";

import { decodePEM } from "../src/pem.js";
import { parseCertificate, verifyCertChain, verifySignedBy } from "../src/x509.js";
import { C8sVerifyError } from "../src/errors.js";
import { loadFixtures } from "./helpers.js";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

test("parses the demo mesh CA and leaf certs", async () => {
  const { meshCaPem, leafPem } = await loadFixtures();
  const ca = parseCertificate(decodePEM(meshCaPem)[0]);
  const leaf = parseCertificate(decodePEM(leafPem)[0]);
  assert.equal(ca.subjectCN, "c8s-demo-mesh-ca");
  assert.equal(ca.spkiCurve, "P-384");
  assert.equal(leaf.subjectCN, "lb.demo.c8s.local");
  assert.equal(leaf.issuerCN, "c8s-demo-mesh-ca");
  assert.equal(leaf.spkiCurve, "P-256");
});

test("verifies the leaf chains to the mesh CA", async () => {
  const { meshCaPem, leafPem } = await loadFixtures();
  const { leaf, ca, leafSha256, caSha256 } = await verifyCertChain(
    decodePEM(leafPem)[0],
    decodePEM(meshCaPem)[0],
  );
  assert.equal(leaf.subjectCN, "lb.demo.c8s.local");
  assert.equal(ca.subjectCN, "c8s-demo-mesh-ca");
  assert.match(leafSha256, /^[0-9a-f]{64}$/);
  assert.match(caSha256, /^[0-9a-f]{64}$/);
});

test("rejects a tampered leaf signature", async () => {
  const { meshCaPem, leafPem } = await loadFixtures();
  const leafDer = decodePEM(leafPem)[0].slice();
  leafDer[leafDer.length - 1] ^= 0x01; // mangle last signature byte
  await assert.rejects(
    () => verifyCertChain(leafDer, decodePEM(meshCaPem)[0]),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "cert_chain",
  );
});

test("rejects a leaf not signed by the given CA (self as issuer)", async () => {
  const { leafPem } = await loadFixtures();
  const leaf = parseCertificate(decodePEM(leafPem)[0]);
  // The leaf is P-256 but not self-signed; verifying it against itself must fail.
  await assert.rejects(
    () => verifySignedBy(leaf, leaf),
    (e: unknown) => e instanceof C8sVerifyError,
  );
});

test("rejects an expired certificate", async () => {
  const { meshCaPem, leafPem } = await loadFixtures();
  await assert.rejects(
    () =>
      verifyCertChain(decodePEM(leafPem)[0], decodePEM(meshCaPem)[0], {
        at: new Date("2999-01-01"),
      }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_cert",
  );
});

test("verifies a self-signed CA against itself", async () => {
  const { meshCaPem } = await loadFixtures();
  const caDer = decodePEM(meshCaPem)[0];
  await assert.doesNotReject(() => verifyCertChain(caDer, caDer));
});

// ---------------------------------------------------------------------------
// Extension parsing
// ---------------------------------------------------------------------------
//
// These bytes are what the RA-TLS attestation binds: REPORTDATA folds the
// config-claims extnValue in verbatim. So a certificate that two parsers read
// differently is a certificate where the value the quote committed to and the
// value a verifier enforces can diverge. Everything ambiguous is refused rather
// than resolved, and each case below was accepted before.

/** Minimal DER builders — just enough to shape a certificate for the parser. */
const T = (tag: number, ...content: (number[] | Uint8Array)[]): number[] => {
  const body = content.flatMap((c) => Array.from(c));
  const len = body.length;
  const hdr = len < 0x80 ? [len] : len < 0x100 ? [0x81, len] : [0x82, len >> 8, len & 0xff];
  return [tag, ...hdr, ...body];
};
const SEQ = (...c: (number[] | Uint8Array)[]): number[] => T(0x30, ...c);
const INT = (n: number): number[] => T(0x02, [n]);
const OCT = (b: number[]): number[] => T(0x04, b);
const UTC = (s: string): number[] => T(0x17, Array.from(new TextEncoder().encode(s)));
/** 1.3.6.1.4.1.59888.1.3 — the config-claims OID. */
const OID_CLAIMS = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xd3, 0x70, 0x01, 0x03];
const CLAIMS_OID_STR = "1.3.6.1.4.1.59888.1.3";

/** Assemble a certificate whose tbsCertificate carries the given trailing fields. */
function synthCert(...trailing: number[][]): Uint8Array {
  const name = SEQ();
  const validity = SEQ(UTC("260101000000Z"), UTC("270101000000Z"));
  const spki = SEQ(SEQ(T(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])), T(0x03, [0x00, 0x04]));
  const tbs = SEQ(T(0xa0, INT(2)), INT(1), SEQ(), name, validity, name, spki, ...trailing);
  return new Uint8Array(SEQ(tbs, SEQ(), T(0x03, [0x00, 0x30, 0x00])));
}

const extBlock = (...exts: number[][]): number[] => T(0xa3, SEQ(...exts));

test("parses extensions located by their [3] tag, not by position", () => {
  // issuerUniqueID [1] present: the extensions must still be found, not shifted
  // out of view and silently read as absent.
  const cert = parseCertificate(synthCert(T(0xa1, [0x00]), extBlock(SEQ(OID_CLAIMS, OCT([0xcc])))));
  assert.deepEqual(cert.extensions.get(CLAIMS_OID_STR), Uint8Array.of(0xcc));
});

test("parses an extension carrying an explicit critical BOOLEAN", () => {
  const cert = parseCertificate(synthCert(extBlock(SEQ(OID_CLAIMS, T(0x01, [0xff]), OCT([0xcc])))));
  assert.deepEqual(cert.extensions.get(CLAIMS_OID_STR), Uint8Array.of(0xcc));
});

// Taking the first [3] silently discarded the second, so a certificate could
// carry two different config-claims values and have only one of them enforced.
test("rejects a certificate carrying two [3] extension blocks", () => {
  assert.throws(
    () =>
      parseCertificate(
        synthCert(extBlock(SEQ(OID_CLAIMS, OCT([0xaa]))), extBlock(SEQ(OID_CLAIMS, OCT([0xbb])))),
      ),
    /2 extensions blocks; exactly one \[3\] is permitted/,
  );
});

// "The last element" accepted {OID, OCTET STRING, NULL, OCTET STRING} and picked
// the decoy — an arity a strict parser rejects outright.
test("rejects an extension SEQUENCE with more than three elements", () => {
  assert.throws(
    () => parseCertificate(synthCert(extBlock(SEQ(OID_CLAIMS, OCT([0xaa]), T(0x05), OCT([0xbb]))))),
    /has 4 elements, expected 2 or 3/,
  );
});

test("rejects a three-element extension whose middle element is not the critical BOOLEAN", () => {
  assert.throws(
    () => parseCertificate(synthCert(extBlock(SEQ(OID_CLAIMS, OCT([0xaa]), OCT([0xbb]))))),
    /middle element is not the critical BOOLEAN/,
  );
});

// The [3] wrapper is EXPLICIT and holds exactly one SEQUENCE OF Extension. Two
// SEQUENCEs inside it is the same smuggling trick one level down: a second set
// of extensions that a lenient reader would drop on the floor.
test("rejects a [3] block holding more than one SEQUENCE", () => {
  assert.throws(
    () =>
      parseCertificate(
        synthCert(T(0xa3, SEQ(SEQ(OID_CLAIMS, OCT([0xaa]))), SEQ(SEQ(OID_CLAIMS, OCT([0xbb]))))),
      ),
    /must hold exactly one SEQUENCE/,
  );
});

test("rejects a duplicate extension OID rather than picking one copy", () => {
  assert.throws(
    () =>
      parseCertificate(
        synthCert(extBlock(SEQ(OID_CLAIMS, OCT([0xaa])), SEQ(OID_CLAIMS, OCT([0xbb])))),
      ),
    new RegExp(`carries extension ${CLAIMS_OID_STR.replace(/\./g, "\\.")} more than once`),
  );
});

test("the live CDS certificate still parses with the stricter rules", async () => {
  const pem = await readFile(
    join(dirname(fileURLToPath(import.meta.url)), "fixtures", "cds-identity.pem"),
    "utf8",
  );
  const cert = parseCertificate(decodePEM(pem)[0]);
  assert.ok(cert.extensions.get(CLAIMS_OID_STR), "config-claims extension went missing");
  assert.ok(cert.extensions.get("1.3.6.1.4.1.59888.1.1"), "attestation extension went missing");
  // Real certificates carry critical BOOLEANs on some extensions — the 3-element
  // form must keep working, which is what makes this fixture the calibration.
  assert.ok(cert.extensions.size >= 5);
});
