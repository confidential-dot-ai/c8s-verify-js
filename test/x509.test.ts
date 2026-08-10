import { test } from "node:test";
import assert from "node:assert/strict";

import { decodePEM } from "../src/pem.js";
import {
  LEAF_VALIDITY_SKEW_MS,
  parseCertificate,
  verifyCertChain,
  verifyECDSASignature,
  verifySignedBy,
} from "../src/x509.js";
import { C8sVerifyError } from "../src/errors.js";
import { OID_MATCHED_WORKLOAD } from "../src/workload.js";
import { loadFixtures } from "./helpers.js";
import {
  OID_15_DER,
  basicConstraintsExt,
  keyUsageExt,
  mintLeaf,
  mintSelfSigned,
  nameDer,
} from "./mint-cert.js";
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

// The self-signature of the P-384 fixture CA still verifies — that is the
// primitive the chain check is built on — but it is checked directly, because
// running it *through* the chain check is precisely the forgery below.
test("the self-signed CA's own signature verifies under its own key", async () => {
  const { meshCaPem } = await loadFixtures();
  const ca = parseCertificate(decodePEM(meshCaPem)[0]);
  assert.ok(await verifyECDSASignature(ca, ca.tbs, ca.signatureDER, "SHA-384"));
});

// ---------------------------------------------------------------------------
// Issuer constraints: a signature is not a chain
// ---------------------------------------------------------------------------
//
// The responder chooses every byte of the served certificate bundle, and the
// mesh leaf's matched-workload stamp is enforced off whatever leaf survives
// this check. Each case below verified fine when the only questions asked were
// "is it in date" and "does the signature check out", and each hands a
// responder a certificate whose extensions it wrote itself. Go's
// CheckSignatureFrom/Verify refuse all three, which is why the server never
// had the hole.

test("rejects a certificate presented as its own CA", async () => {
  // A self-signed certificate that says cA=TRUE: every remaining check passes,
  // so only the leaf≠CA rule stands between a responder and a leaf that vouches
  // for its own stamp.
  const { leafDer } = mintSelfSigned({
    subjectCN: "self.forged.c8s.local",
    extensions: [basicConstraintsExt(true), keyUsageExt(true)],
  });
  await assert.rejects(
    () => verifyCertChain(leafDer, leafDer),
    (e: unknown) =>
      e instanceof C8sVerifyError &&
      e.code === "cert_chain" &&
      e.message.includes("cannot vouch for itself"),
  );
});

test("rejects a leaf issued by a certificate that is not a CA", async () => {
  for (const [label, caExts] of [
    ["cA=FALSE", [basicConstraintsExt(false)]],
    ["no basicConstraints at all", []],
    ["cA=TRUE but keyUsage without keyCertSign", [basicConstraintsExt(true), keyUsageExt(false)]],
  ] as const) {
    const ca = mintSelfSigned({ subjectCN: "not-a-ca.c8s.local", extensions: [...caExts] });
    const { leafDer } = mintLeaf(ca.leafDer, ca.leafKeyPem);
    await assert.rejects(
      () => verifyCertChain(leafDer, ca.leafDer),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "cert_chain",
      `an issuer with ${label} must not be accepted as a CA`,
    );
  }
});

test("rejects a leaf whose issuer name is not the CA's subject name", async () => {
  const ca = mintSelfSigned({
    subjectCN: "real-ca.c8s.local",
    extensions: [basicConstraintsExt(true), keyUsageExt(true)],
  });
  // Signed by the CA's key, so the signature verifies; only the name lies.
  const { leafDer } = mintLeaf(ca.leafDer, ca.leafKeyPem, {
    issuerDer: new Uint8Array(nameDer("other-ca.c8s.local")),
  });
  await assert.rejects(
    () => verifyCertChain(leafDer, ca.leafDer),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "cert_chain",
  );
});

test("a leaf minted by a well-formed CA still verifies", async () => {
  const ca = mintSelfSigned({
    subjectCN: "real-ca.c8s.local",
    extensions: [basicConstraintsExt(true), keyUsageExt(true)],
  });
  const { leafDer } = mintLeaf(ca.leafDer, ca.leafKeyPem);
  const chain = await verifyCertChain(leafDer, ca.leafDer);
  assert.equal(chain.ca.subjectCN, "real-ca.c8s.local");
});

// ---------------------------------------------------------------------------
// Validity window: certutil.LeafValiditySkew on NotBefore, nothing on NotAfter
// ---------------------------------------------------------------------------
//
// CDS mints mesh leaves with NotBefore = now and no backdating, and re-reads
// them per request so a get-cert rotation is picked up mid-flight. A browser
// whose clock trails the issuing TEE therefore sees a NotBefore in its own
// future for a leaf the server considers perfectly valid. The allowance is
// pinned from both sides, the way the server's TestCheckValidity pins it.

const MINUTE = 60_000;

/** A CA and a leaf minted with the given validity window, ready to chain. */
function chainWithValidity(notBefore: Date, notAfter: Date): [Uint8Array, Uint8Array] {
  const ca = mintSelfSigned({
    subjectCN: "skew-ca.c8s.local",
    extensions: [basicConstraintsExt(true), keyUsageExt(true)],
    notBefore,
    notAfter,
  });
  const { leafDer } = mintLeaf(ca.leafDer, ca.leafKeyPem, { notBefore, notAfter });
  return [leafDer, ca.leafDer];
}

test("accepts a NotBefore inside the 5-minute clock-skew allowance", async () => {
  const at = new Date(Math.floor(Date.now() / 1000) * 1000);
  const [leaf, ca] = chainWithValidity(
    new Date(at.getTime() + LEAF_VALIDITY_SKEW_MS - MINUTE),
    new Date(at.getTime() + 60 * MINUTE),
  );
  await assert.doesNotReject(() => verifyCertChain(leaf, ca, { at }));
});

test("rejects a NotBefore one second beyond the allowance", async () => {
  const at = new Date(Math.floor(Date.now() / 1000) * 1000);
  const [leaf, ca] = chainWithValidity(
    new Date(at.getTime() + LEAF_VALIDITY_SKEW_MS + 1000),
    new Date(at.getTime() + 60 * MINUTE),
  );
  await assert.rejects(
    () => verifyCertChain(leaf, ca, { at }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_cert",
  );
});

test("grants NotAfter no allowance at all: one second past is expired", async () => {
  const at = new Date(Math.floor(Date.now() / 1000) * 1000);
  const [leaf, ca] = chainWithValidity(
    new Date(at.getTime() - 60 * MINUTE),
    new Date(at.getTime() - 1000),
  );
  await assert.rejects(
    () => verifyCertChain(leaf, ca, { at }),
    (e: unknown) =>
      e instanceof C8sVerifyError && e.code === "invalid_cert" && e.message.includes("expired"),
  );
  // The same certificate one second earlier is still good, so the rejection is
  // the boundary and not a blanket refusal.
  const [leaf2, ca2] = chainWithValidity(
    new Date(at.getTime() - 60 * MINUTE),
    new Date(at.getTime()),
  );
  await assert.doesNotReject(() => verifyCertChain(leaf2, ca2, { at }));
});

// ---------------------------------------------------------------------------
// Extension parsing
// ---------------------------------------------------------------------------
//
// These bytes are what a verifier enforces: the matched-workload stamp is
// decoded from the extnValue verbatim, and the RA-TLS attestation extension is
// the value the quote's REPORTDATA commits to. So a certificate that two
// parsers read differently is a certificate where the value the CA vouched for
// and the value a verifier enforces can diverge. Everything ambiguous is
// refused rather than resolved, and each case below was accepted before.

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
// The extension these cases are shaped around is the live one: the
// matched-workload stamp on the 1.3.6.1.4.1.66378 arc (c8s's registered PEN).
// The DER form comes from mint-cert.ts's independent encoder and the dotted
// form from the shipped constant, so the two can never drift apart unnoticed.
const OID_MW_DER = OID_15_DER;
const MW_OID_STR = OID_MATCHED_WORKLOAD;

/** Assemble a certificate whose tbsCertificate carries the given trailing fields. */
function synthCert(...trailing: number[][]): Uint8Array {
  const name = SEQ();
  const validity = SEQ(UTC("260101000000Z"), UTC("270101000000Z"));
  const spki = SEQ(SEQ(T(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])), T(0x03, [0x00, 0x04]));
  const tbs = SEQ(T(0xa0, INT(2)), INT(1), SEQ(), name, validity, name, spki, ...trailing);
  return new Uint8Array(SEQ(tbs, SEQ(), T(0x03, [0x00, 0x30, 0x00])));
}

const extBlock = (...exts: number[][]): number[] => T(0xa3, SEQ(...exts));

test("the shipped matched-workload OID is what the DER encoding decodes to", () => {
  const cert = parseCertificate(synthCert(extBlock(SEQ(OID_MW_DER, OCT([0xcc])))));
  assert.deepEqual([...cert.extensions.keys()], [MW_OID_STR]);
  assert.equal(MW_OID_STR, "1.3.6.1.4.1.66378.1.5");
});

test("parses extensions located by their [3] tag, not by position", () => {
  // issuerUniqueID [1] present: the extensions must still be found, not shifted
  // out of view and silently read as absent.
  const cert = parseCertificate(synthCert(T(0xa1, [0x00]), extBlock(SEQ(OID_MW_DER, OCT([0xcc])))));
  assert.deepEqual(cert.extensions.get(MW_OID_STR), Uint8Array.of(0xcc));
});

test("parses an extension carrying an explicit critical BOOLEAN", () => {
  const cert = parseCertificate(synthCert(extBlock(SEQ(OID_MW_DER, T(0x01, [0xff]), OCT([0xcc])))));
  assert.deepEqual(cert.extensions.get(MW_OID_STR), Uint8Array.of(0xcc));
});

// Taking the first [3] silently discarded the second, so a certificate could
// carry two different stamps and have only one of them enforced.
test("rejects a certificate carrying two [3] extension blocks", () => {
  assert.throws(
    () =>
      parseCertificate(
        synthCert(extBlock(SEQ(OID_MW_DER, OCT([0xaa]))), extBlock(SEQ(OID_MW_DER, OCT([0xbb])))),
      ),
    /2 extensions blocks; exactly one \[3\] is permitted/,
  );
});

// "The last element" accepted {OID, OCTET STRING, NULL, OCTET STRING} and picked
// the decoy — an arity a strict parser rejects outright.
test("rejects an extension SEQUENCE with more than three elements", () => {
  assert.throws(
    () => parseCertificate(synthCert(extBlock(SEQ(OID_MW_DER, OCT([0xaa]), T(0x05), OCT([0xbb]))))),
    /has 4 elements, expected 2 or 3/,
  );
});

test("rejects a three-element extension whose middle element is not the critical BOOLEAN", () => {
  assert.throws(
    () => parseCertificate(synthCert(extBlock(SEQ(OID_MW_DER, OCT([0xaa]), OCT([0xbb]))))),
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
        synthCert(T(0xa3, SEQ(SEQ(OID_MW_DER, OCT([0xaa]))), SEQ(SEQ(OID_MW_DER, OCT([0xbb]))))),
      ),
    /must hold exactly one SEQUENCE/,
  );
});

test("rejects a duplicate extension OID rather than picking one copy", () => {
  assert.throws(
    () =>
      parseCertificate(
        synthCert(extBlock(SEQ(OID_MW_DER, OCT([0xaa])), SEQ(OID_MW_DER, OCT([0xbb])))),
      ),
    new RegExp(`carries extension ${MW_OID_STR.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} more than once`),
  );
});

// A recorded RA-TLS certificate off real hardware: multi-kilobyte extnValues,
// critical BOOLEANs, a long-form length at every level. It is a *shape*
// calibration only — it was minted before c8s moved to its registered PEN, so
// its private-arc OIDs are not a drift anchor for the live arc (that is what
// the matched-workload cases above pin). What must hold for any certificate,
// whatever it carries, is that the parser survives the real shapes and hands
// back extnValues byte-for-byte as they appear in the DER it read.
test("a recorded RA-TLS certificate still parses with the stricter rules", async () => {
  const der = decodePEM(
    await readFile(
      join(dirname(fileURLToPath(import.meta.url)), "fixtures", "ratls-cert.pem"),
      "utf8",
    ),
  )[0];
  const cert = parseCertificate(der);
  assert.ok(cert.extensions.size >= 5);
  // Critical extensions use the 3-element form; keyUsage and basicConstraints
  // are critical on every c8s leaf, so both must have come through.
  assert.ok(cert.extensions.get("2.5.29.15"), "keyUsage went missing");
  assert.ok(cert.extensions.get("2.5.29.19"), "basicConstraints went missing");
  // Verbatim, not re-encoded: every value handed out is a slice of the input.
  const haystack = Buffer.from(der);
  for (const [oid, value] of cert.extensions) {
    assert.ok(haystack.includes(Buffer.from(value)), `extnValue for ${oid} is not verbatim`);
  }
});
