// Minimal X.509 certificate parsing + chain verification, sufficient for the c8s
// trust model: parse the served CDS/mesh-CA cert, check its validity window, and
// verify that a leaf certificate's signature was produced by the CA's key
// (ECDSA P-256/P-384 with SHA-256/384). Pure WebCrypto + the tiny DER reader.

import { subtle } from "./crypto-env.js";
import { readTLV, readChildren, decodeOID, decodeTime, TAG, type DERNode } from "./asn1.js";
import { bytesToHex, constantTimeEqual } from "./base64.js";
import { C8sVerifyError } from "./errors.js";

const OID = {
  CN: "2.5.4.3",
  EC_PUBLIC_KEY: "1.2.840.10045.2.1",
  P256: "1.2.840.10045.3.1.7",
  P384: "1.3.132.0.34",
  ECDSA_SHA256: "1.2.840.10045.4.3.2",
  ECDSA_SHA384: "1.2.840.10045.4.3.3",
  BASIC_CONSTRAINTS: "2.5.29.19",
  KEY_USAGE: "2.5.29.15",
} as const;

/**
 * keyCertSign is KeyUsage bit 5, i.e. the sixth-most-significant bit of the
 * BIT STRING's first content byte.
 */
const KEY_USAGE_CERT_SIGN = 0x04;

/**
 * Clock-skew allowance granted to NotBefore, mirroring c8s's
 * `certutil.LeafValiditySkew`. CDS mints mesh leaves with `NotBefore: now` and
 * no backdating, and re-reads them per request so a rotation is picked up
 * mid-flight — so a browser whose clock trails the issuing TEE by a moment
 * would otherwise reject a perfectly fresh leaf. NotAfter gets NO allowance:
 * an expired certificate is expired, and these bundles carry no nonce of their
 * own, so the validity window is the only bound on replaying one.
 */
export const LEAF_VALIDITY_SKEW_MS = 5 * 60 * 1000;

const CURVE_BY_OID: Record<string, string> = { [OID.P256]: "P-256", [OID.P384]: "P-384" };
const CURVE_SIZE: Record<string, number> = { "P-256": 32, "P-384": 48 };
const SIG_ALG: Record<string, "SHA-256" | "SHA-384"> = {
  [OID.ECDSA_SHA256]: "SHA-256",
  [OID.ECDSA_SHA384]: "SHA-384",
};

export interface Certificate {
  der: Uint8Array;
  tbs: Uint8Array;
  serialHex: string;
  notBefore: Date;
  notAfter: Date;
  subjectCN: string | null;
  issuerCN: string | null;
  /**
   * Verbatim DER of the issuer and subject Name elements. Chaining compares
   * these bytes, not the decoded CNs: a Name is a structure, and two different
   * structures can share a CN (or carry none at all, as the c8s mesh leaf
   * does), so anything short of byte equality lets a leaf claim an issuer it
   * does not have.
   */
  rawIssuer: Uint8Array;
  rawSubject: Uint8Array;
  spki: Uint8Array;
  spkiCurve: string | null;
  sigAlgOID: string;
  signatureDER: Uint8Array;
  /**
   * Extension values by OID, as the raw extnValue OCTET STRING contents.
   *
   * Kept raw and unparsed on purpose: what a verifier enforces has to be the
   * exact bytes the issuer signed — the matched-workload stamp is decoded from
   * this DER verbatim, and the RA-TLS attestation extension is the value the
   * quote's REPORTDATA commits to. Anything that re-encodes before comparing or
   * hashing would compute a different value for the same certificate.
   */
  extensions: Map<string, Uint8Array>;
}

export interface ChainResult {
  leaf: Certificate;
  ca: Certificate;
  leafSha256: string;
  caSha256: string;
}

/** Pull the CN string out of a Name SEQUENCE node. */
function nameCN(buf: Uint8Array, nameNode: DERNode): string | null {
  for (const rdn of readChildren(buf, nameNode)) {
    if (rdn.tag !== TAG.SET) continue;
    for (const atv of readChildren(buf, rdn)) {
      const parts = readChildren(buf, atv);
      if (
        parts.length === 2 &&
        parts[0].tag === TAG.OID &&
        decodeOID(parts[0].content) === OID.CN
      ) {
        return new TextDecoder().decode(parts[1].content);
      }
    }
  }
  return null;
}

/**
 * Parse a DER-encoded X.509 certificate.
 */
export function parseCertificate(der: Uint8Array): Certificate {
  const cert = readTLV(der, 0);
  if (cert.tag !== TAG.SEQUENCE) {
    throw new C8sVerifyError("invalid_cert", "certificate is not a SEQUENCE");
  }
  const [tbs, sigAlg, sigValue] = readChildren(der, cert);
  if (!tbs || !sigAlg || !sigValue) {
    throw new C8sVerifyError("invalid_cert", "certificate missing top-level fields");
  }

  const tbsChildren = readChildren(der, tbs);
  let i = 0;
  // Optional [0] EXPLICIT version (context-constructed tag 0xA0).
  if (tbsChildren[i]?.tag === 0xa0) i++;
  const serial = tbsChildren[i++];
  i++; // inner signature AlgorithmIdentifier (ignored; outer is authoritative)
  const issuer = tbsChildren[i++];
  const validity = tbsChildren[i++];
  const subject = tbsChildren[i++];
  const spkiNode = tbsChildren[i++];
  if (!serial || !issuer || !validity || !subject || !spkiNode) {
    throw new C8sVerifyError("invalid_cert", "malformed tbsCertificate");
  }

  const [notBeforeNode, notAfterNode] = readChildren(der, validity);
  const notBefore = decodeTime(notBeforeNode);
  const notAfter = decodeTime(notAfterNode);

  // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier { algOID, [curveOID] }, BIT STRING }
  const spkiChildren = readChildren(der, spkiNode);
  let spkiCurve: string | null = null;
  if (spkiChildren[0]?.tag === TAG.SEQUENCE) {
    const algParts = readChildren(der, spkiChildren[0]);
    if (algParts[1]?.tag === TAG.OID) {
      spkiCurve = CURVE_BY_OID[decodeOID(algParts[1].content)] ?? null;
    }
  }

  // Outer signatureAlgorithm OID + signatureValue (BIT STRING: skip unused-bits byte).
  const sigAlgParts = readChildren(der, sigAlg);
  const sigAlgOID = sigAlgParts[0] ? decodeOID(sigAlgParts[0].content) : "";
  if (sigValue.tag !== TAG.BIT_STRING) {
    throw new C8sVerifyError("invalid_cert", "signatureValue is not a BIT STRING");
  }
  const signatureDER = sigValue.content.subarray(1);

  return {
    der,
    extensions: parseExtensions(der, tbsChildren.slice(i)),
    tbs: tbs.bytes,
    serialHex: bytesToHex(serial.content),
    notBefore,
    notAfter,
    subjectCN: nameCN(der, subject),
    issuerCN: nameCN(der, issuer),
    rawIssuer: issuer.bytes,
    rawSubject: subject.bytes,
    spki: spkiNode.bytes,
    spkiCurve,
    sigAlgOID,
    signatureDER,
  };
}

/**
 * Collect X.509 v3 extensions from the tbsCertificate fields that follow
 * subjectPublicKeyInfo.
 *
 * Those trailing fields are the optional issuerUniqueID [1], subjectUniqueID
 * [2] and extensions [3] EXPLICIT, so the block is located by its context tag
 * rather than by position — a certificate carrying a uniqueID would otherwise
 * shift it and the extensions would silently read as absent.
 *
 * Anything ambiguous is rejected rather than resolved, because these bytes are
 * what the RA-TLS attestation binds — a certificate that can be read two ways
 * is a certificate where the value the quote committed to and the value a
 * verifier enforces may differ:
 *
 *   - a duplicate OID, which X.509 forbids and which would otherwise let one
 *     certificate carry two values for one extension;
 *   - more than one [3] block, or a [3] holding more than one SEQUENCE, where
 *     taking the first silently discards a second set of extensions that a
 *     stricter parser would have seen;
 *   - an Extension SEQUENCE that is not exactly {extnID, extnValue} or
 *     {extnID, critical, extnValue}. Reading "the last element" instead of
 *     validating the shape accepted {OID, OCTET STRING, NULL, OCTET STRING}
 *     and picked the decoy — an arity the Go parser rejects outright.
 */
function parseExtensions(der: Uint8Array, trailing: DERNode[]): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  const blocks = trailing.filter((n) => n.tag === 0xa3);
  if (blocks.length > 1) {
    throw new C8sVerifyError(
      "invalid_cert",
      `certificate carries ${blocks.length} extensions blocks; exactly one [3] is permitted`,
    );
  }
  const block = blocks[0];
  if (!block) return out;

  const blockChildren = readChildren(der, block);
  if (blockChildren.length !== 1) {
    throw new C8sVerifyError("invalid_cert", "extensions [3] block must hold exactly one SEQUENCE");
  }
  const seq = blockChildren[0];
  if (seq.tag !== TAG.SEQUENCE) {
    throw new C8sVerifyError("invalid_cert", "extensions block is not a SEQUENCE");
  }

  for (const ext of readChildren(der, seq)) {
    const parts = readChildren(der, ext);
    // Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER,
    //                          critical BOOLEAN DEFAULT FALSE,
    //                          extnValue OCTET STRING }
    if (parts.length !== 2 && parts.length !== 3) {
      throw new C8sVerifyError(
        "invalid_cert",
        `certificate extension has ${parts.length} elements, expected 2 or 3`,
      );
    }
    const oidNode = parts[0];
    const valueNode = parts[parts.length - 1];
    if (oidNode.tag !== TAG.OID || valueNode.tag !== TAG.OCTET_STRING) {
      throw new C8sVerifyError("invalid_cert", "malformed certificate extension");
    }
    if (parts.length === 3 && parts[1].tag !== TAG.BOOLEAN) {
      throw new C8sVerifyError(
        "invalid_cert",
        "certificate extension's middle element is not the critical BOOLEAN",
      );
    }
    const oid = decodeOID(oidNode.content);
    if (out.has(oid)) {
      throw new C8sVerifyError(
        "invalid_cert",
        `certificate carries extension ${oid} more than once`,
      );
    }
    out.set(oid, valueNode.content);
  }
  return out;
}

/**
 * Convert a DER ECDSA signature (SEQUENCE{r,s}) to raw r||s for WebCrypto.
 * Strict content rules: the SEQUENCE must span the whole buffer and hold
 * exactly two positive INTEGERs without redundant sign padding. (Length
 * octets are bounds-checked by the DER reader but not checked for
 * minimality, so encoding uniqueness is not fully guaranteed.)
 * @param der DER signature
 * @param size curve component size in bytes
 */
function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array {
  const seq = readTLV(der, 0);
  if (seq.tag !== TAG.SEQUENCE || seq.end !== der.length) {
    throw new C8sVerifyError("invalid_cert", "malformed ECDSA signature");
  }
  const ints = readChildren(der, seq);
  if (ints.length !== 2 || ints.some((n) => n.tag !== TAG.INTEGER)) {
    throw new C8sVerifyError("invalid_cert", "malformed ECDSA signature");
  }
  const out = new Uint8Array(size * 2);
  const place = (int: Uint8Array, off: number): void => {
    let v = int;
    if (v.length === 0 || (v[0] & 0x80) !== 0) {
      throw new C8sVerifyError("invalid_cert", "ECDSA integer is empty or negative");
    }
    // A leading 0x00 is only valid DER when it clears a would-be sign bit.
    if (v[0] === 0x00 && v.length > 1) {
      if ((v[1] & 0x80) === 0) {
        throw new C8sVerifyError("invalid_cert", "non-minimal ECDSA integer encoding");
      }
      v = v.subarray(1);
    }
    if (v.length > size) throw new C8sVerifyError("invalid_cert", "ECDSA integer too large");
    out.set(v, off + (size - v.length));
  };
  place(ints[0].content, 0);
  place(ints[1].content, size);
  return out;
}

/** Verify an ASN.1 DER ECDSA signature with a certificate public key. */
export async function verifyECDSASignature(
  cert: Certificate,
  message: Uint8Array,
  signatureDER: Uint8Array,
  hash: "SHA-256" | "SHA-384",
): Promise<boolean> {
  const size = CURVE_SIZE[cert.spkiCurve ?? ""];
  if (!size) {
    throw new C8sVerifyError("invalid_cert", "unsupported EC curve for signature verification");
  }
  const key = await importPublicKey(cert);
  const signature = ecdsaDerToRaw(signatureDER, size);
  return subtle().verify({ name: "ECDSA", hash }, key, signature, message);
}

/**
 * Import a certificate's SubjectPublicKeyInfo as an ECDSA verify key.
 */
export async function importPublicKey(cert: Certificate): Promise<CryptoKey> {
  if (!cert.spkiCurve) {
    throw new C8sVerifyError("invalid_cert", "unsupported or missing EC curve in certificate");
  }
  return subtle().importKey(
    "spki",
    cert.spki,
    { name: "ECDSA", namedCurve: cert.spkiCurve },
    false,
    ["verify"],
  );
}

/**
 * SHA-256 fingerprint of a certificate (DER), as lowercase hex.
 */
export async function fingerprintSHA256(cert: Certificate | Uint8Array): Promise<string> {
  const der = cert instanceof Uint8Array ? cert : cert.der;
  const digest = await subtle().digest("SHA-256", der);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Whether a certificate asserts `basicConstraints` with `cA=TRUE`.
 *
 * Absent, malformed, or explicitly false all read as "not a CA" — `cA` is
 * DEFAULT FALSE, so an empty SEQUENCE (or one opening with the
 * pathLenConstraint INTEGER) says exactly that, and DER damage in an extension
 * this decision rests on must never resolve in the presenter's favour.
 */
function assertsCA(cert: Certificate): boolean {
  const value = cert.extensions.get(OID.BASIC_CONSTRAINTS);
  if (value === undefined) return false;
  try {
    const seq = readTLV(value, 0);
    if (seq.tag !== TAG.SEQUENCE || seq.end !== value.length) return false;
    const [ca] = readChildren(value, seq);
    return ca?.tag === TAG.BOOLEAN && ca.content.length === 1 && ca.content[0] !== 0x00;
  } catch {
    return false;
  }
}

/**
 * Whether a certificate's `keyUsage` permits signing certificates. An absent
 * extension is unconstrained (Go treats a zero KeyUsage the same way); a
 * present one must carry keyCertSign, and anything unreadable is refused.
 */
function permitsCertSign(cert: Certificate): boolean {
  const value = cert.extensions.get(OID.KEY_USAGE);
  if (value === undefined) return true;
  try {
    const bits = readTLV(value, 0);
    if (bits.tag !== TAG.BIT_STRING || bits.end !== value.length || bits.content.length < 2) {
      return false;
    }
    return (bits.content[1] & KEY_USAGE_CERT_SIGN) !== 0;
  } catch {
    return false;
  }
}

/**
 * Verify that `child` was signed by `issuer` (ECDSA), that `issuer` is a
 * certificate allowed to have signed it, and that both are within their
 * validity windows at `at`. Throws C8sVerifyError on any failure.
 *
 * A valid signature alone is not a chain. The responder chooses every byte of
 * the served certificate bundle, so without the issuer checks below "signed
 * by" degenerates to "some certificate signed this one": emitting one
 * self-signed certificate twice makes the leaf its own CA, and everything the
 * chain is meant to vouch for — the matched-workload stamp above all — becomes
 * attacker-chosen. Go's `CheckSignatureFrom` enforces the constraint half of
 * this and `Verify` the name half, which is why the c8s server has no such
 * hole; the rules are restated here rather than inherited.
 */
export async function verifySignedBy(
  child: Certificate,
  issuer: Certificate,
  opts: { at?: Date } = {},
): Promise<void> {
  const at = opts.at ?? new Date();

  for (const [label, c] of [
    ["leaf", child],
    ["CA", issuer],
  ] as const) {
    // NotBefore carries LEAF_VALIDITY_SKEW_MS of allowance, NotAfter none —
    // the exact window certutil.CheckValidity applies server-side.
    if (at.getTime() + LEAF_VALIDITY_SKEW_MS < c.notBefore.getTime()) {
      throw new C8sVerifyError(
        "invalid_cert",
        `${label} certificate is not yet valid: NotBefore is beyond the ${LEAF_VALIDITY_SKEW_MS / 60000}-minute clock-skew allowance`,
        { details: { notBefore: c.notBefore.toISOString() } },
      );
    }
    if (at.getTime() > c.notAfter.getTime()) {
      throw new C8sVerifyError("invalid_cert", `${label} certificate has expired`, {
        details: { notAfter: c.notAfter.toISOString() },
      });
    }
  }

  if (constantTimeEqual(child.der, issuer.der)) {
    throw new C8sVerifyError(
      "cert_chain",
      "leaf and CA are the same certificate: a certificate cannot vouch for itself",
    );
  }
  if (!assertsCA(issuer)) {
    throw new C8sVerifyError(
      "cert_chain",
      "CA certificate does not assert basicConstraints cA=TRUE, so it may not issue certificates",
    );
  }
  if (!permitsCertSign(issuer)) {
    throw new C8sVerifyError(
      "cert_chain",
      "CA certificate carries a keyUsage extension that does not permit keyCertSign",
    );
  }
  if (!constantTimeEqual(child.rawIssuer, issuer.rawSubject)) {
    throw new C8sVerifyError("cert_chain", "leaf issuer name does not match the CA subject name", {
      details: { leafIssuerCN: child.issuerCN, caSubjectCN: issuer.subjectCN },
    });
  }

  const hash = SIG_ALG[child.sigAlgOID];
  if (!hash) {
    throw new C8sVerifyError("cert_chain", `unsupported signature algorithm ${child.sigAlgOID}`);
  }
  // Pre-checked here so an unsupported CA curve reports as cert_chain rather
  // than verifyECDSASignature's generic invalid_cert.
  if (!CURVE_SIZE[issuer.spkiCurve ?? ""]) {
    throw new C8sVerifyError("cert_chain", "unsupported CA key curve");
  }

  const ok = await verifyECDSASignature(issuer, child.tbs, child.signatureDER, hash);
  if (!ok) {
    throw new C8sVerifyError("cert_chain", "certificate signature does not verify against CA");
  }
}

/**
 * Parse a leaf + CA from DER and verify the chain link.
 */
export async function verifyCertChain(
  leafDer: Uint8Array,
  caDer: Uint8Array,
  opts: { at?: Date } = {},
): Promise<ChainResult> {
  const leaf = parseCertificate(leafDer);
  const ca = parseCertificate(caDer);
  await verifySignedBy(leaf, ca, opts);
  return {
    leaf,
    ca,
    leafSha256: await fingerprintSHA256(leaf),
    caSha256: await fingerprintSHA256(ca),
  };
}
