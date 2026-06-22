// Minimal X.509 certificate parsing + chain verification, sufficient for the c8s
// trust model: parse the served CDS/mesh-CA cert, check its validity window, and
// verify that a leaf certificate's signature was produced by the CA's key
// (ECDSA P-256/P-384 with SHA-256/384). Pure WebCrypto + the tiny DER reader.

import { subtle } from "./crypto-env.js";
import { readTLV, readChildren, decodeOID, decodeTime, TAG, type DERNode } from "./asn1.js";
import { bytesToHex } from "./base64.js";
import { C8sVerifyError } from "./errors.js";

const OID = {
  CN: "2.5.4.3",
  EC_PUBLIC_KEY: "1.2.840.10045.2.1",
  P256: "1.2.840.10045.3.1.7",
  P384: "1.3.132.0.34",
  ECDSA_SHA256: "1.2.840.10045.4.3.2",
  ECDSA_SHA384: "1.2.840.10045.4.3.3",
} as const;

const CURVE_BY_OID: Record<string, string> = { [OID.P256]: "P-256", [OID.P384]: "P-384" };
const CURVE_SIZE: Record<string, number> = { "P-256": 32, "P-384": 48 };
const SIG_ALG: Record<string, string> = {
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
  spki: Uint8Array;
  spkiCurve: string | null;
  sigAlgOID: string;
  signatureDER: Uint8Array;
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
    tbs: tbs.bytes,
    serialHex: bytesToHex(serial.content),
    notBefore,
    notAfter,
    subjectCN: nameCN(der, subject),
    issuerCN: nameCN(der, issuer),
    spki: spkiNode.bytes,
    spkiCurve,
    sigAlgOID,
    signatureDER,
  };
}

/**
 * Convert a DER ECDSA signature (SEQUENCE{r,s}) to raw r||s for WebCrypto.
 * @param der DER signature
 * @param size curve component size in bytes
 */
function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array {
  const seq = readTLV(der, 0);
  const [r, s] = readChildren(der, seq);
  if (!r || !s || r.tag !== TAG.INTEGER || s.tag !== TAG.INTEGER) {
    throw new C8sVerifyError("invalid_cert", "malformed ECDSA signature");
  }
  const out = new Uint8Array(size * 2);
  const place = (int: Uint8Array, off: number): void => {
    let v = int;
    // Strip a leading 0x00 sign byte; left-pad to `size`.
    if (v.length > size && v[0] === 0x00) v = v.subarray(v.length - size);
    if (v.length > size) throw new C8sVerifyError("invalid_cert", "ECDSA integer too large");
    out.set(v, off + (size - v.length));
  };
  place(r.content, 0);
  place(s.content, size);
  return out;
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
 * Verify that `child` was signed by `issuer` (ECDSA), and that both are within
 * their validity windows at `at`. Throws C8sVerifyError on any failure.
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
    if (at < c.notBefore) {
      throw new C8sVerifyError("invalid_cert", `${label} certificate is not yet valid`, {
        details: { notBefore: c.notBefore.toISOString() },
      });
    }
    if (at > c.notAfter) {
      throw new C8sVerifyError("invalid_cert", `${label} certificate has expired`, {
        details: { notAfter: c.notAfter.toISOString() },
      });
    }
  }

  const hash = SIG_ALG[child.sigAlgOID];
  if (!hash) {
    throw new C8sVerifyError("cert_chain", `unsupported signature algorithm ${child.sigAlgOID}`);
  }
  const size = CURVE_SIZE[issuer.spkiCurve ?? ""];
  if (!size) {
    throw new C8sVerifyError("cert_chain", "unsupported CA key curve");
  }

  const caKey = await importPublicKey(issuer);
  const rawSig = ecdsaDerToRaw(child.signatureDER, size);
  const ok = await subtle().verify({ name: "ECDSA", hash }, caKey, rawSig, child.tbs);
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
