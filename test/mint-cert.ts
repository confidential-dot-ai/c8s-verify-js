// Node-side minting of mesh leaves for tests — the CA half of the trust model.
// Builds a minimal but well-formed X.509 v3 certificate with the tiny DER
// helpers, signs its tbsCertificate with the demo mesh CA's key, and returns
// the PEM + key the mock-LB helpers need. Exists so tests can put a
// matched-workload stamp (or a deliberately damaged one) on a leaf that
// genuinely chains to the fixture CA. node:crypto signing, so it must never be
// imported from src/ (browser code only verifies).

import { generateKeyPairSync, sign } from "node:crypto";

import { readTLV, readChildren } from "../src/asn1.js";
import { encodePEM } from "../src/pem.js";

/** DER TLV with a correct definite length (short or long form as needed). */
export function tlv(tag: number, ...content: (number[] | Uint8Array)[]): number[] {
  const body = content.flatMap((c) => Array.from(c));
  const len = body.length;
  const hdr =
    len < 0x80 ? [len] : len < 0x100 ? [0x81, len] : [0x82, (len >> 8) & 0xff, len & 0xff];
  return [tag, ...hdr, ...body];
}
export const SEQ = (...c: (number[] | Uint8Array)[]): number[] => tlv(0x30, ...c);
export const INT = (n: number): number[] => tlv(0x02, [n]);
export const OCT = (b: number[] | Uint8Array): number[] => tlv(0x04, b);
export const IA5 = (s: string): number[] => tlv(0x16, Array.from(new TextEncoder().encode(s)));
const UTC = (s: string): number[] => tlv(0x17, Array.from(new TextEncoder().encode(s)));
const UTF8 = (s: string): number[] => tlv(0x0c, Array.from(new TextEncoder().encode(s)));

/** 1.3.6.1.4.1.66378.1.5 — the matched-workload OID, DER-encoded. */
export const OID_15_DER = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x84, 0x86, 0x4a, 0x01, 0x05];
/** ecdsa-with-SHA384. */
const OID_ECDSA_SHA384 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/** id-at-commonName. */
const OID_CN = [0x06, 0x03, 0x55, 0x04, 0x03];

/**
 * Encode a matched-workload extnValue. An independent encoder on purpose: the
 * parser under test must agree with bytes it did not produce (the golden
 * vector pins the cross-repo encoding; this builds the mutation cases).
 */
export function encodeMatchedWorkload(
  name: string,
  allowlistVersion: string,
  digest: Uint8Array,
): Uint8Array {
  return new Uint8Array(SEQ(INT(1), IA5(name), IA5(allowlistVersion), OCT(digest)));
}

/** Wrap an extnValue as the Extension SEQUENCE the [3] block carries. */
export function extension(oidDer: number[], extnValue: Uint8Array | number[]): number[] {
  return SEQ(oidDer, OCT(extnValue));
}

export interface MintedLeaf {
  leafPem: string;
  leafDer: Uint8Array;
  leafKeyPem: string;
}

/** Subject Name element of a certificate's tbsCertificate, verbatim DER. */
function subjectNameDer(certDer: Uint8Array): Uint8Array {
  const cert = readTLV(certDer, 0);
  const tbs = readChildren(certDer, cert)[0];
  const fields = readChildren(certDer, tbs);
  let i = 0;
  if (fields[i]?.tag === 0xa0) i++; // [0] EXPLICIT version
  // serial, inner AlgorithmIdentifier, issuer, validity, subject.
  return fields[i + 4].bytes;
}

/**
 * Mint a leaf signed by the given CA, carrying the given Extension SEQUENCEs
 * (see {@link extension}). The issuer name is copied verbatim from the CA's
 * subject so the pair reads as a real chain link.
 */
export function mintLeaf(
  caCertDer: Uint8Array,
  caKeyPem: string,
  opts: { subjectCN?: string; extensions?: number[][] } = {},
): MintedLeaf {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
  const leafKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  const subject = SEQ(tlv(0x31, SEQ(OID_CN, UTF8(opts.subjectCN ?? "minted.test.c8s.local"))));
  const validity = SEQ(UTC("260101000000Z"), UTC("280101000000Z"));
  const trailing = opts.extensions?.length ? [tlv(0xa3, SEQ(...opts.extensions))] : [];
  const tbs = new Uint8Array(
    SEQ(
      tlv(0xa0, INT(2)), // v3
      INT(2),
      SEQ(OID_ECDSA_SHA384),
      subjectNameDer(caCertDer), // issuer = CA subject, verbatim
      validity,
      subject,
      spki,
      ...trailing,
    ),
  );
  const signature = sign("sha384", tbs, { key: caKeyPem, dsaEncoding: "der" });
  const leafDer = new Uint8Array(
    SEQ(tbs, SEQ(OID_ECDSA_SHA384), tlv(0x03, [0x00], new Uint8Array(signature))),
  );
  return { leafPem: encodePEM(leafDer, "CERTIFICATE"), leafDer, leafKeyPem };
}
