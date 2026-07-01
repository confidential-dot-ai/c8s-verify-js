// Minimal ASN.1 DER reader — only what X.509 certificate parsing needs.
// Not a general-purpose ASN.1 library; it intentionally supports just the tags
// and length forms that appear in DER-encoded certificates.

import { C8sVerifyError } from "./errors.js";

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
} as const;

export interface DERNode {
  tag: number;
  constructed: boolean;
  start: number; // offset of the tag byte
  headerLen: number; // tag + length bytes
  contentStart: number;
  contentEnd: number; // exclusive
  end: number; // exclusive (== contentEnd)
  bytes: Uint8Array; // full element incl. header
  content: Uint8Array; // content only
}

/**
 * Read one TLV element starting at `offset`.
 */
export function readTLV(buf: Uint8Array, offset: number): DERNode {
  if (offset >= buf.length) {
    throw new C8sVerifyError("invalid_cert", "ASN.1: unexpected end of input");
  }
  const tag = buf[offset];
  // High-tag-number form is not used in certificates; reject it.
  if ((tag & 0x1f) === 0x1f) {
    throw new C8sVerifyError("invalid_cert", "ASN.1: high-tag-number form unsupported");
  }
  let pos = offset + 1;
  if (pos >= buf.length) {
    throw new C8sVerifyError("invalid_cert", "ASN.1: truncated length");
  }
  let len = buf[pos++];
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    if (numBytes === 0 || numBytes > 4) {
      throw new C8sVerifyError("invalid_cert", "ASN.1: unsupported length encoding");
    }
    len = 0;
    for (let i = 0; i < numBytes; i++) {
      if (pos >= buf.length) {
        throw new C8sVerifyError("invalid_cert", "ASN.1: truncated long length");
      }
      len = (len << 8) | buf[pos++];
    }
  }
  const contentStart = pos;
  const contentEnd = contentStart + len;
  if (contentEnd > buf.length) {
    throw new C8sVerifyError("invalid_cert", "ASN.1: content exceeds buffer");
  }
  return {
    tag,
    constructed: (tag & 0x20) !== 0,
    start: offset,
    headerLen: contentStart - offset,
    contentStart,
    contentEnd,
    end: contentEnd,
    bytes: buf.subarray(offset, contentEnd),
    content: buf.subarray(contentStart, contentEnd),
  };
}

/**
 * Read all child TLVs of a constructed node.
 */
export function readChildren(buf: Uint8Array, node: DERNode): DERNode[] {
  if (!node.constructed) {
    throw new C8sVerifyError("invalid_cert", "ASN.1: expected constructed node");
  }
  const children: DERNode[] = [];
  let off = node.contentStart;
  while (off < node.contentEnd) {
    const child = readTLV(buf, off);
    children.push(child);
    off = child.end;
  }
  return children;
}

/**
 * Decode an OID node's content into dotted-decimal string.
 */
export function decodeOID(content: Uint8Array): string {
  if (content.length === 0) throw new C8sVerifyError("invalid_cert", "ASN.1: empty OID");
  const first = content[0];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < content.length; i++) {
    value = (value << 7) | (content[i] & 0x7f);
    if ((content[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

/**
 * Parse a DER time (UTCTime or GeneralizedTime) into a Date.
 */
export function decodeTime(node: DERNode): Date {
  const s = new TextDecoder().decode(node.content);
  let year: number, rest: string;
  if (node.tag === TAG.UTC_TIME) {
    // YYMMDDHHMMSSZ — pivot at 50 per RFC 5280.
    const yy = parseInt(s.slice(0, 2), 10);
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = s.slice(2);
  } else if (node.tag === TAG.GENERALIZED_TIME) {
    year = parseInt(s.slice(0, 4), 10);
    rest = s.slice(4);
  } else {
    throw new C8sVerifyError("invalid_cert", `ASN.1: not a time tag (0x${node.tag.toString(16)})`);
  }
  const mo = parseInt(rest.slice(0, 2), 10);
  const da = parseInt(rest.slice(2, 4), 10);
  const ho = parseInt(rest.slice(4, 6), 10);
  const mi = parseInt(rest.slice(6, 8), 10);
  const se =
    rest.length >= 10 && /\d\d/.test(rest.slice(8, 10)) ? parseInt(rest.slice(8, 10), 10) : 0;
  return new Date(Date.UTC(year, mo - 1, da, ho, mi, se));
}
