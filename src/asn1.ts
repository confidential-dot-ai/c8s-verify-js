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
    // `<<` coerces to int32, so a FOUR-byte length whose top bit is set (e.g.
    // 0xFFFFFFFA) wraps to a NEGATIVE number. That length then passes the
    // "exceeds buffer" check below — contentEnd lands *before* contentStart —
    // and yields a node whose `end` is at or behind its own `start`, which sends
    // readChildren into a loop that never advances and allocates until the heap
    // dies. Reject it here rather than relying on `>>> 0`: a 2GiB-plus element
    // cannot appear in any certificate this library parses, so there is nothing
    // legitimate to preserve. Only the 4-byte case can overflow — with three or
    // fewer bytes the value tops out at 0x00FFFFFF — so a leading high bit in a
    // shorter length (0x81 0x80 is a perfectly ordinary 128) stays valid.
    if (numBytes === 4 && pos < buf.length && buf[pos] & 0x80) {
      throw new C8sVerifyError("invalid_cert", "ASN.1: length exceeds the supported range");
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
  // Belt and braces: the high-bit rejection above makes a negative length
  // unreachable, but this is the invariant every caller depends on, so assert it
  // here rather than trusting the arithmetic to stay correct forever.
  if (len < 0) {
    throw new C8sVerifyError("invalid_cert", "ASN.1: negative length");
  }
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
    // Every TLV has at least a tag and a length byte, so a child must end
    // strictly past where it started. Asserting it here means no malformed
    // length can ever turn this loop into a non-terminating one, independently
    // of how readTLV computes its bounds — a loop that does not advance is the
    // difference between a rejected certificate and a dead browser tab.
    if (child.end <= off) {
      throw new C8sVerifyError("invalid_cert", "ASN.1: element does not advance");
    }
    children.push(child);
    off = child.end;
  }
  // A child that overruns its parent means the lengths disagree; DER says the
  // parent's length is authoritative, so a mismatch is malformed, not a
  // trailing element to be tolerated.
  if (off !== node.contentEnd) {
    throw new C8sVerifyError("invalid_cert", "ASN.1: child element overruns its parent");
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
