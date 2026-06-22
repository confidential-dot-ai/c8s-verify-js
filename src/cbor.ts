// Minimal CBOR (RFC 8949) codec — just the subset the c8s over-encryption tunnel
// needs: unsigned/negative integers, byte strings, text strings, booleans, null,
// arrays, and string-keyed maps, with definite lengths only. This is exactly what
// the Go side (github.com/fxamacker/cbor/v2, default options) emits for
// overenc.Record and types.TunnelRequest/Response, so the two stay wire-compatible.
//
// CBOR replaces the previous JSON+base64 framing on the tunnel hop: a raw HTTP body
// rides as a CBOR byte string (major type 2) with no base64 inflation, and the
// AES-GCM record's IV/ciphertext likewise travel as raw bytes.

import { utf8ToBytes, bytesToUtf8, concatBytes } from "./base64.js";

/** Any value the codec can round-trip. */
export type CborValue =
  | number
  | string
  | boolean
  | null
  | Uint8Array
  | CborValue[]
  | { [key: string]: CborValue };

/** Encode a length/value argument into a CBOR head for the given major type. */
function head(major: number, n: number): Uint8Array {
  const mt = major << 5;
  if (n < 24) return Uint8Array.of(mt | n);
  if (n < 0x100) return Uint8Array.of(mt | 24, n);
  if (n < 0x10000) return Uint8Array.of(mt | 25, (n >> 8) & 0xff, n & 0xff);
  if (n < 0x100000000) {
    return Uint8Array.of(mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }
  // 64-bit length (bodies larger than 4 GiB are not expected, but stay correct).
  const hi = Math.floor(n / 0x100000000);
  const lo = n >>> 0;
  return Uint8Array.of(
    mt | 27,
    (hi >>> 24) & 0xff,
    (hi >>> 16) & 0xff,
    (hi >>> 8) & 0xff,
    hi & 0xff,
    (lo >>> 24) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 8) & 0xff,
    lo & 0xff,
  );
}

function encodeInto(value: unknown, out: Uint8Array[]): void {
  if (value === null || value === undefined) {
    out.push(Uint8Array.of(0xf6)); // null
    return;
  }
  if (typeof value === "boolean") {
    out.push(Uint8Array.of(value ? 0xf5 : 0xf4));
    return;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("cbor: only integer numbers are supported");
    if (value >= 0) out.push(head(0, value));
    else out.push(head(1, -1 - value));
    return;
  }
  if (typeof value === "string") {
    const b = utf8ToBytes(value);
    out.push(head(3, b.length), b);
    return;
  }
  if (value instanceof Uint8Array) {
    out.push(head(2, value.length), value);
    return;
  }
  if (Array.isArray(value)) {
    out.push(head(4, value.length));
    for (const item of value) encodeInto(item, out);
    return;
  }
  if (typeof value === "object") {
    // Plain object => CBOR map with text-string keys. undefined-valued fields are
    // dropped, mirroring Go's `omitempty` so absent and empty are indistinguishable.
    const entries = Object.entries(value as Record<string, unknown>).filter(
      ([, v]) => v !== undefined,
    );
    out.push(head(5, entries.length));
    for (const [k, v] of entries) {
      const kb = utf8ToBytes(k);
      out.push(head(3, kb.length), kb);
      encodeInto(v, out);
    }
    return;
  }
  throw new Error(`cbor: unsupported value type ${typeof value}`);
}

/**
 * Encode a JS value to CBOR bytes.
 */
export function cborEncode(value: unknown): Uint8Array {
  const out: Uint8Array[] = [];
  encodeInto(value, out);
  return concatBytes(...out);
}

interface DecodeState {
  bytes: Uint8Array;
  pos: number;
  dv: DataView;
}

/** Cursor over the input bytes. */
function readArg(st: DecodeState, ai: number): number {
  if (ai < 24) return ai;
  if (ai === 24) {
    need(st, 1);
    return st.bytes[st.pos++];
  }
  if (ai === 25) {
    need(st, 2);
    const v = (st.bytes[st.pos] << 8) | st.bytes[st.pos + 1];
    st.pos += 2;
    return v;
  }
  if (ai === 26) {
    need(st, 4);
    const v = st.dv.getUint32(st.pos);
    st.pos += 4;
    return v;
  }
  if (ai === 27) {
    need(st, 8);
    const hi = st.dv.getUint32(st.pos);
    const lo = st.dv.getUint32(st.pos + 4);
    st.pos += 8;
    return hi * 0x100000000 + lo;
  }
  throw new Error(`cbor: unsupported additional info ${ai} (indefinite lengths not supported)`);
}

function need(st: DecodeState, n: number): true {
  if (st.pos + n > st.bytes.length) throw new Error("cbor: truncated input");
  return true;
}

function readBytes(st: DecodeState, n: number): Uint8Array {
  need(st, n);
  const out = st.bytes.slice(st.pos, st.pos + n);
  st.pos += n;
  return out;
}

function decodeValue(st: DecodeState): CborValue | undefined {
  need(st, 1);
  const ib = st.bytes[st.pos++];
  const major = ib >> 5;
  const ai = ib & 0x1f;

  switch (major) {
    case 0: // unsigned integer
      return readArg(st, ai);
    case 1: // negative integer
      return -1 - readArg(st, ai);
    case 2: // byte string
      return readBytes(st, readArg(st, ai));
    case 3: // text string
      return bytesToUtf8(readBytes(st, readArg(st, ai)));
    case 4: {
      // array
      const n = readArg(st, ai);
      const arr: CborValue[] = new Array<CborValue>(n);
      for (let i = 0; i < n; i++) arr[i] = decodeValue(st) as CborValue;
      return arr;
    }
    case 5: {
      // map
      const n = readArg(st, ai);
      const obj: Record<string, CborValue> = {};
      for (let i = 0; i < n; i++) {
        const k = decodeValue(st);
        if (typeof k !== "string") throw new Error("cbor: only string map keys are supported");
        obj[k] = decodeValue(st) as CborValue;
      }
      return obj;
    }
    case 7: // simple values / floats
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 23) return undefined;
      if (ai === 26) {
        const v = st.dv.getFloat32(st.pos);
        st.pos += 4;
        return v;
      }
      if (ai === 27) {
        const v = st.dv.getFloat64(st.pos);
        st.pos += 8;
        return v;
      }
      throw new Error(`cbor: unsupported simple value ${ai}`);
    default:
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

/**
 * Decode CBOR bytes to a JS value. Byte strings decode to Uint8Array, text strings
 * to string, maps to plain objects.
 */
export function cborDecode(bytes: Uint8Array): CborValue {
  const st: DecodeState = {
    bytes,
    pos: 0,
    dv: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength),
  };
  return decodeValue(st) as CborValue;
}
