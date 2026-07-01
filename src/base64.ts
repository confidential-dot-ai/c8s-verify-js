// Base64 (standard and URL-safe) <-> bytes, plus hex, plus byte helpers.
// Pure JS so it works identically in the browser and Node without Buffer.

const STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function decodeTable(alphabet: string): Int16Array {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) t[alphabet.charCodeAt(i)] = i;
  return t;
}
const STD_DEC = decodeTable(STD_ALPHABET);
const URL_DEC = decodeTable(URL_ALPHABET);

function encode(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      alphabet[(n >> 18) & 63] +
      alphabet[(n >> 12) & 63] +
      alphabet[(n >> 6) & 63] +
      alphabet[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63];
    if (pad) out += "==";
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63];
    if (pad) out += "=";
  }
  return out;
}

function decode(str: string, table: Int16Array): Uint8Array {
  // Tolerate padding and either alphabet's chars regardless of which table.
  let clean = "";
  for (const ch of str) {
    if (ch === "=" || ch === "\n" || ch === "\r" || ch === " ") continue;
    clean += ch;
  }
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let buf = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    const v = code < 128 ? table[code] : -1;
    if (v < 0) throw new Error(`base64: invalid character ${JSON.stringify(clean[i])}`);
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buf >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

export const bytesToBase64 = (b: Uint8Array): string => encode(b, STD_ALPHABET, true);
export const bytesToBase64Url = (b: Uint8Array): string => encode(b, URL_ALPHABET, false);
export const base64ToBytes = (s: string): Uint8Array => decode(s, STD_DEC);
export const base64UrlToBytes = (s: string): Uint8Array => decode(s, URL_DEC);

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += byte.toString(16).padStart(2, "0");
  return s;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("hex: odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) throw new Error("hex: invalid characters");
    out[i] = byte;
  }
  return out;
}

export function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

/**
 * Concatenate byte arrays.
 */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Constant-time equality for two byte arrays.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
