// Base64 (standard and URL-safe) <-> bytes, plus hex, plus byte helpers.
// Pure JS so it works identically in the browser and Node without Buffer.

const STD_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** @param {string} alphabet */
function decodeTable(alphabet) {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) t[alphabet.charCodeAt(i)] = i;
  return t;
}
const STD_DEC = decodeTable(STD_ALPHABET);
const URL_DEC = decodeTable(URL_ALPHABET);

/**
 * @param {Uint8Array} bytes
 * @param {string} alphabet
 * @param {boolean} pad
 */
function encode(bytes, alphabet, pad) {
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
    out +=
      alphabet[(n >> 18) & 63] +
      alphabet[(n >> 12) & 63] +
      alphabet[(n >> 6) & 63];
    if (pad) out += "=";
  }
  return out;
}

/**
 * @param {string} str
 * @param {Int16Array} table
 * @returns {Uint8Array}
 */
function decode(str, table) {
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

/** @param {Uint8Array} b @returns {string} */
export const bytesToBase64 = (b) => encode(b, STD_ALPHABET, true);
/** @param {Uint8Array} b @returns {string} */
export const bytesToBase64Url = (b) => encode(b, URL_ALPHABET, false);
/** @param {string} s @returns {Uint8Array} */
export const base64ToBytes = (s) => decode(s, STD_DEC);
/** @param {string} s @returns {Uint8Array} */
export const base64UrlToBytes = (s) => decode(s, URL_DEC);

/** @param {Uint8Array} b @returns {string} */
export function bytesToHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

/** @param {string} hex @returns {Uint8Array} */
export function hexToBytes(hex) {
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

/** @param {string} s @returns {Uint8Array} */
export function utf8ToBytes(s) {
  return new TextEncoder().encode(s);
}

/** @param {Uint8Array} b @returns {string} */
export function bytesToUtf8(b) {
  return new TextDecoder().decode(b);
}

/**
 * Concatenate byte arrays.
 * @param {...Uint8Array} parts
 * @returns {Uint8Array}
 */
export function concatBytes(...parts) {
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
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
