// PEM <-> DER. Minimal, dependency-free.

import { base64ToBytes, bytesToBase64 } from "./base64.js";
import { C8sVerifyError } from "./errors.js";

/**
 * Decode all PEM blocks of the given label from a string.
 * @param {string} pem
 * @param {string} [label="CERTIFICATE"]
 * @returns {Uint8Array[]} DER bodies, in order
 */
export function decodePEM(pem, label = "CERTIFICATE") {
  const re = new RegExp(
    `-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`,
    "g",
  );
  /** @type {Uint8Array[]} */
  const out = [];
  let m;
  while ((m = re.exec(pem)) !== null) {
    out.push(base64ToBytes(m[1]));
  }
  return out;
}

/**
 * Decode exactly one PEM block, throwing if zero or more than one is present.
 * @param {string} pem
 * @param {string} [label="CERTIFICATE"]
 * @returns {Uint8Array}
 */
export function decodeOnePEM(pem, label = "CERTIFICATE") {
  const blocks = decodePEM(pem, label);
  if (blocks.length === 0) {
    throw new C8sVerifyError("invalid_cert", `no PEM ${label} block found`);
  }
  if (blocks.length > 1) {
    throw new C8sVerifyError(
      "invalid_cert",
      `expected exactly one PEM ${label} block, got ${blocks.length}`,
    );
  }
  return blocks[0];
}

/**
 * Encode DER bytes as a PEM block.
 * @param {Uint8Array} der
 * @param {string} [label="CERTIFICATE"]
 * @returns {string}
 */
export function encodePEM(der, label = "CERTIFICATE") {
  const b64 = bytesToBase64(der);
  const lines = b64.match(/.{1,64}/g) ?? [""];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
