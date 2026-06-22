// PEM <-> DER. Minimal, dependency-free.

import { base64ToBytes, bytesToBase64 } from "./base64.js";
import { C8sVerifyError } from "./errors.js";

/**
 * Decode all PEM blocks of the given label from a string.
 * @returns DER bodies, in order
 */
export function decodePEM(pem: string, label = "CERTIFICATE"): Uint8Array[] {
  const re = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`, "g");
  const out: Uint8Array[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem)) !== null) {
    out.push(base64ToBytes(m[1]));
  }
  return out;
}

/**
 * Decode exactly one PEM block, throwing if zero or more than one is present.
 */
export function decodeOnePEM(pem: string, label = "CERTIFICATE"): Uint8Array {
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
 */
export function encodePEM(der: Uint8Array, label = "CERTIFICATE"): string {
  const b64 = bytesToBase64(der);
  const lines = b64.match(/.{1,64}/g) ?? [""];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
