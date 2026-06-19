// Azure vTPM freshness chain for az-snp — a JS port of attestation-go's
// `tpmcommon` (itself a port of attestation-rs `tpm_common.rs`), so the JS, Go
// and Rust verifiers agree byte-for-byte. On Azure node-as-CVM the hardware SNP
// `report_data` binds the vTPM Attestation Key (AK), NOT the caller's nonce, so
// the per-session binding rides in the AK-signed TPM quote. This module verifies:
//
//   SNP report_data[:32] == SHA-256(var_data)        (HCL binds the AK to the HW)
//     -> AK pub (from var_data JWK "HCLAkPub")
//       -> AK-signed TPM quote (RSASSA-PKCS1-v1.5 / SHA-256)
//         -> quote extraData == expected              (the session/nonce binding)
//
// All offsets come from the (untrusted, host-controlled) HCL/TPM structures and
// are bounds-checked; authenticity comes from the SHA-256 var_data binding into
// the SNP-signature-verified report and the AK signature over the quote.

import { subtle } from "./crypto-env.js";
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToUtf8,
  constantTimeEqual,
} from "./base64.js";
import { fail } from "./errors.js";

const HCL_TEE_REPORT_OFFSET = 0x20;
const HCL_TEE_REPORT_SIZE = 1184; // SNP and TDX both 1184
const HCL_VAR_DATA_HEADER_SIZE = 20; // total, count, report_type, version, content_length (5 LE u32)
const TPM_ATTEST_MAGIC = 0xff544347; // "\xFFTCG", big-endian

/** Decode standard or URL-safe base64 by sniffing the alphabet. */
function decodeB64(s) {
  return /[-_]/.test(s) ? base64UrlToBytes(s) : base64ToBytes(s);
}

/** Hex-decode, failing closed on malformed input. */
function hexToBytesStrict(h, what) {
  if (typeof h !== "string" || h.length % 2 !== 0) {
    fail("verification_failed", `az-snp: ${what} is not even-length hex`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(h.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) fail("verification_failed", `az-snp: ${what} has invalid hex`);
    out[i] = byte;
  }
  return out;
}

/**
 * Parse the var_data (HCL runtime data: a JWK JSON blob with the vTPM AK) out of
 * an HCL report. Layout: header(0x20) + TEE report(1184) + var_data header(20) +
 * content (null-padded).
 * @param {Uint8Array} hcl
 * @returns {{ reportType: number, varData: Uint8Array }}
 */
export function parseHclVarData(hcl) {
  const teeEnd = HCL_TEE_REPORT_OFFSET + HCL_TEE_REPORT_SIZE;
  const contentStart = teeEnd + HCL_VAR_DATA_HEADER_SIZE;
  if (hcl.length < contentStart) {
    fail("verification_failed", `az-snp: HCL report too short for var_data (${hcl.length} bytes)`);
  }
  const dv = new DataView(hcl.buffer, hcl.byteOffset, hcl.byteLength);
  const reportType = dv.getUint32(teeEnd + 8, true);
  const contentLength = dv.getUint32(teeEnd + 16, true);
  const available = hcl.length - contentStart;
  if (contentLength > available) {
    fail("verification_failed", `az-snp: HCL content_length (${contentLength}) exceeds available (${available})`);
  }
  let end = contentLength;
  while (end > 0 && hcl[contentStart + end - 1] === 0) end--; // trim trailing nulls
  if (end === 0) fail("verification_failed", "az-snp: HCL var_data is empty after null trimming");
  return { reportType, varData: hcl.subarray(contentStart, contentStart + end) };
}

/** report_data[:32] == SHA-256(var_data): how the HCL binds the AK into the HW report. */
export async function verifyVarDataBinding(reportData, varData) {
  if (reportData.length < 32) fail("verification_failed", "az-snp: report_data shorter than 32 bytes");
  const want = new Uint8Array(await subtle().digest("SHA-256", varData));
  if (!constantTimeEqual(reportData.subarray(0, 32), want)) {
    fail("verification_failed", "az-snp: HCL var_data binding failed (report_data[:32] != SHA-256(var_data))");
  }
}

/** Import the HCLAkPub RSA key from the var_data JWK as a WebCrypto verify key. */
async function importAkPub(varData) {
  let set;
  try {
    set = JSON.parse(bytesToUtf8(varData));
  } catch (e) {
    fail("verification_failed", `az-snp: var_data is not JSON: ${e.message ?? e}`);
  }
  const keys = set && set.keys;
  if (!Array.isArray(keys)) fail("verification_failed", "az-snp: var_data missing 'keys' array");
  const k = keys.find((x) => x && x.kid === "HCLAkPub" && x.kty === "RSA");
  if (!k || !k.n || !k.e) fail("verification_failed", "az-snp: var_data missing HCLAkPub RSA key");
  return subtle().importKey(
    "jwk",
    { kty: "RSA", n: k.n, e: k.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

/** Verify the AK's RSASSA-PKCS1-v1.5 / SHA-256 signature over the TPMS_ATTEST message. */
export async function verifyQuoteSignature(signature, message, varData) {
  const key = await importAkPub(varData);
  const ok = await subtle().verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, message);
  if (!ok) fail("verification_failed", "az-snp: TPM quote AK signature is invalid");
}

/** Extract extraData (qualifyingData) from a TPMS_ATTEST message — where the nonce rides. */
export function extractTpmNonce(message) {
  if (message.length < 10) fail("verification_failed", "az-snp: TPM attest message too short");
  const dv = new DataView(message.buffer, message.byteOffset, message.byteLength);
  if (dv.getUint32(0, false) !== TPM_ATTEST_MAGIC) {
    fail("verification_failed", `az-snp: invalid TPM attest magic 0x${dv.getUint32(0, false).toString(16)}`);
  }
  let off = 6; // magic(4) + type(2)
  const signerSize = dv.getUint16(off, false);
  off += 2 + signerSize;
  if (off + 2 > message.length) fail("verification_failed", "az-snp: TPM attest truncated at extraData size");
  const nonceSize = dv.getUint16(off, false);
  off += 2;
  if (off + nonceSize > message.length) fail("verification_failed", "az-snp: TPM attest truncated at extraData");
  return message.subarray(off, off + nonceSize);
}

/** Enforce that the quote's extraData equals `expected` exactly (unpadded). */
export function verifyTpmNonce(message, expected) {
  const nonce = extractTpmNonce(message);
  if (nonce.length !== expected.length) {
    fail(
      "report_data_mismatch",
      `az-snp: TPM nonce length mismatch: quote has ${nonce.length} bytes, expected ${expected.length}`,
    );
  }
  if (!constantTimeEqual(nonce, expected)) {
    fail("report_data_mismatch", "az-snp: TPM quote nonce does not match the expected binding (stale or replayed evidence)");
  }
}

/**
 * Full az-snp vTPM freshness chain. Fails closed (throws C8sVerifyError) on any step.
 * @param {{ hcl_report?: string, tpm_quote?: { signature: string, message: string } }} evidence
 * @param {Uint8Array} reportData  the SNP report's report_data (from the verified HW claims)
 * @param {Uint8Array} expected    the binding the quote must carry (e.g. SHA-384(x25519‖mlkem768‖nonce))
 */
export async function verifyVtpmFreshness(evidence, reportData, expected) {
  if (!evidence || !evidence.hcl_report) {
    fail("invalid_request", "az-snp freshness verification needs evidence.hcl_report");
  }
  if (!evidence.tpm_quote || !evidence.tpm_quote.signature || !evidence.tpm_quote.message) {
    fail("verification_failed", "az-snp evidence is missing the required tpm_quote");
  }
  const { varData } = parseHclVarData(decodeB64(evidence.hcl_report));
  await verifyVarDataBinding(reportData, varData);
  const signature = hexToBytesStrict(evidence.tpm_quote.signature, "tpm_quote.signature");
  const message = hexToBytesStrict(evidence.tpm_quote.message, "tpm_quote.message");
  await verifyQuoteSignature(signature, message, varData);
  verifyTpmNonce(message, expected);
}
