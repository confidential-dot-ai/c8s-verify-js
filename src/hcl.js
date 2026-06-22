// Azure SEV-SNP (az-snp) evidence unwrapping.
//
// This module exists because Azure Confidential VMs do not hand back a bare SNP
// attestation report. The guest asks the paravisor (the HCL — Host Compatibility
// Layer) for a report and gets back an *HCL report*: a 32-byte header, then the
// raw 1184-byte SNP ATTESTATION_REPORT, then IGVM runtime data (the vTPM AK pub
// etc.). The layout matches Microsoft's az-cvm-vtpm crate and the c8s Go
// extractor (c8s/pkg/attestclient/snpreport.go).
//
// This unwrap supports the *degraded* az-snp path: the WASM `verify_snp` entry
// understands only a bare SNP report (`attestation_report` + `cert_chain.vcek`)
// and has no notion of the HCL envelope, so we unwrap the HCL report down to the
// raw SNP report it expects. The (host-controlled, untrusted) header is only used
// to *locate* bytes, with bounds checks so we never read out of range —
// authenticity comes entirely from the SNP signature the WASM verifies over the
// extracted report against the VCEK chain. A tampered report fails that check.
//
// This unwraps the hardware report only: it does NOT bind the vTPM quote
// (evidence.tpm_quote) to the SNP report, so it verifies hardware + measurement
// but not freshness/key-binding. For full az-snp verification — which also
// verifies the TPM quote against the AK and checks the quote's extraData against
// the session nonce — use the WASM `verify_az_snp` entry (exposed as
// `verifyAzSnp`, selected by `platform: "az-snp"`). This unwrap remains for
// callers that opt into the degraded `platform: "snp"` mode over az-snp evidence.

import { base64ToBytes, base64UrlToBytes, bytesToBase64 } from "./base64.js";
import { fail } from "./errors.js";

const HCL_MAGIC = 0x414c4348; // "HCLA", little-endian u32 at offset 0
const HCL_HEADER_SIZE = 32; // signature, version, report_size, request_type, status, reserved[3]
const HCL_REQUEST_TYPE_SNP = 2; // request_type field selects the hardware report type
const SNP_REPORT_SIZE = 1184; // sizeof(struct ATTESTATION_REPORT)

/**
 * Decode standard or URL-safe base64 by sniffing the alphabet. vTPM (az-snp)
 * evidence is URL-safe (per the c8s Go extractor), but VCEKs may arrive in
 * either alphabet, so we detect per field rather than assume.
 * @param {string} s
 * @returns {Uint8Array}
 */
function decodeB64(s) {
  return /[-_]/.test(s) ? base64UrlToBytes(s) : base64ToBytes(s);
}

/**
 * Extract the raw 1184-byte SNP attestation report from an Azure HCL report.
 * Validates the magic, hardware report type, and length before slicing.
 * @param {Uint8Array} hcl  decoded HCL report bytes
 * @returns {Uint8Array} the 1184-byte SNP ATTESTATION_REPORT
 */
export function snpReportFromHcl(hcl) {
  if (hcl.length < HCL_HEADER_SIZE + SNP_REPORT_SIZE) {
    fail("verification_failed", `az-snp: HCL report too short (${hcl.length} bytes)`);
  }
  const dv = new DataView(hcl.buffer, hcl.byteOffset, hcl.byteLength);
  const magic = dv.getUint32(0, true);
  if (magic !== HCL_MAGIC) {
    fail("verification_failed", `az-snp: bad HCL signature 0x${magic.toString(16)}, expected "HCLA"`);
  }
  const requestType = dv.getUint32(12, true);
  if (requestType !== HCL_REQUEST_TYPE_SNP) {
    fail("unsupported", `az-snp: HCL request_type ${requestType} is not SNP (${HCL_REQUEST_TYPE_SNP})`);
  }
  return hcl.subarray(HCL_HEADER_SIZE, HCL_HEADER_SIZE + SNP_REPORT_SIZE);
}

/**
 * Convert az-snp evidence (HCL report + VCEK) into the bare-SNP evidence shape
 * the WASM verifier expects: `{ attestation_report, cert_chain: { vcek } }`,
 * both standard base64. The TPM quote and version are dropped — the WASM
 * verifies the hardware report only (see module note).
 * @param {{ hcl_report?: string, vcek?: string }} evidence
 * @returns {{ attestation_report: string, cert_chain: { vcek: string } }}
 */
export function hclEvidenceToSnp(evidence) {
  if (!evidence.hcl_report || !evidence.vcek) {
    fail("invalid_request", "az-snp evidence requires both hcl_report and vcek");
  }
  const snp = snpReportFromHcl(decodeB64(evidence.hcl_report));
  return {
    attestation_report: bytesToBase64(snp),
    cert_chain: { vcek: bytesToBase64(decodeB64(evidence.vcek)) },
  };
}

/**
 * Normalize an evidence object to the bare-SNP shape the WASM verifier accepts.
 * az-snp evidence (carries `hcl_report`) is unwrapped; bare SNP evidence
 * (carries `attestation_report`) is returned unchanged.
 * @param {object} evidence
 * @returns {object}
 */
export function toWasmEvidence(evidence) {
  return evidence && evidence.hcl_report ? hclEvidenceToSnp(evidence) : evidence;
}
