// The matched-workload stamp and the allowlist document it pins.
//
// CDS stamps a mesh leaf with the single allowlist entry whose (digest, argv)
// policy the pod's attested container inventory uniquely matched at issuance.
// Like the sandbox ID, the mesh CA signature — never the hardware evidence —
// is what vouches for the stamp, so it is enforceable only where a CA chain
// has been verified; on the LB's own leaf the exact leaf DER is additionally
// committed by the identity transcript.
//
// The stamp's allowlist digest pins WHICH policy document the match was
// decided under, so a relying party holding the same canonical bytes can
// detect skew between the policy it pinned and the one CDS enforced.
//
// Parser parity: c8s pkg/ratls/matchedworkload.go. Golden vectors are shared
// across the Go, JS, and TEErminator parsers so they cannot drift.

import { readTLV, readChildren, requireMinimalLength, TAG, type DERNode } from "./asn1.js";
import { bytesToHex, utf8ToBytes } from "./base64.js";
import { subtle } from "./crypto-env.js";
import { C8sVerifyError, fail } from "./errors.js";

/** Matched-workload extension OID (c8s pkg/ratls, the 1.3.6.1.4.1.59888 arc). */
export const OID_MATCHED_WORKLOAD = "1.3.6.1.4.1.59888.1.5";

/** The only encoding version this module parses; unknown versions fail closed. */
const MATCHED_WORKLOAD_VERSION = 1;

/** Exact length of the canonical-allowlist SHA-256. */
const ALLOWLIST_DIGEST_SIZE = 32;

/**
 * The pkg/allowlist workload-name grammar with the 63-byte Kubernetes
 * label-value bound: [A-Za-z0-9][A-Za-z0-9._-]*, 1..63 bytes. Must match
 * allowlist.ValidWorkloadName exactly — the stamp, the allowlist lint, and the
 * admission webhook all admit the same names.
 */
const WORKLOAD_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

/**
 * The canonical positive decimal integer the store's monotonic version counter
 * emits: 1–20 ASCII digits, no leading zero. Matches Go's
 * allowlistVersionPattern exactly.
 */
const ALLOWLIST_VERSION_PATTERN = /^[1-9][0-9]{0,19}$/;

/**
 * A parsed matched-workload stamp: the allowlist entry a leaf's attested
 * container set uniquely matched at issuance, and the exact policy snapshot
 * the match was decided under.
 */
export interface MatchedWorkload {
  /** The matched entry name (workload-name grammar, at most 63 bytes). */
  name: string;
  /**
   * The allowlist store's monotonic version counter at the snapshot the match
   * used — a canonical positive decimal integer.
   */
  allowlistVersion: string;
  /** SHA-256 of Allowlist.Canonical() of that snapshot, exactly 32 bytes. */
  allowlistDigest: Uint8Array;
}

const invalid = (message: string): never => fail("workload_invalid", message);

/**
 * Decode a DER-encoded matched-workload extension value:
 *
 *   MatchedWorkload ::= SEQUENCE {
 *       formatVersion    INTEGER,           -- exactly 1
 *       name             IA5String,         -- 1..63 bytes, workload-name grammar
 *       allowlistVersion IA5String,         -- 1..20 decimal digits, no leading zero
 *       allowlistDigest  OCTET STRING (32)  -- SHA-256(Allowlist.Canonical())
 *   }
 *
 * Requires the one canonical encoding: minimal DER throughout, no trailing
 * bytes or fields — no two distinct extension values may parse to the same
 * MatchedWorkload, because the CA signature (and, on the LB leaf, the
 * identity transcript) vouches for the bytes rather than their meaning.
 * Everything else fails closed with `workload_invalid`.
 */
export function parseMatchedWorkload(extnValue: Uint8Array): MatchedWorkload {
  let seq: DERNode;
  let parts: DERNode[];
  try {
    seq = readTLV(extnValue, 0);
    if (seq.tag !== TAG.SEQUENCE) {
      invalid("matched-workload extension is not a SEQUENCE");
    }
    if (seq.end !== extnValue.length) {
      invalid(
        `matched-workload extension has ${extnValue.length - seq.end} trailing bytes after the SEQUENCE`,
      );
    }
    requireMinimalLength(seq, "matched-workload SEQUENCE");
    parts = readChildren(extnValue, seq);
    for (const [i, p] of parts.entries()) requireMinimalLength(p, `matched-workload field ${i}`);
  } catch (e) {
    // The DER reader and minimal-length check throw the neutral invalid_cert;
    // surface parse damage under the precise workload code instead.
    if (e instanceof C8sVerifyError && e.code === "invalid_cert") {
      invalid(`matched-workload extension is malformed DER: ${e.message}`);
    }
    throw e;
  }

  if (parts.length !== 4) {
    invalid(`matched-workload SEQUENCE has ${parts.length} fields, expected 4`);
  }
  const [versionNode, nameNode, allowlistVersionNode, digestNode] = parts;

  // DER INTEGERs are minimally encoded two's-complement: never empty, no
  // redundant leading byte. Without this, {02 01 01} and {02 02 00 01} would
  // both read as version 1 — two byte strings, one meaning.
  if (versionNode.tag !== TAG.INTEGER) {
    invalid("matched-workload formatVersion is not an INTEGER");
  }
  const v = versionNode.content;
  if (v.length === 0) invalid("matched-workload formatVersion INTEGER is empty");
  if (v.length > 1 && (v[0] === 0x00 || v[0] === 0xff) && (v[0] & 0x80) === (v[1] & 0x80)) {
    invalid("matched-workload formatVersion INTEGER is not minimally encoded");
  }
  if (v[0] & 0x80) invalid("matched-workload formatVersion INTEGER is negative");
  if (v.length !== 1 || v[0] !== MATCHED_WORKLOAD_VERSION) {
    let version = 0;
    for (const b of v) version = version * 256 + b;
    invalid(
      `unsupported matched-workload version ${version} (supported: ${MATCHED_WORKLOAD_VERSION})`,
    );
  }

  if (nameNode.tag !== TAG.IA5_STRING) {
    invalid("matched-workload name is not an IA5String");
  }
  const name = new TextDecoder().decode(nameNode.content);
  if (!WORKLOAD_NAME_PATTERN.test(name)) {
    invalid(
      `matched-workload name ${JSON.stringify(name)} is not a valid workload entry name ` +
        "(1..63 bytes, [A-Za-z0-9][A-Za-z0-9._-]*)",
    );
  }

  if (allowlistVersionNode.tag !== TAG.IA5_STRING) {
    invalid("matched-workload allowlistVersion is not an IA5String");
  }
  const allowlistVersion = new TextDecoder().decode(allowlistVersionNode.content);
  if (!ALLOWLIST_VERSION_PATTERN.test(allowlistVersion)) {
    invalid(
      `matched-workload allowlist version ${JSON.stringify(allowlistVersion)} is not a ` +
        "canonical positive decimal integer",
    );
  }

  if (digestNode.tag !== TAG.OCTET_STRING || digestNode.content.length !== ALLOWLIST_DIGEST_SIZE) {
    invalid(
      `matched-workload allowlist digest must be a ${ALLOWLIST_DIGEST_SIZE}-byte OCTET STRING`,
    );
  }

  return { name, allowlistVersion, allowlistDigest: digestNode.content };
}

/** One workload entry of an allowlist document. Kept structurally loose: the
 * verifier resolves names, it does not enforce container policy. */
export interface AllowlistWorkload {
  label?: string;
  [key: string]: unknown;
}

/** The `c8s.allowlist/v1` document (the shape `GET /allowlist` serves). */
export interface AllowlistDocument {
  schema: "c8s.allowlist/v1";
  /** Admitted image digests: `sha256:<64-hex>` → image reference. */
  digests: Record<string, string>;
  /** Named workload entries; stamp names resolve as key lookups here. */
  workloads: Record<string, AllowlistWorkload>;
}

/** Bytes as supplied: a string is UTF-8-encoded verbatim, never re-serialized. */
function allowlistBytes(input: Uint8Array | string): Uint8Array {
  return typeof input === "string" ? utf8ToBytes(input) : input;
}

/**
 * Parse allowlist document bytes and check the schema. Parsing is for name
 * resolution only — the digest check hashes the exact bytes supplied (see
 * {@link allowlistDigestHex}), never a re-serialized copy.
 */
export function parseAllowlist(bytes: Uint8Array | string): AllowlistDocument {
  let doc: unknown;
  try {
    doc = JSON.parse(new TextDecoder().decode(allowlistBytes(bytes))) as unknown;
  } catch (cause) {
    fail("invalid_request", "allowlist document is not valid JSON", { cause });
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    fail("invalid_request", "allowlist document is not a JSON object");
  }
  const { schema, digests, workloads } = doc as Record<string, unknown>;
  if (schema !== "c8s.allowlist/v1") {
    fail(
      "invalid_request",
      `allowlist document has schema ${JSON.stringify(schema)}, want "c8s.allowlist/v1"`,
    );
  }
  if (digests === null || typeof digests !== "object" || Array.isArray(digests)) {
    fail("invalid_request", "allowlist document has no digests map");
  }
  if (workloads === null || typeof workloads !== "object" || Array.isArray(workloads)) {
    fail("invalid_request", "allowlist document has no workloads map");
  }
  return doc as AllowlistDocument;
}

/**
 * Resolve a stamped workload name in a pinned allowlist document — a key
 * lookup in `workloads`, failing closed when absent. An unresolved name means
 * CDS matched against a policy revision this document does not carry, which
 * the digest check normally catches first; reaching this failure indicates a
 * document that hashes right but omits the entry, and must never pass.
 */
export function resolveWorkload(doc: AllowlistDocument, name: string): AllowlistWorkload {
  if (!Object.prototype.hasOwnProperty.call(doc.workloads, name)) {
    fail(
      "workload_unresolved",
      `stamped workload name ${JSON.stringify(name)} does not resolve in the pinned allowlist ` +
        `document (${Object.keys(doc.workloads).length} workload entries)`,
    );
  }
  return doc.workloads[name];
}

/**
 * SHA-256 over the EXACT bytes supplied, as lowercase hex.
 *
 * Canonical bytes only: the stamp commits SHA-256 over Allowlist.Canonical(),
 * so the caller must supply those bytes verbatim (the server emits canonical
 * bytes on `GET /allowlist`). Nothing here parses or re-serializes — a
 * re-encoded copy of semantically identical content is a different digest.
 */
export async function allowlistDigestHex(bytes: Uint8Array | string): Promise<string> {
  const exact = allowlistBytes(bytes);
  return bytesToHex(new Uint8Array(await subtle().digest("SHA-256", exact.slice())));
}
