// Matched-workload stamp parsing and allowlist-document handling.
//
// The DER cases mirror c8s pkg/ratls/matchedworkload_test.go: the golden
// vector pins the one canonical encoding across the Go, JS, and TEErminator
// parsers, and every rejected boundary from the Go suite is rejected here too,
// so the three parsers cannot drift.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  OID_MATCHED_WORKLOAD,
  allowlistDigestHex,
  parseAllowlist,
  parseMatchedWorkload,
  resolveWorkload,
} from "../src/workload.js";
import { parseCertificate } from "../src/x509.js";
import { C8sVerifyError } from "../src/errors.js";
import { utf8ToBytes } from "../src/base64.js";
import {
  encodeMatchedWorkload,
  mintLeaf,
  extension,
  OID_15_DER,
  SEQ,
  INT,
  IA5,
  OCT,
  tlv,
} from "./mint-cert.js";
import { loadFixtures } from "./helpers.js";
import { decodePEM } from "../src/pem.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// The cross-repo golden vector: the one canonical encoding of
// {v1, "api", "7", 0x11*32}. MUST stay byte-identical to
// goldenMatchedWorkloadDER in c8s pkg/ratls/matchedworkload_test.go.
const GOLDEN_HEX =
  "302d0201011603617069160137" +
  "04201111111111111111111111111111111111111111111111111111111111111111";

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/../g)!.map((b) => parseInt(b, 16)));
}

const golden = () => hexToBytes(GOLDEN_HEX);

const rejectsInvalid = (der: Uint8Array | number[], label: string) => {
  assert.throws(
    () => parseMatchedWorkload(der instanceof Uint8Array ? der : new Uint8Array(der)),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "workload_invalid",
    `${label} must be rejected with workload_invalid`,
  );
};

test("parses the golden vector shared with the Go parser", () => {
  const m = parseMatchedWorkload(golden());
  assert.equal(m.name, "api");
  assert.equal(m.allowlistVersion, "7");
  assert.deepEqual(m.allowlistDigest, new Uint8Array(32).fill(0x11));
});

test("the test-side encoder reproduces the golden vector byte for byte", () => {
  // Guards the mutation cases below: if this encoder drifted from the
  // canonical encoding, "reject the mutation" tests would prove nothing.
  assert.deepEqual(encodeMatchedWorkload("api", "7", new Uint8Array(32).fill(0x11)), golden());
});

test("rejects every mutated boundary of the golden vector", () => {
  const digest = new Uint8Array(32).fill(0x11);
  rejectsInvalid([], "empty input");
  rejectsInvalid(golden().subarray(0, golden().length - 1), "truncated");
  rejectsInvalid([...golden(), 0x00], "trailing byte");
  rejectsInvalid(SEQ(INT(1), IA5("api"), IA5("7"), OCT(digest), INT(5)), "extra sequence field");
  rejectsInvalid(SEQ(INT(2), IA5("api"), IA5("7"), OCT(digest)), "format version 2");
  rejectsInvalid(
    SEQ(tlv(0x02, [0x00, 0x01]), IA5("api"), IA5("7"), OCT(digest)),
    "non-minimal version INTEGER",
  );
  rejectsInvalid(SEQ(IA5("api"), IA5("7"), OCT(digest)), "missing version field");
  rejectsInvalid(SEQ(INT(1), IA5(""), IA5("7"), OCT(digest)), "empty name");
  rejectsInvalid(SEQ(INT(1), IA5("a".repeat(64)), IA5("7"), OCT(digest)), "64-byte name");
  rejectsInvalid(SEQ(INT(1), IA5("a,b"), IA5("7"), OCT(digest)), "name with comma");
  rejectsInvalid(SEQ(INT(1), IA5(".api"), IA5("7"), OCT(digest)), "name with leading dot");
  rejectsInvalid(SEQ(INT(1), IA5("a/b"), IA5("7"), OCT(digest)), "name with slash");
  rejectsInvalid(SEQ(INT(1), IA5("api"), IA5(""), OCT(digest)), "empty version string");
  rejectsInvalid(SEQ(INT(1), IA5("api"), IA5("0"), OCT(digest)), "version zero");
  rejectsInvalid(SEQ(INT(1), IA5("api"), IA5("01"), OCT(digest)), "leading-zero version");
  rejectsInvalid(SEQ(INT(1), IA5("api"), IA5("1a"), OCT(digest)), "non-decimal version");
  rejectsInvalid(
    SEQ(INT(1), IA5("api"), IA5("1" + "0".repeat(20)), OCT(digest)),
    "21-digit version",
  );
  rejectsInvalid(SEQ(INT(1), IA5("api"), IA5("7"), OCT(digest.subarray(0, 31))), "31-byte digest");
  rejectsInvalid(SEQ(INT(1), IA5("api"), IA5("7"), OCT([...digest, 0x11])), "33-byte digest");
  // Long-form outer length where short form is canonical.
  rejectsInvalid([0x30, 0x81, golden()[1], ...golden().subarray(2)], "non-minimal outer length");
  // UTF8String tag where IA5String is required (offset 5 is the name's tag).
  const utf8Name = golden();
  utf8Name[5] = 0x0c;
  rejectsInvalid(utf8Name, "wrong string tag on name");
  rejectsInvalid([0x02, 0x01, 0x01], "not a sequence");
});

test("accepts the boundary values the grammar permits", () => {
  const digest = new Uint8Array(32);
  const long = parseMatchedWorkload(
    new Uint8Array(SEQ(INT(1), IA5("a".repeat(63)), IA5("7"), OCT(digest))),
  );
  assert.equal(long.name, "a".repeat(63));
  const maxVersion = parseMatchedWorkload(
    new Uint8Array(SEQ(INT(1), IA5("api"), IA5("9".repeat(20)), OCT(digest))),
  );
  assert.equal(maxVersion.allowlistVersion, "9".repeat(20));
});

// ---------------------------------------------------------------------------
// Reading the stamp off a certificate
// ---------------------------------------------------------------------------

test("a minted leaf carries the stamp under the .1.5 OID and it parses", async () => {
  const { caDer, caKeyPem } = await loadFixtures();
  const leaf = mintLeaf(caDer, caKeyPem, {
    extensions: [extension(OID_15_DER, golden())],
  });
  const cert = parseCertificate(decodePEM(leaf.leafPem, "CERTIFICATE")[0]);
  const extnValue = cert.extensions.get(OID_MATCHED_WORKLOAD);
  assert.ok(extnValue, "stamp extension went missing");
  assert.equal(parseMatchedWorkload(extnValue).name, "api");
});

test("a duplicate .1.5 extension fails closed at certificate parse", async () => {
  const { caDer, caKeyPem } = await loadFixtures();
  const leaf = mintLeaf(caDer, caKeyPem, {
    extensions: [extension(OID_15_DER, golden()), extension(OID_15_DER, golden())],
  });
  assert.throws(
    () => parseCertificate(leaf.leafDer),
    (e: unknown) =>
      e instanceof C8sVerifyError &&
      e.code === "invalid_cert" &&
      e.message.includes("more than once"),
  );
});

// ---------------------------------------------------------------------------
// Allowlist document handling
// ---------------------------------------------------------------------------

const readAllowlist = () => readFile(join(FIX, "cds-allowlist.json"));

test("parses the fixture allowlist and resolves a stamped name", async () => {
  const bytes = new Uint8Array(await readAllowlist());
  const doc = parseAllowlist(bytes);
  assert.equal(doc.schema, "c8s.allowlist/v1");
  assert.ok(resolveWorkload(doc, "sglang-dev"));
  assert.ok(resolveWorkload(doc, "sglang-kimi-k3"));
});

test("an absent workload name fails closed with workload_unresolved", async () => {
  const doc = parseAllowlist(new Uint8Array(await readAllowlist()));
  assert.throws(
    () => resolveWorkload(doc, "api"),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "workload_unresolved",
  );
  // Inherited object properties are not workload entries.
  assert.throws(
    () => resolveWorkload(doc, "toString"),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "workload_unresolved",
  );
});

// pkg/allowlist enforces MaxWorkloadNameLen on the WRITE path only: a served
// document is not the verifier's to reject over a name that was already stored,
// and failing the whole document would break every pull in the cluster over one
// legacy entry. The stamp parser still applies the bound (above), so an
// over-long name can be carried but never matched.
test("a served document keeps an over-long legacy workload name", () => {
  const legacy = "a".repeat(64);
  const doc = parseAllowlist(
    `{"schema":"c8s.allowlist/v1","digests":{},"workloads":{"${legacy}":{}}}`,
  );
  assert.ok(resolveWorkload(doc, legacy));
});

test("rejects a document that is not schema c8s.allowlist/v1", () => {
  for (const bad of [
    "null",
    "[]",
    '{"digests":{},"workloads":{}}',
    '{"schema":"c8s.allowlist/v2","digests":{},"workloads":{}}',
    '{"schema":"c8s.allowlist/v1","workloads":{}}',
    '{"schema":"c8s.allowlist/v1","digests":{}}',
    '{"schema":"c8s.allowlist/v1","digests":{},"workloads":[]}',
    "not json",
  ]) {
    assert.throws(
      () => parseAllowlist(utf8ToBytes(bad)),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
      `document ${JSON.stringify(bad)} must be rejected`,
    );
  }
});

test("allowlistDigestHex hashes the exact bytes, never a re-serialization", async () => {
  const bytes = new Uint8Array(await readAllowlist());
  const exact = await allowlistDigestHex(bytes);
  assert.match(exact, /^[0-9a-f]{64}$/);
  // A string input is UTF-8-encoded verbatim — same bytes, same digest.
  assert.equal(await allowlistDigestHex(new TextDecoder().decode(bytes)), exact);
  // A parse → stringify round-trip is semantically identical content with
  // different bytes; its digest must differ, which is exactly why the policy
  // pins bytes rather than JSON values.
  const reserialized = JSON.stringify(JSON.parse(new TextDecoder().decode(bytes)), null, 2);
  assert.notEqual(await allowlistDigestHex(reserialized), exact);
});
