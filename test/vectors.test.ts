// Cross-language interoperability vectors, shared verbatim with c8s
// pkg/overenc/testdata (regenerated there with `go test -update`). Everything
// downstream of the recorded X-Wing ciphertext is deterministic, so this test
// reproduces the whole pipeline — seed-expanded keypair, decapsulation,
// identity transcript, HKDF key schedule, and one sealed record per direction
// — and compares byte for byte against the Go implementation.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  xwingKeyPairFromSeed,
  xwingDecapsulate,
  deriveChannel,
  deriveRawKeySchedule,
} from "../src/keyagreement.js";
import { identityTranscriptHash } from "../src/identity.js";
import { bytesToHex, hexToBytes } from "../src/base64.js";

interface ChannelVectors {
  xwing_seed_hex: string;
  xwing_ek_hex: string;
  xwing_ct_hex: string;
  shared_secret_hex: string;
  leaf_der_hex: string;
  ca_der_hex: string;
  nonce_hex: string;
  session_id_hex: string;
  transcript_hash_hex: string;
  c2s_key_hex: string;
  s2c_key_hex: string;
  c2s_iv_hex: string;
  s2c_iv_hex: string;
  exporter_hex: string;
  request_seq: number;
  request_plaintext_hex: string;
  request_ct_hex: string;
  response_seq: number;
  response_plaintext_hex: string;
  response_ct_hex: string;
}

const VECTORS = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "test-vectors",
  "attest_pq_channel_vectors.json",
);

test("channel golden vectors match the Go implementation byte for byte", async () => {
  const v = JSON.parse(await readFile(VECTORS, "utf8")) as ChannelVectors;

  // Keypair from seed: the derived encapsulation key must match.
  const kp = await xwingKeyPairFromSeed(hexToBytes(v.xwing_seed_hex));
  assert.equal(bytesToHex(kp.ek), v.xwing_ek_hex, "encapsulation key from seed");

  // Decapsulation of the recorded ciphertext.
  const ct = hexToBytes(v.xwing_ct_hex);
  const ss = await xwingDecapsulate(kp, ct);
  assert.equal(bytesToHex(ss), v.shared_secret_hex, "shared secret");

  // Identity transcript.
  const sessionId = hexToBytes(v.session_id_hex);
  const transcript = await identityTranscriptHash(
    kp.ek,
    ct,
    sessionId,
    hexToBytes(v.nonce_hex),
    hexToBytes(v.leaf_der_hex),
    hexToBytes(v.ca_der_hex),
  );
  assert.equal(bytesToHex(transcript), v.transcript_hash_hex, "transcript hash");

  // HKDF key schedule.
  const schedule = await deriveRawKeySchedule(ss, transcript);
  assert.equal(bytesToHex(schedule.c2sKey), v.c2s_key_hex, "c2s key");
  assert.equal(bytesToHex(schedule.s2cKey), v.s2c_key_hex, "s2c key");
  assert.equal(bytesToHex(schedule.c2sIv), v.c2s_iv_hex, "c2s iv prefix");
  assert.equal(bytesToHex(schedule.s2cIv), v.s2c_iv_hex, "s2c iv prefix");
  assert.equal(bytesToHex(schedule.exporter), v.exporter_hex, "exporter");

  // Record layer: deterministic nonces make the sealed bytes reproducible.
  const client = await deriveChannel("client", ss, transcript, sessionId);
  const server = await deriveChannel("server", ss, transcript, sessionId);

  const req = await client.sealRequest(hexToBytes(v.request_plaintext_hex));
  assert.equal(req.seq, v.request_seq, "request seq");
  assert.equal(bytesToHex(req.ct), v.request_ct_hex, "request record");
  assert.equal(
    bytesToHex(await server.openRequest(req)),
    v.request_plaintext_hex,
    "request plaintext",
  );

  const resp = await server.sealResponse(hexToBytes(v.response_plaintext_hex), req.seq);
  assert.equal(resp.seq, v.response_seq, "response seq");
  assert.equal(bytesToHex(resp.ct), v.response_ct_hex, "response record");
  assert.equal(
    bytesToHex(await client.openResponse(resp, req.seq)),
    v.response_plaintext_hex,
    "response plaintext",
  );
});
