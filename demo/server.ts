// Mock C8s Load Balancer for the demo. Implements the attest-pq protocol
// (bundle version c8s/attest-pq/v1, see ../PROTOCOL.md) so the browser library
// can run the full flow offline.
//
// TEST/DEMO ONLY. It mirrors c8s's own test/mock-cds: it serves REAL recorded
// SNP hardware evidence (verified for real by the WASM verifier) but does not run
// inside a TEE, so it cannot bind a live key exchange into a fresh hardware report.
// Everything else — the X-Wing key exchange, the mesh identity proof, and the
// AES-256-GCM over-encryption channel — is real. Because the recorded report_data
// can never match a fresh transcript, the demo explicitly disables freshness.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";
import { Buffer } from "node:buffer";

import { deriveChannel, xwingEncapsulate, XWING_EK_BYTES } from "../src/keyagreement.js";
import { type Channel, type WireRecord } from "../src/channel.js";
import { cborEncode, cborDecode, type CborValue } from "../src/cbor.js";
import { bytesToBase64Url, base64UrlToBytes, utf8ToBytes, bytesToUtf8 } from "../src/base64.js";
import { decodePEM } from "../src/pem.js";
import { NONCE_BYTES } from "../src/nonce.js";
import { mintIdentityProof } from "../test/mint-identity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Run from source via tsx; this file lives at demo/, so the repo root — the
// static root, also holding demo/fixtures — is one directory up.
const REPO = join(__dirname, ".."); // package root, served statically
const FIX = join(REPO, "demo", "fixtures");
const PORT = Number(process.env.PORT ?? 8799);

// ---- load fixtures ----------------------------------------------------------
const evidence = JSON.parse(await readFile(join(FIX, "snp-evidence-genoa.json"), "utf8"));
const snpEvidence = evidence.evidence ?? evidence; // tolerate wrapped or bare
const meshCaPem = await readFile(join(FIX, "mesh-ca.crt"), "utf8");
const leafPem = await readFile(join(FIX, "cds-leaf.crt"), "utf8");
const leafKeyPem = await readFile(join(FIX, "cds-leaf.key"), "utf8");
// Bundle the leaf followed by the mesh CA so the client can chain leaf -> CA.
const cdsCertPem = leafPem.trim() + "\n" + meshCaPem.trim() + "\n";
const leafDer = decodePEM(leafPem, "CERTIFICATE")[0];
const caDer = decodePEM(meshCaPem, "CERTIFICATE")[0];

// ---- session state ----------------------------------------------------------
interface SessionEntry {
  channel: Channel;
  createdAt: number;
}
const sessions = new Map<string, SessionEntry>();
const TTL_MS = 5 * 60 * 1000;

function sweep(): void {
  const now = Date.now();
  for (const [k, v] of sessions) if (now - v.createdAt > TTL_MS) sessions.delete(k);
}

// ---- helpers ----------------------------------------------------------------
function json(res: ServerResponse, status: number, obj: unknown): void {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}
function text(res: ServerResponse, status: number, body: string, type = "text/plain"): void {
  res.writeHead(status, { "content-type": type });
  res.end(body);
}
function cbor(res: ServerResponse, status: number, obj: unknown): void {
  const body = Buffer.from(cborEncode(obj));
  res.writeHead(status, { "content-type": "application/cbor", "content-length": body.length });
  res.end(body);
}
async function readBodyBytes(req: IncomingMessage): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return new Uint8Array(Buffer.concat(chunks));
}
async function readBody(req: IncomingMessage): Promise<string> {
  return Buffer.from(await readBodyBytes(req)).toString("utf8");
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json",
};

async function serveStatic(res: ServerResponse, urlPath: string): Promise<void> {
  // Map "/" to the demo page; everything else resolves under the package root.
  const rel = urlPath === "/" ? "demo/index.html" : urlPath.replace(/^\/+/, "");
  const abs = normalize(join(REPO, rel));
  if (!abs.startsWith(REPO)) return text(res, 403, "forbidden"); // path traversal guard
  try {
    const data = await readFile(abs);
    res.writeHead(200, { "content-type": MIME[extname(abs)] ?? "application/octet-stream" });
    res.end(data);
  } catch {
    text(res, 404, "not found");
  }
}

// ---- request router ---------------------------------------------------------
const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  try {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const p = url.pathname;

    // The retired endpoint and its query selectors: an explicit 400, no alias
    // or downgrade — mirroring the real sidecar's post-cutover behavior.
    if (p === "/.well-known/c8s/attestation") {
      return json(res, 400, {
        error: "invalid_request",
        message: "the /attestation endpoint is retired; use /attest-pq",
      });
    }

    // The pre-client-first GET shape: an explicit 400, mirroring the sidecar.
    if (req.method === "GET" && p === "/.well-known/c8s/attest-pq") {
      return json(res, 400, {
        error: "invalid_request",
        message: "attest-pq is client-first: POST a JSON body with nonce and xwing_ek",
      });
    }

    if (req.method === "POST" && p === "/.well-known/c8s/attest-pq") {
      sweep();
      const body = JSON.parse(await readBody(req)) as { nonce?: string; xwing_ek?: string };
      if (typeof body.nonce !== "string" || typeof body.xwing_ek !== "string") {
        return json(res, 400, { error: "invalid_request", message: "missing nonce or xwing_ek" });
      }
      let nonce: Uint8Array;
      let xwingEk: Uint8Array;
      try {
        nonce = base64UrlToBytes(body.nonce);
        xwingEk = base64UrlToBytes(body.xwing_ek);
      } catch {
        return json(res, 400, { error: "invalid_request", message: "fields are not base64url" });
      }
      if (nonce.length !== NONCE_BYTES) {
        return json(res, 400, {
          error: "invalid_request",
          message: `nonce must be ${NONCE_BYTES} bytes, got ${nonce.length}`,
        });
      }
      if (xwingEk.length !== XWING_EK_BYTES) {
        return json(res, 400, {
          error: "invalid_request",
          message: `xwing_ek must be ${XWING_EK_BYTES} bytes, got ${xwingEk.length}`,
        });
      }

      // Encapsulate to the client's key and commit the whole exchange in the
      // transcript. A real LB asks the hardware to bind this transcript into
      // report_data; the recorded fixture cannot, so report_data_match is
      // always false against the mock.
      const { ct, sharedSecret } = await xwingEncapsulate(xwingEk);
      const sessionId = crypto.getRandomValues(new Uint8Array(16));
      // The mock LB fronts a cds deployment (TEST.md's real-sidecar demo
      // states webpki instead; attest-pq is served either way).
      const minted = await mintIdentityProof(
        "cds",
        xwingEk,
        ct,
        sessionId,
        nonce,
        leafDer,
        caDer,
        leafKeyPem,
      );
      const channel = await deriveChannel("server", sharedSecret, minted.transcript, sessionId);
      const sessionIdB64 = bytesToBase64Url(sessionId);
      sessions.set(sessionIdB64, { channel, createdAt: Date.now() });
      const bundle: Record<string, unknown> = {
        ...minted.bundleFields,
        platform: "snp",
        generation: "genoa",
        nonce: body.nonce,
        evidence: snpEvidence,
        cds_cert_pem: cdsCertPem,
        xwing_ek: body.xwing_ek,
        xwing_ct: bytesToBase64Url(ct),
        session_id: sessionIdB64,
      };
      return json(res, 200, bundle);
    }

    // The retired two-step handshake: an explicit 400, mirroring the sidecar.
    if (p === "/.well-known/c8s/handshake") {
      return json(res, 400, {
        error: "invalid_request",
        message: "the handshake endpoint is gone: attest-pq establishes the session in one POST",
      });
    }

    // Over-encryption termination: open the sealed request envelope, "forward"
    // to the backend (echo here), and seal the response back. A real LB forwards
    // the reconstructed plaintext request to the upstream over the raTLS mesh.
    if (req.method === "POST" && p === "/.well-known/c8s/tunnel") {
      const sid = req.headers["x-c8s-session"];
      const entry = typeof sid === "string" ? sessions.get(sid) : undefined;
      if (!entry) return json(res, 401, { error: "channel_error", message: "no session" });
      const channel = entry.channel;
      let record: WireRecord;
      try {
        record = cborDecode(await readBodyBytes(req)) as unknown as WireRecord;
      } catch {
        return json(res, 400, { error: "channel_error", message: "invalid record" });
      }
      let plaintext: Uint8Array;
      try {
        plaintext = await channel.openRequest(record);
      } catch {
        return json(res, 400, { error: "channel_error", message: "decrypt failed" });
      }
      const env = cborDecode(plaintext) as {
        method?: string;
        path?: string;
        headers?: CborValue;
        body?: Uint8Array;
      };
      const body = env.body ?? new Uint8Array(0);
      const reply = utf8ToBytes(
        `LB enclave received ${body.length} bytes over the over-encrypted channel for ` +
          `${env.method} ${env.path}: ${JSON.stringify(bytesToUtf8(body))}`,
      );
      // Echo the request's header pairs after content-type, so a client can
      // see its duplicate fields survive the round trip.
      const respEnv: Record<string, CborValue> = {
        status: 200,
        headers: [
          ["content-type", "text/plain; charset=utf-8"],
          ...(Array.isArray(env.headers) ? env.headers : []),
        ],
        body: reply,
      };
      const out = await channel.sealResponse(cborEncode(respEnv), record.seq);
      return cbor(res, 200, { seq: out.seq, ct: out.ct });
    }

    // Static demo assets (index.html, /dist/*, /wasm/*, /node_modules/*).
    if (req.method === "GET") return serveStatic(res, p);

    text(res, 405, "method not allowed");
  } catch (e) {
    json(res, 500, {
      error: "internal",
      message: String((e as { message?: unknown })?.message ?? e),
    });
  }
});

server.listen(PORT, () => {
  console.log(`mock C8s LB listening on http://localhost:${PORT}  (open this in a browser)`);
});
