// Mock C8s Load Balancer for the demo. Implements c8s-verify/v1 (see
// ../PROTOCOL.md) so the browser library can run the full flow offline.
//
// TEST/DEMO ONLY. It mirrors c8s's own test/mock-cds: it serves REAL recorded
// SNP hardware evidence (verified for real by the WASM verifier) but does not run
// inside a TEE, so it cannot bind a live session key into a fresh hardware report.
// Everything else — the PQ hybrid handshake, the mesh identity proof, and the
// AES-256-GCM over-encryption channel — is real. Because the recorded report_data
// can never match a fresh transcript, the demo explicitly disables freshness.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";
import { Buffer } from "node:buffer";

import {
  generateServerHybridKey,
  serverKeyAgreement,
  type ServerKeys,
} from "../src/keyagreement.js";
import { Channel, requestAAD, responseAAD, type WireRecord } from "../src/channel.js";
import { cborEncode, cborDecode, type CborValue } from "../src/cbor.js";
import { bytesToBase64Url, base64UrlToBytes, utf8ToBytes, bytesToUtf8 } from "../src/base64.js";
import { decodePEM } from "../src/pem.js";
import { NONCE_BYTES } from "../src/nonce.js";
import { mintIdentityProof } from "./mint-identity.js";

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
interface PendingEntry {
  priv: ServerKeys;
  transcript: Uint8Array;
  createdAt: number;
}
const pending = new Map<string, PendingEntry>();
const sessions = new Map<string, Channel>();
const TTL_MS = 5 * 60 * 1000;

function sweep(): void {
  const now = Date.now();
  for (const [k, v] of pending) if (now - v.createdAt > TTL_MS) pending.delete(k);
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

    if (req.method === "GET" && p === "/.well-known/c8s/attestation") {
      sweep();
      const nonceB64 = url.searchParams.get("nonce");
      if (!nonceB64) return json(res, 400, { error: "invalid_request", message: "missing nonce" });
      let nonce: Uint8Array;
      try {
        nonce = base64UrlToBytes(nonceB64);
      } catch {
        return json(res, 400, { error: "invalid_request", message: "nonce is not base64url" });
      }
      if (nonce.length !== NONCE_BYTES) {
        return json(res, 400, {
          error: "invalid_request",
          message: `nonce must be ${NONCE_BYTES} bytes`,
        });
      }

      // Fresh per-session hybrid key. A real LB asks the hardware to bind this
      // identity transcript into report_data; the recorded fixture cannot, so
      // report_data_match is always false against the mock.
      const { priv, pub } = await generateServerHybridKey();
      const minted = await mintIdentityProof(pub, nonce, leafDer, caDer, leafKeyPem);
      const bundle: Record<string, unknown> = {
        ...minted.bundleFields,
        platform: "snp",
        generation: "genoa",
        nonce: nonceB64,
        evidence: snpEvidence,
        cds_cert_pem: cdsCertPem,
        session_pubkey: {
          x25519: bytesToBase64Url(pub.x25519),
          mlkem768: bytesToBase64Url(pub.mlkem768),
        },
      };
      pending.set(nonceB64, { priv, transcript: minted.transcript, createdAt: Date.now() });
      return json(res, 200, bundle);
    }

    if (req.method === "POST" && p === "/.well-known/c8s/handshake") {
      const body = JSON.parse(await readBody(req));
      const entry = pending.get(body.nonce);
      if (!entry)
        return json(res, 400, { error: "invalid_request", message: "unknown or expired nonce" });
      pending.delete(body.nonce);
      const key = await serverKeyAgreement(
        entry.priv,
        {
          clientX25519: base64UrlToBytes(body.client_x25519),
          mlkemCiphertext: base64UrlToBytes(body.mlkem_ct),
        },
        entry.transcript,
      );
      const sessionId = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(16)));
      sessions.set(sessionId, new Channel(key));
      return json(res, 200, { session_id: sessionId });
    }

    // Over-encryption termination: open the sealed request envelope, "forward"
    // to the backend (echo here), and seal the response back. A real LB forwards
    // the reconstructed plaintext request to the upstream over the raTLS mesh.
    if (req.method === "POST" && p === "/.well-known/c8s/tunnel") {
      const sid = req.headers["x-c8s-session"];
      const channel = typeof sid === "string" ? sessions.get(sid) : undefined;
      if (!channel) return json(res, 401, { error: "channel_error", message: "no session" });
      let record: WireRecord;
      try {
        record = cborDecode(await readBodyBytes(req)) as unknown as WireRecord;
      } catch {
        return json(res, 400, { error: "channel_error", message: "invalid record" });
      }
      let plaintext: Uint8Array;
      try {
        plaintext = await channel.open(record, requestAAD());
      } catch {
        return json(res, 400, { error: "channel_error", message: "decrypt failed" });
      }
      const env = cborDecode(plaintext) as {
        method?: string;
        path?: string;
        body?: Uint8Array;
      };
      const body = env.body ?? new Uint8Array(0);
      const reply = utf8ToBytes(
        `LB enclave received ${body.length} bytes over the over-encrypted channel for ` +
          `${env.method} ${env.path}: ${JSON.stringify(bytesToUtf8(body))}`,
      );
      const respEnv: Record<string, CborValue> = {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
        body: reply,
      };
      const out = await channel.seal(cborEncode(respEnv), responseAAD());
      return cbor(res, 200, out);
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
