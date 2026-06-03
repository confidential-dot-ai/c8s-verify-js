// Mock C8s Load Balancer for the demo. Implements the c8s-verify/v1 contract
// (see ../PROTOCOL.md) so the browser library can run the full flow offline.
//
// TEST/DEMO ONLY. It mirrors c8s's own test/mock-cds: it serves REAL recorded
// SNP hardware evidence (verified for real by the WASM verifier) but does not run
// inside a TEE, so it cannot bind a live session key into a fresh hardware report.
// Everything else — the PQ hybrid handshake and the AES-256-GCM over-encryption
// channel — is real.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";

import {
  generateServerHybridKey,
  serverKeyAgreement,
} from "../src/keyagreement.js";
import { Channel, requestAAD, responseAAD } from "../src/channel.js";
import {
  bytesToBase64Url,
  base64UrlToBytes,
  bytesToBase64,
  base64ToBytes,
  utf8ToBytes,
  bytesToUtf8,
} from "../src/base64.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, ".."); // package root, served statically
const FIX = join(__dirname, "fixtures");
const PORT = Number(process.env.PORT ?? 8799);

// ---- load fixtures ----------------------------------------------------------
const evidence = JSON.parse(await readFile(join(FIX, "snp-evidence-genoa.json"), "utf8"));
const snpEvidence = evidence.evidence ?? evidence; // tolerate wrapped or bare
const meshCaPem = await readFile(join(FIX, "mesh-ca.crt"), "utf8");
const leafPem = await readFile(join(FIX, "cds-leaf.crt"), "utf8");
// Serve the leaf followed by the mesh CA so the client can chain leaf -> CA.
const cdsCertPem = leafPem.trim() + "\n" + meshCaPem.trim() + "\n";

// ---- session state ----------------------------------------------------------
/** nonce(b64url) -> { priv, pub, createdAt } */
const pending = new Map();
/** sessionId -> Channel */
const sessions = new Map();
const TTL_MS = 5 * 60 * 1000;

function sweep() {
  const now = Date.now();
  for (const [k, v] of pending) if (now - v.createdAt > TTL_MS) pending.delete(k);
}

// ---- helpers ----------------------------------------------------------------
function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  res.end(body);
}
function text(res, status, body, type = "text/plain") {
  res.writeHead(status, { "content-type": type });
  res.end(body);
}
async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json",
};

async function serveStatic(res, urlPath) {
  // Map "/" to the demo page; everything else resolves under the package root.
  const rel = urlPath === "/" ? "demo/index.html" : urlPath.replace(/^\/+/, "");
  const abs = normalize(join(ROOT, rel));
  if (!abs.startsWith(ROOT)) return text(res, 403, "forbidden"); // path traversal guard
  try {
    const data = await readFile(abs);
    res.writeHead(200, { "content-type": MIME[extname(abs)] ?? "application/octet-stream" });
    res.end(data);
  } catch {
    text(res, 404, "not found");
  }
}

// ---- request router ---------------------------------------------------------
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const p = url.pathname;

    if (req.method === "GET" && p === "/.well-known/c8s/cds-cert.pem") {
      return text(res, 200, cdsCertPem, "application/x-pem-file");
    }

    if (req.method === "GET" && p === "/.well-known/c8s/attestation") {
      sweep();
      const nonceB64 = url.searchParams.get("nonce");
      if (!nonceB64) return json(res, 400, { error: "invalid_request", message: "missing nonce" });
      // Fresh per-session hybrid key. A real LB would also ask the hardware to
      // bind SHA-384(pub||nonce) into report_data; the recorded fixture cannot.
      const { priv, pub } = await generateServerHybridKey();
      pending.set(nonceB64, { priv, pub, createdAt: Date.now() });
      return json(res, 200, {
        version: "c8s-verify/v1",
        platform: "snp",
        generation: "genoa",
        nonce: nonceB64,
        evidence: snpEvidence,
        cds_cert_pem: cdsCertPem,
        session_pubkey: {
          x25519: bytesToBase64Url(pub.x25519),
          mlkem768: bytesToBase64Url(pub.mlkem768),
        },
      });
    }

    if (req.method === "POST" && p === "/.well-known/c8s/handshake") {
      const body = JSON.parse(await readBody(req));
      const entry = pending.get(body.nonce);
      if (!entry) return json(res, 400, { error: "invalid_request", message: "unknown or expired nonce" });
      pending.delete(body.nonce);
      const nonce = base64UrlToBytes(body.nonce);
      const key = await serverKeyAgreement(
        entry.priv,
        {
          clientX25519: base64UrlToBytes(body.client_x25519),
          mlkemCiphertext: base64UrlToBytes(body.mlkem_ct),
        },
        nonce,
      );
      const sessionId = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(16)));
      sessions.set(sessionId, new Channel(key));
      return json(res, 200, { session_id: sessionId });
    }

    // Over-encryption termination: open the sealed request envelope, "forward"
    // to the backend (echo here), and seal the response back. A real LB forwards
    // the reconstructed plaintext request to the upstream over the raTLS mesh.
    if (req.method === "POST" && p === "/.well-known/c8s/tunnel") {
      const channel = sessions.get(req.headers["x-c8s-session"]);
      if (!channel) return json(res, 401, { error: "channel_error", message: "no session" });
      const record = JSON.parse(await readBody(req));
      let plaintext;
      try {
        plaintext = await channel.open(record, requestAAD());
      } catch {
        return json(res, 400, { error: "channel_error", message: "decrypt failed" });
      }
      const env = JSON.parse(bytesToUtf8(plaintext));
      const body = env.body_b64 ? base64ToBytes(env.body_b64) : new Uint8Array(0);
      const reply = utf8ToBytes(
        `LB enclave received ${body.length} bytes over the over-encrypted channel for ` +
          `${env.method} ${env.path}: ${JSON.stringify(bytesToUtf8(body))}`,
      );
      const respEnv = {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
        body_b64: bytesToBase64(reply),
      };
      const out = await channel.seal(utf8ToBytes(JSON.stringify(respEnv)), responseAAD());
      return json(res, 200, out);
    }

    // Static demo assets (index.html, /src/*, /wasm/*, /node_modules/*).
    if (req.method === "GET") return serveStatic(res, p);

    text(res, 405, "method not allowed");
  } catch (e) {
    json(res, 500, { error: "internal", message: String(e?.message ?? e) });
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`mock C8s LB listening on http://localhost:${PORT}  (open this in a browser)`);
});
