// Browser demo: drives the c8s-verify library step by step against the mock LB,
// visualising each verification stage. Imports the library straight from source
// (no bundler) using the import map in index.html for the mlkem-wasm dependency.

import { generateNonce } from "/src/nonce.js";
import { verifyAttestation } from "/src/verify.js";
import { initVerifier } from "/src/wasm-loader.js";
import { clientKeyAgreement } from "/src/keyagreement.js";
import { Channel, requestAAD, responseAAD } from "/src/channel.js";
import { cborEncode, cborDecode } from "/src/cbor.js";
import {
  bytesToBase64Url,
  base64UrlToBytes,
  base64ToBytes,
  bytesToBase64,
  utf8ToBytes,
  bytesToUtf8,
} from "/src/base64.js";
import { DEMO_MEASUREMENTS, DEMO_REQUIRE_FRESHNESS } from "/demo/config.js";

const stepsEl = document.getElementById("steps");
const runBtn = document.getElementById("run");
const tamperEl = document.getElementById("tamper");

const STEPS = [
  ["nonce", "Generate a fresh random nonce"],
  ["fetch", "Fetch attestation bundle from the LB"],
  ["wasm", "Verify SEV-SNP hardware evidence (WASM)"],
  ["measure", "Check launch measurement against allowlist"],
  ["binding", "Bind session key + nonce (freshness)"],
  ["cert", "Verify CDS certificate chains to mesh CA"],
  ["handshake", "PQ hybrid key agreement (X25519 + ML-KEM-768)"],
  ["echo", "Send an over-encrypted request"],
];

/** @type {Record<string, HTMLElement>} */
const nodes = {};
function render() {
  stepsEl.innerHTML = "";
  for (const [id, title] of STEPS) {
    const el = document.createElement("div");
    el.className = "step pending";
    el.innerHTML = `<div class="row"><span class="icon">○</span><span class="title">${title}</span></div><div class="detail"></div>`;
    stepsEl.appendChild(el);
    nodes[id] = el;
  }
}
function set(id, state, detail) {
  const el = nodes[id];
  el.className = `step ${state}`;
  const icon = { run: "◌", ok: "✓", bad: "✗", warn: "⚠" }[state] ?? "○";
  el.querySelector(".icon").textContent = icon;
  if (detail !== undefined) el.querySelector(".detail").textContent = detail;
}

const BASE = location.origin;
const PREFIX = "/.well-known/c8s";

async function fetchPinnedMeshCa() {
  // Out-of-band trust anchor: in production the operator ships you the mesh CA.
  const res = await fetch("/demo/fixtures/mesh-ca.crt");
  return res.text();
}

async function run() {
  render();
  runBtn.disabled = true;
  const tamper = tamperEl.checked;
  try {
    await initVerifier();

    // 1. nonce
    set("nonce", "run");
    const nonce = generateNonce();
    set("nonce", "ok", `nonce = ${bytesToBase64Url(nonce)}`);

    // 2. fetch bundle
    set("fetch", "run");
    const bundleRes = await fetch(`${PREFIX}/attestation?nonce=${bytesToBase64Url(nonce)}`, {
      headers: { accept: "application/json" },
    });
    if (!bundleRes.ok) throw new Error(`HTTP ${bundleRes.status}`);
    const bundle = await bundleRes.json();
    set(
      "fetch",
      "ok",
      `platform=${bundle.platform} generation=${bundle.generation}\n` +
        `evidence report ${base64ToBytes(bundle.evidence.attestation_report).length} bytes, ` +
        `vcek ${base64ToBytes(bundle.evidence.cert_chain.vcek).length} bytes`,
    );

    if (tamper) {
      // Flip one byte of the signed report — the hardware signature must now fail.
      const rep = base64ToBytes(bundle.evidence.attestation_report);
      rep[200] ^= 0x01;
      bundle.evidence.attestation_report = bytesToBase64(rep);
    }

    const pinnedCa = await fetchPinnedMeshCa();

    // 3–6: verifyAttestation runs WASM verify + measurement + binding + cert chain.
    // We surface the sub-results by inspecting the returned object / thrown error.
    set("wasm", "run");
    let result;
    try {
      result = await verifyAttestation(bundle, nonce, {
        measurements: DEMO_MEASUREMENTS,
        requireFreshness: DEMO_REQUIRE_FRESHNESS,
        meshCaPem: pinnedCa,
      });
    } catch (e) {
      // Attribute the failure to the right step.
      const code = e.code ?? "verification_failed";
      if (code === "verification_failed") set("wasm", "bad", `✗ ${e.message}`);
      else if (code === "measurement_denied") { set("wasm", "ok", "signature OK"); set("measure", "bad", `✗ ${e.message}`); }
      else if (code === "report_data_mismatch") { set("wasm", "ok"); set("measure", "ok"); set("binding", "bad", `✗ ${e.message}`); }
      else if (code === "nonce_mismatch") set("fetch", "bad", `✗ ${e.message}`);
      else if (code.includes("cert")) { set("wasm","ok"); set("measure","ok"); set("cert", "bad", `✗ ${e.message}`); }
      throw e;
    }

    set("wasm", "ok", `signature_valid=true · report v${result.reportVersion} · platform=${result.platform}`);
    set("measure", "ok", `launch_digest ∈ allowlist\n${result.measurement}`);

    if (result.reportDataMatch === true) {
      set("binding", "ok", "report_data = SHA-384(session_pubkey ‖ nonce) ✓ live-bound");
    } else {
      set(
        "binding",
        "warn",
        "report_data not bound to this session (recorded fixture).\n" +
          "A live TEE LB binds SHA-384(session_pubkey ‖ nonce); signature + measurement are still real.",
      );
    }

    set(
      "cert",
      "ok",
      `leaf CN=${result.cert.subjectCN}  issuer CN=${result.cert.issuerCN}\n` +
        `leaf sha256=${result.cert.sha256.slice(0, 32)}…\n` +
        `mesh-CA sha256=${result.cert.caSha256.slice(0, 32)}… (pinned)`,
    );

    // 7. handshake
    set("handshake", "run");
    const { key, handshake } = await clientKeyAgreement(result.sessionPubKey, nonce);
    const hsRes = await fetch(`${PREFIX}/handshake`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: bytesToBase64Url(nonce),
        client_x25519: bytesToBase64Url(handshake.clientX25519),
        mlkem_ct: bytesToBase64Url(handshake.mlkemCiphertext),
      }),
    });
    const { session_id } = await hsRes.json();
    const channel = new Channel(key);
    set(
      "handshake",
      "ok",
      `ML-KEM-768 ct ${handshake.mlkemCiphertext.length}B + X25519 ${handshake.clientX25519.length}B\n` +
        `→ HKDF-SHA256 → AES-256-GCM · session ${session_id.slice(0, 16)}…`,
    );

    // 8. over-encrypted request through the tunnel (full request envelope sealed).
    // The transport is CBOR end to end (record and envelope), matching the
    // library's Session.fetch and the mock LB: raw byte bodies, no base64/JSON.
    set("echo", "run");
    const msg = "hello from a browser that verified the enclave 🛡️";
    const envelope = {
      method: "POST",
      path: "/v1/echo",
      headers: { "content-type": "text/plain" },
      body: utf8ToBytes(msg),
    };
    const rec = await channel.seal(cborEncode(envelope), requestAAD());
    const echoRes = await fetch(`${PREFIX}/tunnel`, {
      method: "POST",
      headers: { "content-type": "application/cbor", "x-c8s-session": session_id },
      body: cborEncode(rec),
    });
    if (!echoRes.ok) throw new Error(`tunnel returned HTTP ${echoRes.status}`);
    const respRec = cborDecode(new Uint8Array(await echoRes.arrayBuffer()));
    const respEnv = cborDecode(await channel.open(respRec, responseAAD()));
    const plain = bytesToUtf8(respEnv.body ?? new Uint8Array(0));
    set("echo", "ok", `sent (sealed envelope): ${JSON.stringify(msg)}\nrecv (opened): ${plain}`);
  } catch (e) {
    // Steps already mark themselves; mark any still-pending as not-reached.
    for (const [id] of STEPS) {
      if (nodes[id].classList.contains("pending") || nodes[id].classList.contains("run")) {
        set(id, nodes[id].classList.contains("run") ? "bad" : "pending");
      }
    }
    console.error(e);
  } finally {
    runBtn.disabled = false;
  }
}

render();
runBtn.addEventListener("click", run);
