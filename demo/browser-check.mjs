// Standalone headless-browser smoke test (run via `node test/browser-check.mjs`).
// Kept out of `node --test` so the unit suite has no browser dependency.
// Launches the mock LB, drives the real demo page in Chromium, and asserts the
// verification steps reach their expected states — proving the library runs in a
// browser (WebCrypto X25519 + ML-KEM-768 WASM + attestation-rs WASM).

import { spawn } from "node:child_process";
import { chromium } from "playwright";

const PORT = 8855;

function startServer() {
  const child = spawn(process.execPath, ["demo/server.js"], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: ["ignore", "pipe", "inherit"],
  });
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("server timeout")), 8000);
    child.stdout.on("data", (d) => {
      if (d.toString().includes("listening")) { clearTimeout(t); resolve(child); }
    });
  });
}

const stepState = (page, id) =>
  page.$eval(`#steps .step:nth-child(${id})`, (el) => {
    for (const s of ["ok", "bad", "warn", "run", "pending"]) if (el.classList.contains(s)) return s;
    return "?";
  });

// step indices (1-based) in demo.js order
const STEP = { nonce: 1, fetch: 2, wasm: 3, measure: 4, binding: 5, cert: 6, handshake: 7, echo: 8 };

async function runOnce(page, { tamper }) {
  if (tamper) await page.check("#tamper");
  else await page.uncheck("#tamper");
  await page.click("#run");
  // Wait until the run button re-enables (flow finished).
  await page.waitForFunction(() => !document.getElementById("run").disabled, null, { timeout: 20000 });
  const states = {};
  for (const [k, i] of Object.entries(STEP)) states[k] = await stepState(page, i);
  return states;
}

const server = await startServer();
let failures = 0;
const expect = (cond, msg) => { if (!cond) { failures++; console.error("  ✗", msg); } else console.log("  ✓", msg); };

try {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  page.on("console", (m) => { if (m.type() === "error") console.error("   [browser]", m.text()); });
  await page.goto(`http://localhost:${PORT}/`, { waitUntil: "load" });

  console.log("happy path:");
  const ok = await runOnce(page, { tamper: false });
  console.log("   states:", JSON.stringify(ok));
  expect(ok.nonce === "ok", "nonce generated");
  expect(ok.fetch === "ok", "attestation fetched");
  expect(ok.wasm === "ok", "SNP evidence verified in WASM");
  expect(ok.measure === "ok", "measurement in allowlist");
  expect(ok.binding === "warn", "freshness shown as warning (recorded fixture)");
  expect(ok.cert === "ok", "CDS cert chains to pinned mesh CA");
  expect(ok.handshake === "ok", "PQ hybrid handshake completed");
  expect(ok.echo === "ok", "over-encrypted echo round-tripped");

  console.log("tamper path:");
  const bad = await runOnce(page, { tamper: true });
  console.log("   states:", JSON.stringify(bad));
  expect(bad.wasm === "bad", "tampered evidence fails WASM verification (fail-closed)");
  expect(bad.echo !== "ok", "no channel established after failed verification");

  await browser.close();
} finally {
  server.kill();
}

if (failures) { console.error(`\n${failures} browser assertion(s) failed`); process.exit(1); }
console.log("\nbrowser smoke test passed");
