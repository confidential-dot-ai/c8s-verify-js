import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { C8sClient } from "../src/index.js";
import { DEMO_MEASUREMENTS, DEMO_REQUIRE_FRESHNESS } from "../demo/config.js";

// Run from source via tsx; the repo root is one directory up (test/ -> root),
// and the mock LB server is a TypeScript source run through the tsx loader.
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Start the mock LB on an ephemeral port; resolve once it logs readiness. */
function startServer(port: number): Promise<ChildProcess> {
  const child = spawn(process.execPath, ["--import", "tsx", join(ROOT, "demo", "server.ts")], {
    env: { ...process.env, PORT: String(port) },
    stdio: ["ignore", "pipe", "inherit"],
  });
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("server did not start in time")), 8000);
    child.stdout?.on("data", (d: Buffer) => {
      if (d.toString().includes("listening")) {
        clearTimeout(t);
        resolve(child);
      }
    });
    child.on("exit", (code) => reject(new Error(`server exited early (${code})`)));
  });
}

test("end-to-end: connect, verify, and over-encrypted echo", async () => {
  const port = 8900 + Math.floor(Math.random() * 200);
  const server = await startServer(port);
  try {
    const client = new C8sClient({
      baseUrl: `http://localhost:${port}`,
      measurements: DEMO_MEASUREMENTS,
      requireFreshness: DEMO_REQUIRE_FRESHNESS,
      requireClusterIdentity: false,
    });
    const session = await client.connect();
    assert.equal(session.attestation.platform, "snp");
    assert.equal(session.attestation.measurement, DEMO_MEASUREMENTS[0]);
    assert.equal(session.attestation.cert!.subjectCN, "lb.demo.c8s.local");

    const msg = "round-trip over the post-quantum channel";
    const res = await session.fetch("/v1/echo", { method: "POST", body: msg });
    assert.equal(res.status, 200);
    assert.match(res.text(), /over-encrypted channel/);
    assert.ok(res.text().includes(JSON.stringify(msg)));
  } finally {
    server.kill();
  }
});
