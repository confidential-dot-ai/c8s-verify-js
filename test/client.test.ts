import { test } from "node:test";
import assert from "node:assert/strict";

import { C8sClient } from "../src/index.js";
import { C8sVerifyError } from "../src/errors.js";
import { DEMO_MEASUREMENTS } from "../demo/config.js";

// The constructor only checks presence of the pins, not their contents (parsing
// happens later in connect()), so any non-empty PEM-ish string is fine here.
const MESH_CA = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n";

test("new C8sClient throws without a measurement allowlist", () => {
  assert.throws(
    () => new C8sClient({ baseUrl: "https://lb.example", measurements: [], meshCaPem: MESH_CA }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
});

test("new C8sClient throws without a pinned mesh CA", () => {
  assert.throws(
    () =>
      new C8sClient({
        baseUrl: "https://lb.example",
        measurements: DEMO_MEASUREMENTS,
        meshCaPem: "",
      }),
    (e: unknown) => e instanceof C8sVerifyError && e.code === "invalid_request",
  );
});

test("new C8sClient constructs (fails closed) with both pins", () => {
  const c = new C8sClient({
    baseUrl: "https://lb.example",
    measurements: DEMO_MEASUREMENTS,
    meshCaPem: MESH_CA,
  });
  assert.equal(c.policy.measurements.length, 1);
  assert.equal(c.policy.allowAnyMeasurement, false);
  assert.equal(c.policy.allowUnpinnedMeshCa, false);
});

test("C8sClient.insecure waives both pins when neither is supplied", () => {
  const c = C8sClient.insecure({ baseUrl: "https://lb.example" });
  assert.equal(c.policy.allowAnyMeasurement, true);
  assert.equal(c.policy.allowUnpinnedMeshCa, true);
});

test("C8sClient.insecure still enforces a pin that is supplied", () => {
  const c = C8sClient.insecure({ baseUrl: "https://lb.example", measurements: DEMO_MEASUREMENTS });
  assert.equal(c.policy.allowAnyMeasurement, false); // measurement is still enforced
  assert.equal(c.policy.allowUnpinnedMeshCa, true); // mesh CA is waived
});
