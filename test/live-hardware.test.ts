import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifyEvidence } from "../src/verify.js";
import { C8sVerifyError } from "../src/errors.js";
import type { Evidence } from "../src/hcl.js";

// Evidence captured from REAL Azure confidential VMs (2026-07, this box's QA
// session), not the checked-in recorded fixtures:
//   - live-az-snp.json: a Standard_DC4as_v5 (AMD SEV-SNP) CVM.
//   - live-az-tdx.json: a Standard_DC4es_v6 (Intel TDX) CVM.
// Each was produced by attestation-cli on the node's vTPM with a known
// report_data anchor (SHA-384 of the label below), so the browser verifier's
// report_data binding and MRTD/launch-digest surfacing can be checked against
// genuine hardware output — and fail closed on a wrong anchor. The MRTD differs
// from the recorded az-tdx-evidence.json fixture, proving the path works on
// fresh hardware rather than one captured bundle.
const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

const sha384 = async (s: string) =>
  new Uint8Array(await crypto.subtle.digest("SHA-384", new TextEncoder().encode(s)));

async function inner(file: string): Promise<Evidence> {
  return JSON.parse(await readFile(join(FIX, file), "utf8")).evidence as Evidence;
}

const CASES = [
  {
    name: "az-snp",
    file: "live-az-snp.json",
    label: "c8s-qa-live-snp",
    measurement:
      "5b0ce64ad1c1f6375dbda5f760b98526ca1bcf91b8195091afc28e7b024251d68fe32e05af34048d6607678cd23283ff",
  },
  {
    name: "az-tdx",
    file: "live-az-tdx.json",
    label: "c8s-qa-live-tdx",
    measurement:
      "c9a7fb6dd0d9a2b1ca401c71b63a1041dfbac84a48c7e65bf76f21ca0492b63003d8b40ee2d0bf0c6ae1db3981e9eb17",
  },
] as const;

for (const c of CASES) {
  test(`verifyEvidence verifies LIVE ${c.name} hardware evidence and pins its measurement`, async () => {
    const anchor = await sha384(c.label);
    const r = await verifyEvidence(await inner(c.file), {
      platform: c.name,
      measurements: [c.measurement],
      expectedReportData: anchor,
    });
    assert.equal(r.ok, true);
    assert.equal(r.platform, c.name);
    assert.equal(r.measurement, c.measurement);
    assert.equal(r.reportDataMatch, true, "the bound report_data must match the live anchor");
  });

  test(`verifyEvidence fails closed on a wrong measurement for LIVE ${c.name}`, async () => {
    const anchor = await sha384(c.label);
    await assert.rejects(
      verifyEvidence(await inner(c.file), {
        platform: c.name,
        measurements: ["00".repeat(48)],
        expectedReportData: anchor,
      }),
      (e: unknown) => e instanceof C8sVerifyError && e.code === "measurement_denied",
    );
  });

  test(`verifyEvidence fails closed on a wrong report_data for LIVE ${c.name}`, async () => {
    await assert.rejects(
      verifyEvidence(await inner(c.file), {
        platform: c.name,
        measurements: [c.measurement],
        expectedReportData: new Uint8Array(48),
      }),
    );
  });

  test(`verifyEvidence fails closed on platform confusion for LIVE ${c.name}`, async () => {
    const other = c.name === "az-snp" ? "az-tdx" : "az-snp";
    const anchor = await sha384(c.label);
    await assert.rejects(
      verifyEvidence(await inner(c.file), {
        platform: other,
        measurements: [c.measurement],
        expectedReportData: anchor,
      }),
    );
  });
}
