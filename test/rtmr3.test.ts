import { test } from "node:test";
import assert from "node:assert/strict";

import { C8sVerifyError, type C8sErrorCode } from "../src/errors.js";
import { judgePolicyHistory, type LeafPolicy } from "../src/rtmr3.js";

const D1 = "sha256:" + "1".repeat(64);
const D2 = "sha256:" + "2".repeat(64);
const D3 = "sha256:" + "3".repeat(64);

const NO_LEAF: LeafPolicy = { kind: "none" };

test("judgePolicyHistory", () => {
  const cases: {
    name: string;
    history: string[];
    pins?: string[];
    leaf?: LeafPolicy;
    fresh?: boolean;
    wantNotProven?: RegExp[];
    wantCode?: C8sErrorCode;
    wantWarning?: boolean;
  }[] = [
    { name: "no pins, no history", history: [], wantNotProven: [] },
    {
      name: "no pins, history left unjudged",
      history: [D1, D2],
      wantNotProven: [/replayed 2 measured policies/],
      wantWarning: true,
    },
    {
      name: "no pins, stale history is unjudged once",
      history: [D1],
      fresh: false,
      wantNotProven: [/replayed 1 measured policies/],
      wantWarning: true,
    },
    { name: "pins, no history", history: [], pins: [D1], wantCode: "policy_history_absent" },
    {
      name: "pins, entry not pinned",
      history: [D1, D2],
      pins: [D1],
      wantCode: "policy_history_not_pinned",
    },
    { name: "pins cover the history", history: [D1, D2], pins: [D2, D1], wantNotProven: [] },
    {
      name: "pins, stale evidence",
      history: [D1],
      pins: [D1],
      fresh: false,
      wantNotProven: [/current policy history/],
    },
    {
      name: "pins, unstamped leaf",
      history: [D1],
      pins: [D1],
      leaf: { kind: "unstamped" },
      wantNotProven: [/no matched-workload stamp/],
    },
    {
      name: "pins, leaf issued under an unpinned policy",
      history: [D1],
      pins: [D1],
      leaf: { kind: "stamped", digest: D3, vouched: true },
      wantCode: "policy_history_not_pinned",
    },
    {
      name: "pins, leaf issued under a pinned policy outside the history",
      history: [D1],
      pins: [D1, D3],
      leaf: { kind: "stamped", digest: D3, vouched: true },
      wantNotProven: [],
    },
    {
      name: "pins, stamp no pinned CA vouches for, on stale evidence",
      history: [D1],
      pins: [D1],
      leaf: { kind: "stamped", digest: D1, vouched: false },
      fresh: false,
      wantNotProven: [/no pinned mesh CA/, /current policy history/],
    },
  ];
  for (const c of cases) {
    const warnings: string[] = [];
    const judge = (): string[] =>
      judgePolicyHistory(c.history, c.pins, c.leaf ?? NO_LEAF, c.fresh ?? true, warnings);
    if (c.wantCode !== undefined) {
      assert.throws(
        judge,
        (e: unknown) => e instanceof C8sVerifyError && e.code === c.wantCode,
        c.name,
      );
      continue;
    }
    const got = judge();
    assert.equal(
      got.length,
      c.wantNotProven!.length,
      `${c.name}: notProven ${JSON.stringify(got)}`,
    );
    c.wantNotProven!.forEach((re, i) => assert.match(got[i], re, c.name));
    assert.equal(
      warnings.some((w) => w.includes("none judged")),
      c.wantWarning === true,
      `${c.name}: warnings ${JSON.stringify(warnings)}`,
    );
  }
});
