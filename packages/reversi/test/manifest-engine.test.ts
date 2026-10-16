import { describe, expect, it } from "vitest";
import { Ledger, Registry, Reversi, SealedScope, expectMismatch, renderIdempotencyKey } from "../src/index.js";

const MANIFESTS = [
  {
    tool: "pay.create",
    effect: "compensable",
    permission: "p",
    idempotency: { key: "{{args.order_id}}:{{args.amount}}", scope: "run" },
    compensation: {
      tool: "pay.cancel",
      kind: "compensation",
      residue: ["customer may see a notification"],
      argument_map: { id: "$result.id" },
      verification: { tool: "pay.get", arguments: { id: "$result.id", order: "$args.order_id" }, expect: { status: "canceled", "meta.reason": "customer" }, retries: 3, backoff_ms: 10 },
    },
  },
  { tool: "pay.cancel", effect: "idempotent", permission: "p" },
  { tool: "pay.get", effect: "read_only", permission: "p" },
  { tool: "global.once", effect: "idempotent", permission: "p", idempotency: { key: "{{args.k}}", scope: "global" } },
  { tool: "actor.once", effect: "idempotent", permission: "p", idempotency: { key: "{{args.k}}", scope: "actor" } },
  { tool: "wip", effect: "read_only", permission: "p", status: "draft" },
  { tool: "old", effect: "read_only", permission: "p", status: "deprecated", replaced_by: "new" },
  { tool: "new", effect: "read_only", permission: "p" },
];

function make() {
  const rv = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger() });
  const run = (id = "r1", actor = "agent") => rv.startRun({ run_id: id, actor, scope: SealedScope.seal(["p"]) });
  return { rv, run };
}
const ok = (v: unknown = { id: "pi_1" }) => () => v;

describe("manifest status", () => {
  it("blocks calls to a draft manifest and notes a deprecated one", async () => {
    const { rv, run } = make();
    const r = run();
    expect(await r.call({ tool: "wip", reason: "x", execute: ok() })).toMatchObject({ status: "blocked", reasons: [expect.stringContaining("is a draft")] });
    expect((await r.call({ tool: "old", reason: "x", execute: ok() })).status).toBe("executed");
    expect(rv.ledger.records().find((x) => x.event === "intended")?.detail).toBe("manifest deprecated; use new");
  });
});

describe("idempotency keys", () => {
  it("renders templates and refuses missing or non-scalar values", () => {
    expect(renderIdempotencyKey("{{args.a}}-{{ args.b.c }}", { a: 1, b: { c: "x" } })).toBe("1-x");
    expect(renderIdempotencyKey("{{args.a}}", {})).toBeUndefined();
    expect(renderIdempotencyKey("{{args.a}}", { a: { n: 1 } })).toBeUndefined();
    expect(renderIdempotencyKey("{{args.a}}", null)).toBeUndefined();
  });

  it("blocks a duplicate in the same run while the first still stands, but allows it after the first failed or was undone", async () => {
    const { run } = make();
    const r = run();
    const args = { order_id: "o1", amount: 5 };
    expect((await r.call({ tool: "pay.create", args, reason: "x", execute: ok() })).status).toBe("executed");
    const dup = await r.call({ tool: "pay.create", args, reason: "x", execute: ok() });
    expect(dup).toMatchObject({ status: "blocked", reasons: [expect.stringContaining("duplicate call: idempotency key matches step 0")] });
    expect((await r.call({ tool: "pay.create", args: { order_id: "o1", amount: 6 }, reason: "x", execute: ok() })).status).toBe("executed"); // different key
    // a failed first attempt does not count
    const r2 = run("r2");
    await r2.call({ tool: "pay.create", args, reason: "x", execute: () => { throw new Error("nope"); } }).catch(() => {});
    expect((await r2.call({ tool: "pay.create", args, reason: "x", execute: ok() })).status).toBe("executed");
  });

  it("treats an in-flight call as a duplicate", async () => {
    const { run } = make();
    const r = run();
    const first = await r.begin({ tool: "pay.create", args: { order_id: "o", amount: 1 }, reason: "x" });
    expect(first.decision).toBe("allow");
    const second = await r.begin({ tool: "pay.create", args: { order_id: "o", amount: 1 }, reason: "x" });
    expect(second).toMatchObject({ decision: "block", reasons: [expect.stringContaining("still in flight")] });
  });

  it("blocks a call whose key cannot be rendered", async () => {
    const { run } = make();
    const r = await run().call({ tool: "pay.create", args: { order_id: "o" }, reason: "x", execute: ok() });
    expect(r).toMatchObject({ status: "blocked", reasons: [expect.stringContaining("missing or not simple values")] });
  });

  it("actor scope spans that actor's runs only; global spans everyone", async () => {
    const { run } = make();
    const a1 = run("a1", "alice");
    const a2 = run("a2", "alice");
    const b1 = run("b1", "bob");
    await a1.call({ tool: "actor.once", args: { k: "x" }, reason: "x", execute: ok() });
    expect((await a2.call({ tool: "actor.once", args: { k: "x" }, reason: "x", execute: ok() })).status).toBe("blocked");
    expect((await b1.call({ tool: "actor.once", args: { k: "x" }, reason: "x", execute: ok() })).status).toBe("executed");
    await a1.call({ tool: "global.once", args: { k: "g" }, reason: "x", execute: ok() });
    expect((await b1.call({ tool: "global.once", args: { k: "g" }, reason: "x", execute: ok() })).status).toBe("blocked");
  });
});

describe("compensation metadata and verification", () => {
  const args = { order_id: "o1", amount: 5 };

  it("the plan shows residue, kind and that the undo is verified; results are referenced by hash", async () => {
    const { run } = make();
    const r = run();
    await r.call({ tool: "pay.create", args, reason: "x", execute: ok() });
    expect(r.plan().actions[0]).toMatchObject({ kind: "compensate", residue: ["customer may see a notification"], compensation_kind: "compensation", verified: true });
    const s = r.state().steps[0];
    expect(s?.result_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(s?.verification).toMatchObject({ tool: "pay.get", args: { id: "pi_1", order: "o1" }, missing: [] });
  });

  it("verifies the undo by reading back, retrying with backoff until the state matches", async () => {
    const { rv, run } = make();
    const r = run();
    await r.call({ tool: "pay.create", args, reason: "x", execute: ok() });
    const calls: unknown[] = [];
    const sleeps: number[] = [];
    let n = 0;
    const rep = await r.rollback({
      compensate: () => {},
      retry: { sleep: async (ms) => void sleeps.push(ms) },
      verifier: (tool, a) => {
        calls.push([tool, a]);
        return ++n < 3 ? { status: "pending" } : { status: "canceled", meta: { reason: "customer" } };
      },
    });
    expect(rep).toMatchObject({ complete: true, compensated: [0], unverified: [] });
    expect(calls).toHaveLength(3);
    expect(calls[0]).toEqual(["pay.get", { id: "pi_1", order: "o1" }]);
    expect(sleeps).toEqual([10, 20]);
    expect(rv.ledger.records().map((x) => x.event).slice(-3)).toEqual(["compensating", "verified", "compensated"]);
  });

  it("a verification that never matches fails the compensation and is never reported complete", async () => {
    const { rv, run } = make();
    const r = run();
    await r.call({ tool: "pay.create", args, reason: "x", execute: ok() });
    const rep = await r.rollback({ compensate: () => {}, retry: { sleep: async () => {} }, verifier: () => ({ status: "succeeded" }) });
    expect(rep.complete).toBe(false);
    expect(rep.failed[0]?.error).toContain("verification failed");
    expect(r.state().steps[0]?.status).toBe("compensation_failed");
    const ev = rv.ledger.records().find((x) => x.event === "verification_failed");
    expect(ev?.detail).toContain("after 3 attempts");
    expect(ev?.detail).toContain("`status` is \"succeeded\", expected \"canceled\"");
  });

  it("without a verifier the step is compensated but reported unverified, and the rollback is incomplete", async () => {
    const { rv, run } = make();
    const r = run();
    await r.call({ tool: "pay.create", args, reason: "x", execute: ok() });
    const rep = await r.rollback({ compensate: () => {} });
    expect(rep).toMatchObject({ compensated: [0], unverified: [0], complete: false });
    expect(rv.ledger.records().some((x) => x.event === "unverified")).toBe(true);
  });

  it("when the verification's arguments are missing it says so instead of skipping", async () => {
    const { run } = make();
    const r = run();
    await r.call({ tool: "pay.create", args, reason: "x", execute: ok({ no_id: true }) }); // result has no `id`
    const plan = r.plan();
    expect(plan.actions[0]).toMatchObject({ kind: "unrecoverable" }); // compensation args missing too
    expect(r.state().steps[0]?.verification?.missing).toContain("id");
  });

  it("an invalid result (does not match the tool's declared output) makes its $result references unusable", async () => {
    const { run } = make();
    const r = run();
    const b = await r.begin({ tool: "pay.create", args, reason: "x" });
    if (b.decision !== "allow") throw new Error("expected allow");
    r.complete(b.step, { status: "succeeded", result: { id: "pi_9" }, invalid_result: true, notes: ["output schema: id must be a number"] });
    const s = r.state().steps[0]!;
    expect(s.handle_missing).toContain("id");
    expect(r.plan().actions[0]).toMatchObject({ kind: "unrecoverable" });
  });

  it("expectMismatch handles nested paths, arrays and missing values", () => {
    expect(expectMismatch({ a: { b: [1, { c: 2 }] } }, { "a.b.1.c": 2 })).toBeNull();
    expect(expectMismatch({ a: 1 }, { a: 2 })).toContain("expected 2");
    expect(expectMismatch({}, { "a.b": null })).toContain("missing");
    expect(expectMismatch({ s: { x: 1, y: 2 } }, { s: { y: 2, x: 1 } })).toBeNull(); // key order does not matter
  });
});
