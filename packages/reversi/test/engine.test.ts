import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  EffectUncertainError,
  FileRunStore,
  JsonlLedgerStore,
  Ledger,
  MemoryLedgerStore,
  Registry,
  Reversi,
  ReversiError,
  SealedScope,
  idempotencyKey,
  toJsonl,
  type Approver,
  type CompensationCall,
  type LedgerStore,
} from "../src/index.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), "reversi-eng-"));
  dirs.push(d);
  return d;
};

const MANIFESTS = [
  { tool: "read_order", effect: "read_only", permission: "orders:read" },
  { tool: "put_flag", effect: "idempotent", permission: "orders:write" },
  {
    tool: "create_order",
    effect: "reversible",
    permission: "orders:write",
    compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } },
  },
  { tool: "cancel_order", effect: "idempotent", permission: "orders:write" },
  {
    tool: "charge_card",
    effect: "compensable",
    permission: "pay:write",
    requires: ["create_order"],
    compensation: { tool: "refund", argument_map: { charge: "$result.charge_id", amount: "$args.amount" } },
  },
  { tool: "refund", effect: "idempotent", permission: "pay:write" },
  { tool: "send_email", effect: "irreversible", permission: "mail:send" },
  {
    tool: "big_refund_needed",
    effect: "compensable",
    permission: "pay:write",
    compensation: { tool: "reverse", requires_approval: true, argument_map: { id: "$result.id" } },
  },
  { tool: "reverse", effect: "idempotent", permission: "pay:write" },
];

const FULL = ["orders:read", "orders:write", "pay:write", "mail:send"];

function setup(opts: { approver?: Approver; ledgerStore?: LedgerStore; perms?: string[]; mode?: "enforce" | "observe" } = {}) {
  let t = 1000;
  const ledger = new Ledger(opts.ledgerStore ?? new MemoryLedgerStore());
  const rv = new Reversi({ registry: Registry.from(MANIFESTS), ledger, approver: opts.approver, now: () => t++ });
  const run = rv.startRun({
    run_id: "r1",
    actor: "agent-1",
    scope: SealedScope.seal(opts.perms ?? FULL),
    mode: opts.mode,
  });
  return { rv, run, ledger };
}

const events = (l: Ledger, run = "r1") => l.forRun(run).map((r) => `${r.event}${r.step === null ? "" : ":" + r.step}`);

describe("calls", () => {
  it("journals intent BEFORE the tool executes", async () => {
    const { run, ledger } = setup();
    let seenAtExecution: string[] = [];
    await run.call({
      tool: "create_order",
      args: { sku: "A1" },
      reason: "customer asked",
      execute: () => {
        seenAtExecution = events(ledger);
        return { id: 7 };
      },
    });
    expect(seenAtExecution).toEqual(["run_started", "intended:0"]);
    expect(events(ledger)).toEqual(["run_started", "intended:0", "succeeded:0"]);
  });

  it("blocks unmanifested tools, out-of-scope tools, and does not execute them", async () => {
    const { run, ledger } = setup({ perms: ["orders:read"] });
    let ran = false;
    const exec = () => {
      ran = true;
    };
    const a = await run.call({ tool: "mystery", reason: "x", execute: exec });
    const b = await run.call({ tool: "create_order", reason: "x", execute: exec });
    expect(a.status).toBe("blocked");
    expect(b).toMatchObject({ status: "blocked" });
    expect(ran).toBe(false);
    expect(events(ledger).filter((e) => e === "blocked")).toHaveLength(2);
    expect(run.state().steps).toHaveLength(0);
  });

  it("enforces manifest `requires`", async () => {
    const { run } = setup();
    const r = await run.call({ tool: "charge_card", args: { amount: 5 }, reason: "pay", execute: () => ({ charge_id: "c" }) });
    expect(r).toMatchObject({ status: "blocked" });
    await run.call({ tool: "create_order", reason: "o", execute: () => ({ id: 1 }) });
    const ok = await run.call({ tool: "charge_card", args: { amount: 5 }, reason: "pay", execute: () => ({ charge_id: "c" }) });
    expect(ok.status).toBe("executed");
    expect(run.state().steps[1]?.depends_on).toEqual([0]);
  });

  it("requires a reason", async () => {
    const { run } = setup();
    await expect(run.call({ tool: "read_order", reason: " ", execute: () => 1 })).rejects.toThrow();
  });

  it("journals failures and rethrows", async () => {
    const { run, ledger } = setup();
    await expect(
      run.call({ tool: "create_order", reason: "o", execute: () => { throw new Error("db down"); } }),
    ).rejects.toThrow("db down");
    expect(events(ledger)).toEqual(["run_started", "intended:0", "failed:0"]);
    expect(run.state().steps[0]?.status).toBe("failed");
  });

  it("marks EffectUncertainError as uncertain and unresolved", async () => {
    const { run } = setup();
    await expect(
      run.call({ tool: "create_order", reason: "o", execute: () => { throw new EffectUncertainError("timeout"); } }),
    ).rejects.toThrow();
    expect(run.state().steps[0]?.status).toBe("uncertain");
    expect(run.unresolved()).toEqual([0]);
  });

  it("never stores arguments or results in the ledger", async () => {
    const { run, ledger } = setup();
    await run.call({
      tool: "create_order",
      args: { card: "4111-SECRET" },
      reason: "o",
      execute: () => ({ id: 1, token: "tok-SECRET" }),
    });
    const text = toJsonl(ledger.records());
    expect(text).not.toContain("SECRET");
  });

  it("fails closed when the ledger cannot be written", async () => {
    let failing = false;
    const store: LedgerStore = {
      ...new MemoryLedgerStore(),
      all: () => records,
      append: (r) => {
        if (failing) throw new Error("disk full");
        records.push(r);
      },
    };
    const records: any[] = [];
    const { run } = setup({ ledgerStore: store });
    failing = true;
    let ran = false;
    await expect(
      run.call({ tool: "create_order", reason: "o", execute: () => { ran = true; return { id: 1 }; } }),
    ).rejects.toThrow("disk full");
    expect(ran).toBe(false);
  });

  it("detects a tampered scope", async () => {
    const { rv, run } = setup({ perms: ["orders:read"] });
    const st = run.state();
    st.scope.permissions.push("pay:write");
    rv.runs.put(st);
    const r = await run.call({ tool: "refund", reason: "x", execute: () => 1 });
    expect(r).toMatchObject({ status: "blocked" });
    expect((r as any).reasons.join(" ")).toContain("modified after it was sealed");
  });
});

describe("approvals", () => {
  it("blocks irreversible tools without an approver", async () => {
    const { run } = setup();
    const r = await run.call({ tool: "send_email", reason: "confirm", execute: () => "sent" });
    expect(r).toMatchObject({ status: "blocked" });
  });

  it("runs after approval and records it before the intent", async () => {
    const { run, ledger } = setup({ approver: () => true });
    const r = await run.call({ tool: "send_email", reason: "confirm", execute: () => "sent" });
    expect(r.status).toBe("executed");
    expect(events(ledger)).toEqual(["run_started", "approved", "intended:0", "succeeded:0"]);
  });

  it("denied approvals block", async () => {
    const { run } = setup({ approver: () => false });
    expect((await run.call({ tool: "send_email", reason: "x", execute: () => 1 })).status).toBe("blocked");
  });
});

describe("observe mode", () => {
  it("lets violating calls run but journals would_block", async () => {
    const { run, ledger } = setup({ mode: "observe", perms: ["orders:read"] });
    const r = await run.call({ tool: "create_order", reason: "o", execute: () => ({ id: 3 }) });
    expect(r).toMatchObject({ status: "executed" });
    expect((r as any).observed_violations.length).toBeGreaterThan(0);
    expect(events(ledger)).toEqual(["run_started", "would_block:0", "intended:0", "succeeded:0"]);
  });

  it("treats a missing approver as an observed violation, not a block", async () => {
    const { run } = setup({ mode: "observe" });
    const r = await run.call({ tool: "send_email", reason: "x", execute: () => "sent" });
    expect(r.status).toBe("executed");
  });
});

describe("rollback", () => {
  async function scenario(ctx = setup()) {
    const { run } = ctx;
    await run.call({ tool: "read_order", reason: "look", execute: () => ({}) });
    await run.call({ tool: "create_order", args: { sku: "A1" }, reason: "order", execute: () => ({ id: 42 }) });
    await run.call({ tool: "charge_card", args: { amount: 19 }, reason: "pay", execute: () => ({ charge_id: "ch_9" }) });
    return ctx;
  }

  it("compensates newest first using $args and $result handles", async () => {
    const { run } = await scenario();
    const calls: CompensationCall[] = [];
    const rep = await run.rollback({ compensate: (c) => void calls.push(c) });
    expect(calls.map((c) => c.tool)).toEqual(["refund", "cancel_order"]);
    expect(calls[0]?.args).toEqual({ charge: "ch_9", amount: 19 });
    expect(calls[1]?.args).toEqual({ id: 42 });
    expect(rep).toMatchObject({ compensated: [2, 1], skipped: [0], complete: true });
  });

  it("is idempotent: a second rollback does nothing", async () => {
    const { run } = await scenario();
    await run.rollback({ compensate: () => {} });
    let n = 0;
    const rep = await run.rollback({ compensate: () => void n++ });
    expect(n).toBe(0);
    expect(rep.compensated).toEqual([]);
    expect(rep.complete).toBe(true);
  });

  it("retries failures with the same idempotency key", async () => {
    const { run } = await scenario();
    const keys: string[] = [];
    const first = await run.rollback({
      compensate: (c) => {
        keys.push(c.idempotency_key);
        if (c.tool === "refund") throw new Error("gateway 503");
      },
    });
    expect(first.failed).toEqual([{ step: 2, error: "gateway 503" }]);
    // create_order (step 1) is depended on by the failed charge, so it must NOT be undone yet.
    expect(first.deferred).toEqual([{ step: 1, blocked_by: [2] }]);
    expect(first.complete).toBe(false);
    expect(first.compensated).toEqual([]);

    const second = await run.rollback({ compensate: (c) => void keys.push(c.idempotency_key) });
    expect(second.complete).toBe(true);
    expect(second.compensated).toEqual([2, 1]);
    expect(keys[0]).toBe(keys[1]); // the retried refund reuses its key
    expect(keys[0]).toBe(idempotencyKey("r1", 2, "charge_card"));
  });

  it("never claims irreversible steps were undone", async () => {
    const ctx = setup({ approver: () => true });
    await ctx.run.call({ tool: "create_order", reason: "o", execute: () => ({ id: 1 }) });
    await ctx.run.call({ tool: "send_email", reason: "mail", execute: () => "ok" });
    const rep = await ctx.run.rollback({ compensate: () => {} });
    expect(rep.unrecoverable).toEqual([1]);
    expect(rep.compensated).toEqual([0]);
    expect(rep.complete).toBe(false);
    expect(events(ctx.ledger)).toContain("unrecoverable:1");
  });

  it("reports unmanifested and unresolved steps instead of guessing", async () => {
    const ctx = setup({ mode: "observe" });
    await ctx.run.call({ tool: "mystery", reason: "x", execute: () => 1 });
    await expect(
      ctx.run.call({ tool: "create_order", reason: "o", execute: () => { throw new EffectUncertainError(); } }),
    ).rejects.toThrow();
    const rep = await ctx.run.rollback({ compensate: () => {} });
    expect(rep.unmanifested).toEqual([0]);
    expect(rep.unresolved).toEqual([1]);
    expect(rep.complete).toBe(false);
  });

  it("marks steps whose compensation handle is missing as unrecoverable", async () => {
    const { run } = setup();
    await run.call({ tool: "create_order", reason: "o", execute: () => ({ no_id_here: true }) });
    expect(run.state().steps[0]?.handle_missing).toEqual(["id"]);
    const rep = await run.rollback({ compensate: () => { throw new Error("must not run"); } });
    expect(rep.unrecoverable).toEqual([0]);
  });

  it("does not run an independent step's undo behind a failed one's back (independent steps still undo)", async () => {
    const { run } = setup();
    await run.call({ tool: "create_order", reason: "a", execute: () => ({ id: 1 }) });
    await run.call({ tool: "create_order", reason: "b", execute: () => ({ id: 2 }) });
    const rep = await run.rollback({
      compensate: (c) => {
        if (c.args.id === 2) throw new Error("boom");
      },
    });
    expect(rep.failed).toHaveLength(1);
    expect(rep.compensated).toEqual([0]); // independent: still undone
  });

  it("honours explicit depends_on", async () => {
    const { run } = setup();
    const a = await run.call({ tool: "create_order", reason: "a", execute: () => ({ id: 1 }) });
    await run.call({
      tool: "create_order",
      reason: "b",
      depends_on: [(a as any).step],
      execute: () => ({ id: 2 }),
    });
    const rep = await run.rollback({
      compensate: (c) => {
        if (c.args.id === 2) throw new Error("boom");
      },
    });
    expect(rep.deferred).toEqual([{ step: 0, blocked_by: [1] }]);
  });

  it("rejects depends_on that points nowhere", async () => {
    const { run } = setup();
    const r = await run.call({ tool: "read_order", reason: "x", depends_on: [9], execute: () => 1 });
    expect(r.status).toBe("blocked");
  });

  it("plan() simulates success and executes nothing", async () => {
    const { run, ledger } = await scenario();
    const before = ledger.records().length;
    const plan = run.plan();
    expect(plan.actions.map((a) => `${a.kind}:${a.step}`)).toEqual(["compensate:2", "compensate:1", "skip:0"]);
    expect(plan.fully_reversible).toBe(true);
    expect(ledger.records().length).toBe(before);
    expect(run.state().steps.every((s) => s.status === "succeeded")).toBe(true);
  });

  it("plan() flags irreversible steps", async () => {
    const ctx = setup({ approver: () => true });
    await ctx.run.call({ tool: "send_email", reason: "m", execute: () => 1 });
    const plan = ctx.run.plan();
    expect(plan.fully_reversible).toBe(false);
    expect(plan.actions[0]).toMatchObject({ kind: "unrecoverable", step: 0 });
  });

  it("holds compensations that need approval until approved", async () => {
    let allow = false;
    const ctx = setup({ approver: (r) => (r.kind === "compensation" ? allow : true) });
    await ctx.run.call({ tool: "big_refund_needed", reason: "x", execute: () => ({ id: "z" }) });
    const first = await ctx.run.rollback({ compensate: () => {} });
    expect(first.awaiting_approval).toEqual([0]);
    expect(first.complete).toBe(false);
    allow = true;
    const second = await ctx.run.rollback({ compensate: () => {} });
    expect(second.compensated).toEqual([0]);
  });

  it("writes `compensating` before the compensator runs", async () => {
    const { run, ledger } = await scenario();
    let seen: string[] = [];
    await run.rollback({
      compensate: (c) => {
        if (c.step === 2) seen = events(ledger);
      },
    });
    expect(seen.at(-1)).toBe("compensating:2");
  });

  it("split begin/complete protocol works for remote executors", async () => {
    const { run } = await scenario();
    const start = await run.beginCompensation(2);
    expect(start.decision).toBe("go");
    expect(() => run.completeCompensation(1, { status: "compensated" })).toThrow(ReversiError);
    run.completeCompensation(2, { status: "compensated" });
    expect((await run.beginCompensation(2)).decision).toBe("nothing_to_do");
  });
});

describe("recovery", () => {
  it("surfaces a dangling intent after a crash", async () => {
    const { run } = setup();
    const b = await run.begin({ tool: "create_order", reason: "o" });
    expect(b.decision).toBe("allow");
    // process dies here: never completed
    expect(run.unresolved()).toEqual([0]);
    const rep = await run.rollback({ compensate: () => {} });
    expect(rep.unresolved).toEqual([0]);
  });

  it("reconciles from the ledger when run state was lost", async () => {
    const ctx = setup();
    await ctx.run.begin({ tool: "create_order", reason: "o" });
    const lost = new Reversi({
      registry: Registry.from(MANIFESTS),
      ledger: ctx.ledger,
      runs: undefined,
    });
    // Fresh in-memory run store: the run is unknown, but the ledger remembers the intent.
    expect(() => lost.openRun("r1")).toThrow(ReversiError);
    const intended = ctx.ledger.forRun("r1").filter((r) => r.event === "intended");
    expect(intended).toHaveLength(1);
  });

  it("never reuses a step number the ledger already used", async () => {
    const ctx = setup();
    await ctx.run.call({ tool: "create_order", reason: "o", execute: () => ({ id: 1 }) });
    const st = ctx.run.state();
    st.steps = []; // simulate state saved before the last step was recorded
    ctx.rv.runs.put(st);
    const b = await ctx.run.begin({ tool: "read_order", reason: "x" });
    expect(b).toMatchObject({ decision: "allow", step: 1 });
  });

  it("survives a restart with file-backed stores", async () => {
    const dir = tmp();
    const mk = () =>
      new Reversi({
        registry: Registry.from(MANIFESTS),
        ledger: new Ledger(new JsonlLedgerStore(join(dir, "ledger.jsonl"))),
        runs: new FileRunStore(join(dir, "runs")),
      });
    const a = mk();
    const run = a.startRun({ run_id: "persist-1", actor: "agent", scope: SealedScope.seal(FULL) });
    await run.call({ tool: "create_order", reason: "o", execute: () => ({ id: 5 }) });

    const b = mk();
    expect(b.runIds()).toEqual(["persist-1"]);
    const again = b.openRun("persist-1");
    const calls: CompensationCall[] = [];
    const rep = await again.rollback({ compensate: (c) => void calls.push(c) });
    expect(rep.complete).toBe(true);
    expect(calls[0]?.args).toEqual({ id: 5 });
    expect(b.ledger.verify().ok).toBe(true);
  });

  it("rejects unsafe or duplicate run ids", () => {
    const { rv } = setup();
    expect(() => rv.startRun({ run_id: "../etc", actor: "a", scope: SealedScope.seal([]) })).toThrow(ReversiError);
    expect(() => rv.startRun({ run_id: "r1", actor: "a", scope: SealedScope.seal([]) })).toThrow(/already exists/);
    expect(() => new FileRunStore(tmp()).get("../x")).toThrow();
  });
});

describe("concurrency", () => {
  it("parallel calls get distinct step numbers", async () => {
    const { run } = setup();
    const rs = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        run.call({ tool: "read_order", args: { i }, reason: "r", execute: async () => i }),
      ),
    );
    const steps = rs.map((r) => (r as any).step).sort((a, b) => a - b);
    expect(steps).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });
});
