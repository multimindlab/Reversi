import { describe, expect, it } from "vitest";
import {
  ApprovalError,
  Approvals,
  Delegations,
  Ledger,
  MemoryKvStore,
  Policy,
  PolicyError,
  Registry,
  Reversi,
  SealedScope,
  inWindow,
  mergeRequirements,
  parsePolicy,
  scoreRisk,
} from "../src/index.js";

const base = { tool: "pay", effect: "compensable" as const, permission: "p", actor: "agent", run_id: "r1", environment: "prod", args: {} };
const at = (iso: string) => () => Date.parse(iso);

describe("risk scoring", () => {
  it("adds transparent factors and caps at 100", () => {
    const r = scoreRisk({ amount: { path: "$args.amount", bands: [{ over: 100, points: 10 }, { over: 1000, points: 25 }] }, actors: { newbie: 15 } }, { effect: "compensable", blast_radius: "high", data_class: "financial", environment: "prod", actor: "newbie", args: { amount: 5000 } });
    expect(r.score).toBe(100); // 30+20+20+10+25+15 = 120, capped
    expect(r.factors).toEqual(["effect compensable +30", "blast radius high +20", "data class financial +20", "environment prod +10", "amount over 1000 +25", "actor newbie +15"]);
    expect(scoreRisk(undefined, { effect: "irreversible", blast_radius: "critical", data_class: "secret", environment: "prod", actor: "a", args: {} }).score).toBe(100);
    expect(scoreRisk(undefined, { effect: null, environment: "dev", actor: "a", args: {} })).toMatchObject({ score: 40, factors: ["no manifest +40"] });
  });

  it("thresholds turn a score into an approval or a denial", () => {
    const p = Policy.from({ risk: { thresholds: { approve: 40, deny: 90 } } });
    const d = (over: object) => p.evaluate({ ...base, ...over });
    expect(d({ effect: "read_only", environment: "dev" }).action).toBe("allow");
    expect(d({ effect: "compensable", blast_radius: "high" }).action).toBe("require_approval"); // 30+20+10 = 60
    expect(d({ effect: "irreversible", blast_radius: "critical", data_class: "secret" }).action).toBe("deny");
    expect(d({ effect: "read_only", environment: "dev" }).risk?.score).toBe(0);
  });

  it("rejects bad risk config", () => {
    expect(() => parsePolicy({ risk: { thresholds: { approve: 90, deny: 50 } } })).toThrow(/approve must not be above deny/);
    expect(() => parsePolicy({ risk: { weights: { effect: { x: "a" } } } })).toThrow(PolicyError);
  });
});

describe("time windows and freezes", () => {
  it("evaluates days, hours, wrap-around and time zones", () => {
    const biz = { days: ["mon", "tue", "wed", "thu", "fri"] as never, between: "09:00-17:00" };
    expect(inWindow(biz, Date.parse("2026-10-14T10:00:00Z"))).toBe(true); // Wednesday
    expect(inWindow(biz, Date.parse("2026-10-14T18:00:00Z"))).toBe(false);
    expect(inWindow(biz, Date.parse("2026-10-17T10:00:00Z"))).toBe(false); // Saturday
    expect(inWindow({ between: "22:00-06:00" }, Date.parse("2026-10-14T23:30:00Z"))).toBe(true);
    expect(inWindow({ between: "22:00-06:00" }, Date.parse("2026-10-14T05:59:00Z"))).toBe(true);
    expect(inWindow({ between: "22:00-06:00" }, Date.parse("2026-10-14T12:00:00Z"))).toBe(false);
    expect(inWindow({ between: "09:00-17:00", timezone: "America/New_York" }, Date.parse("2026-10-14T14:00:00Z"))).toBe(true); // 10:00 in New York
    expect(inWindow({ between: "09:00-17:00", timezone: "America/New_York", outside: true }, Date.parse("2026-10-14T14:00:00Z"))).toBe(false);
  });

  it("a rule with a window only fires inside it", () => {
    const doc = { rules: [{ id: "after-hours", match: { tool: "pay" }, window: { between: "09:00-17:00", outside: true }, action: "require_approval" }] };
    expect(Policy.from(doc, at("2026-10-14T10:00:00Z")).evaluate(base).action).toBe("allow");
    expect(Policy.from(doc, at("2026-10-14T20:00:00Z")).evaluate(base).action).toBe("require_approval");
  });

  it("a freeze denies non-read calls for its period, with its reason", () => {
    const doc = { freezes: [{ id: "q4-freeze", from: "2026-12-15T00:00:00Z", to: "2027-01-05T00:00:00Z", reason: "holiday change freeze" }] };
    const during = Policy.from(doc, at("2026-12-24T12:00:00Z"));
    expect(during.evaluate(base)).toMatchObject({ action: "deny", deny: [expect.stringContaining("holiday change freeze")] });
    expect(during.evaluate({ ...base, effect: "read_only" }).action).toBe("allow");
    expect(Policy.from(doc, at("2027-01-06T00:00:00Z")).evaluate(base).action).toBe("allow");
    expect(() => parsePolicy({ freezes: [{ id: "x", from: "2026-01-02", to: "2026-01-01", reason: "r" }] })).toThrow(/after from/);
    expect(() => parsePolicy({ rules: [{ id: "a", action: "deny", window: { between: "9-5" } }] })).toThrow(/between/);
  });
});

describe("budgets and shared limits", () => {
  it("a sum budget refuses the call that would exceed it, warns near the end, and is shared through the KV store", () => {
    const kv = new MemoryKvStore();
    let t = 1_000_000;
    const doc = { budgets: [{ id: "daily-spend", match: { tool: "pay" }, metric: "sum", path: "$args.amount", max: 1000, window_seconds: 86400, per: "actor", warn_at: 0.8 }] };
    const a = new Policy(parsePolicy(doc), () => t, kv);
    const b = new Policy(parsePolicy(doc), () => t, kv); // another process
    const call = (p: Policy, amount: number) => {
      const i = { ...base, args: { amount } };
      const d = p.evaluate(i);
      if (d.action !== "deny") p.record(i);
      return d;
    };
    expect(call(a, 500).action).toBe("allow");
    const second = call(b, 350); // 850 of 1000 now: over the 80% warning
    expect(second.action).toBe("allow");
    expect(second.warnings[0]).toBe("budget `daily-spend` at 85% (850 of 1000)");
    const third = call(a, 300);
    expect(third).toMatchObject({ action: "deny", deny: [expect.stringContaining("850 of 1000 used")] });
    t += 86_400_001; // the window slides past the earlier spending
    expect(call(b, 300).action).toBe("allow");
  });

  it("a budget can ask for approval instead of refusing, and is per actor", () => {
    const p = Policy.from({ budgets: [{ id: "calls", match: {}, metric: "calls", max: 1, window_seconds: 60, per: "actor", action: "require_approval" }] });
    p.record(base);
    expect(p.evaluate(base).action).toBe("require_approval");
    expect(p.evaluate({ ...base, actor: "other" }).action).toBe("allow");
  });

  it("rate limits are shared the same way", () => {
    const kv = new MemoryKvStore();
    const doc = { limits: [{ id: "burst", match: {}, max_calls: 1, window_seconds: 60, per: "global" }] };
    const a = new Policy(parsePolicy(doc), undefined, kv);
    const b = new Policy(parsePolicy(doc), undefined, kv);
    a.record(base);
    expect(b.evaluate(base).deny[0]).toContain("burst");
  });

  it("validates budgets", () => {
    expect(() => parsePolicy({ budgets: [{ id: "x", metric: "sum", max: 5, window_seconds: 60 }] })).toThrow(/needs path/);
    expect(() => parsePolicy({ budgets: [{ id: "x", metric: "calls", max: -1, window_seconds: 0, per: "world" }] })).toThrow(PolicyError);
  });
});

describe("tenants and match fields", () => {
  it("matches tenant, data class and blast radius", () => {
    const p = Policy.from({ rules: [{ id: "acme-pii", match: { tenant: "acme", data_class: "pii", blast_radius: ["high", "critical"] }, action: "deny" }] });
    expect(p.evaluate({ ...base, tenant: "acme", data_class: "pii", blast_radius: "high" }).action).toBe("deny");
    expect(p.evaluate({ ...base, tenant: "other", data_class: "pii", blast_radius: "high" }).action).toBe("allow");
    expect(p.evaluate({ ...base, data_class: "pii", blast_radius: "high" }).action).toBe("allow"); // no tenant known: does not match
  });
});

describe("approval routing, quorum, delegation, escalation, break-glass", () => {
  const fin = { roles: ["approver"], groups: ["finance"] };
  const ops = { roles: ["approver"], groups: ["ops"] };
  function setup(opts: { now?: () => number } = {}) {
    const kv = new MemoryKvStore();
    const delegations = new Delegations(kv, opts.now);
    const events: string[] = [];
    const approvals = new Approvals(undefined, { delegations, now: opts.now, on_decision: (r, d) => events.push(`${d}:${r.decided_by}`), on_escalate: (r) => events.push(`escalated:${r.required_roles?.join("|")}`) });
    const asked = (extra: object = {}) =>
      approvals.asApprover()({ run_id: "r1", step: null, tool: "pay", reason: "x", kind: "call", args_hash: "h", requested_by: "agent-1", required_roles: ["finance"], quorum: 1, ...extra });
    return { approvals, delegations, events, asked };
  }

  it("only a listed role or group may approve; the requester never may", () => {
    const { approvals, asked } = setup();
    asked();
    const id = approvals.list()[0]!.id;
    expect(() => approvals.approve(id, "olga", undefined, ops)).toThrow(/needs an approver from: finance/);
    expect(() => approvals.approve(id, "agent-1", undefined, { roles: ["approver"], groups: ["finance"] })).toThrow(/your own run/);
    expect(approvals.approve(id, "fiona", "ok", fin)).toMatchObject({ status: "approved", decided_by: "fiona" });
    expect(approvals.get(id)?.decisions?.[0]).toMatchObject({ by: "fiona", basis: "group:finance" });
  });

  it("a quorum needs distinct approvers and stays pending until it is met", () => {
    const { approvals, asked, events } = setup();
    asked({ quorum: 2 });
    const id = approvals.list()[0]!.id;
    expect(approvals.approve(id, "fiona", undefined, fin).status).toBe("pending");
    expect(() => approvals.approve(id, "fiona", undefined, fin)).toThrow(/already decided/);
    const done = approvals.approve(id, "fred", undefined, fin);
    expect(done).toMatchObject({ status: "approved", decided_by: "fiona, fred" });
    expect(events).toEqual(["approved:fiona, fred"]); // only the final decision reaches the ledger hook
    expect(approvals.asApprover()({ run_id: "r1", step: null, tool: "pay", reason: "x", kind: "call", args_hash: "h" })).toBe(true);
  });

  it("one denial ends it", () => {
    const { approvals, asked } = setup();
    asked({ quorum: 2 });
    const id = approvals.list()[0]!.id;
    approvals.approve(id, "fiona", undefined, fin);
    expect(approvals.deny(id, "fred", "no", fin).status).toBe("denied");
  });

  it("two approvers racing on the same vote cannot lose one", () => {
    const { approvals, asked } = setup();
    asked({ quorum: 2 });
    const id = approvals.list()[0]!.id;
    const stale = approvals.get(id)!;
    approvals.approve(id, "fiona", undefined, fin);
    // fred decides from the stale copy the store no longer matches
    expect(approvals.store.transition(id, "pending", { decisions: [{ by: "fred", basis: "x", decision: "approve", note: null, ms: 1 }], decision_count: 1 }, stale.decision_count ?? 0)).toBe(false);
    expect(approvals.get(id)?.decisions).toHaveLength(1);
  });

  it("a delegate approves on behalf of the delegator, once, and the delegator cannot also vote", () => {
    let t = 1_000_000;
    const { approvals, delegations, asked } = setup({ now: () => t });
    delegations.grant({ from: "fiona", to: "dan", until_ms: t + 3_600_000, reason: "on leave" });
    asked({ quorum: 2 });
    const id = approvals.list()[0]!.id;
    const dan = { roles: ["approver"], groups: [] };
    expect(approvals.approve(id, "dan", undefined, dan).status).toBe("pending");
    expect(approvals.get(id)?.decisions?.[0]).toMatchObject({ by: "dan", on_behalf_of: "fiona", basis: "delegated by fiona (finance)" });
    expect(() => approvals.approve(id, "fiona", undefined, fin)).toThrow(/already decided/);
    expect(approvals.approve(id, "fred", undefined, fin).status).toBe("approved");
    // expired or revoked delegations stop working
    const second = setup({ now: () => t });
    const d = second.delegations.grant({ from: "fiona", to: "dan", until_ms: t + 1000, reason: "short" });
    second.asked();
    t += 5000;
    expect(() => second.approvals.approve(second.approvals.list()[0]!.id, "dan", undefined, dan)).toThrow(/needs an approver/);
    void d;
  });

  it("delegation is validated", () => {
    const { delegations } = setup();
    expect(() => delegations.grant({ from: "a", to: "a", until_ms: Date.now() + 1000, reason: "x" })).toThrow(/yourself/);
    expect(() => delegations.grant({ from: "a", to: "b", until_ms: Date.now() - 1, reason: "x" })).toThrow(/future/);
    expect(() => delegations.grant({ from: "a", to: "b", until_ms: Date.now() + 200 * 86_400_000, reason: "x" })).toThrow(/90 days/);
    expect(() => delegations.grant({ from: "a", to: "b", until_ms: Date.now() + 1000, reason: " " })).toThrow(/reason/);
    const d = delegations.grant({ from: "a", to: "b", until_ms: Date.now() + 5000, reason: "r" });
    expect(delegations.activeFor("b")).toHaveLength(1);
    delegations.revoke(d.id);
    expect(delegations.activeFor("b")).toHaveLength(0);
  });

  it("an unanswered request is denied on timeout, or escalates to other approvers once", () => {
    let t = 1_000_000;
    const denying = setup({ now: () => t });
    denying.asked({ timeout_ms: 1000, on_timeout: "deny" });
    t += 1500;
    expect(denying.approvals.list()[0]?.status).toBe("expired");
    expect(denying.asked({ timeout_ms: 1000, on_timeout: "deny" })).toMatchObject({ approved: false, message: expect.stringContaining("expired unanswered and was denied") });

    t = 2_000_000;
    const esc = setup({ now: () => t });
    esc.asked({ timeout_ms: 1000, on_timeout: "escalate", escalate_to: ["cfo"] });
    t += 1500;
    const rec = esc.approvals.list()[0]!;
    expect(rec).toMatchObject({ status: "pending", escalated: true, required_roles: ["cfo"] });
    expect(esc.events).toEqual(["escalated:cfo"]);
    expect(() => esc.approvals.approve(rec.id, "fiona", undefined, fin)).toThrow(/needs an approver from: cfo/);
    expect(esc.approvals.approve(rec.id, "carl", undefined, { roles: ["approver"], groups: ["cfo"] }).status).toBe("approved");
    t += 5_000_000; // escalation happens once; the next timeout expires it
    const again = setup({ now: () => t });
    again.asked({ timeout_ms: 1000, on_timeout: "escalate", escalate_to: ["cfo"] });
    t += 1500;
    again.approvals.list();
    t += 1500;
    expect(again.approvals.list()[0]?.status).toBe("expired");
  });

  it("break-glass needs admin, a real reason and evidence, and is recorded as such", () => {
    const { approvals, asked, events } = setup();
    asked({ quorum: 2 });
    const id = approvals.list()[0]!.id;
    expect(() => approvals.breakGlass(id, "oscar", { reason: "outage, customers affected", evidence: "INC-42" }, ops)).toThrow(/admin role/);
    const admin = { roles: ["admin"], groups: [] };
    expect(() => approvals.breakGlass(id, "root", { reason: "short", evidence: "INC-42" }, admin)).toThrow(/at least 10/);
    expect(() => approvals.breakGlass(id, "root", { reason: "outage, customers affected", evidence: " " }, admin)).toThrow(/evidence/);
    const done = approvals.breakGlass(id, "root", { reason: "outage, customers affected", evidence: "INC-42" }, admin);
    expect(done).toMatchObject({ status: "approved", break_glass: { by: "root", evidence: "INC-42" } });
    expect(done.decision_note).toContain("BREAK-GLASS");
    expect(events).toEqual(["approved:root"]);
    expect(() => approvals.breakGlass(id, "root", { reason: "outage, customers affected", evidence: "INC-42" }, admin)).toThrow(ApprovalError);
  });

  it("merges several requirements: any listed role, biggest quorum, shortest timeout, deny wins", () => {
    expect(mergeRequirements([])).toEqual({});
    expect(mergeRequirements([
      { roles: ["finance"], quorum: 1, timeout_ms: 900000, on_timeout: "escalate", escalate_to: ["cfo"], source: "a" },
      { roles: ["risk"], quorum: 2, timeout_ms: 600000, source: "b" },
    ])).toEqual({ required_roles: ["finance", "risk"], quorum: 2, timeout_ms: 600000, on_timeout: "deny", escalate_to: ["cfo"] });
  });
});

describe("engine: requirements, scoped halts, advise mode, tenants", () => {
  const MANIFESTS = [
    { tool: "pay", effect: "compensable", permission: "p", risk: { data_class: "financial", blast_radius: "high" }, approval: { roles: ["finance"], quorum: 2, timeout: "10m", on_timeout: "escalate", escalate_to: ["cfo"] }, compensation: { tool: "refund" } },
    { tool: "refund", effect: "idempotent", permission: "p" },
    { tool: "read", effect: "read_only", permission: "p" },
  ];
  function make(opts: Partial<ConstructorParameters<typeof Reversi>[0]> = {}) {
    const kv = new MemoryKvStore();
    const approvals = new Approvals();
    const rv = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(), approver: approvals.asApprover(), kv, ...opts });
    return { rv, approvals, kv };
  }

  it("manifest approval rules and policy rules reach the approval request", async () => {
    const policy = Policy.from({ rules: [{ id: "big", match: { tool: "pay" }, action: "require_approval", approvers: ["risk"], quorum: 1 }], risk: { thresholds: { approve: 50 } } });
    const { rv, approvals } = make({ policy });
    const run = rv.startRun({ actor: "agent", scope: SealedScope.seal(["p"]) });
    const r = await run.call({ tool: "pay", args: { n: 1 }, reason: "x", execute: () => ({}) });
    expect(r).toMatchObject({ status: "blocked", reasons: [expect.stringContaining("needs 2 approvers from risk or finance")] });
    expect(approvals.list()[0]).toMatchObject({ requested_by: "agent", required_roles: ["risk", "finance"], quorum: 2, on_timeout: "deny" });
    expect(rv.ledger.records().at(-1)?.detail).toContain("policy `big`");
    expect(rv.ledger.records().at(-1)?.detail).toContain("manifest requires approval");
    expect(rv.ledger.records().at(-1)?.detail).toContain("risk score");
  });

  it("the risk score is recorded in the intent and on the step", async () => {
    const policy = Policy.from({ risk: {} });
    const { rv } = make({ policy });
    const run = rv.startRun({ actor: "agent", scope: SealedScope.seal(["p"]) });
    await run.call({ tool: "read", reason: "x", execute: () => 1 });
    expect(run.state().steps[0]?.risk_score).toBe(0); // read_only in the default environment
    expect(rv.ledger.records().find((r) => r.event === "intended")?.detail).toBe("risk 0");
  });

  it("scoped halts block only what they name, are shared through the KV, and rollback still works", async () => {
    const { rv, kv } = make();
    const run = rv.startRun({ actor: "agent-7", scope: SealedScope.seal(["p"]), tenant: "acme" });
    rv.halt("pay is broken", { tool: "pay" });
    const other = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(), kv }); // another process
    expect(other.halted({ tool: "pay" })).toContain("pay is broken (scope: tool=pay)");
    expect(other.halted({ tool: "read" })).toBeNull();
    expect((await run.call({ tool: "pay", reason: "x", execute: () => ({}) })).status).toBe("blocked");
    expect((await run.call({ tool: "read", reason: "x", execute: () => 1 })).status).toBe("executed");
    rv.halt("tenant freeze", { tenant: "acme" });
    expect((await run.call({ tool: "read", reason: "x", execute: () => 1 })).status).toBe("blocked");
    rv.halt("agent paused", { actor: "agent-*" });
    expect(rv.halts()).toHaveLength(3);
    expect(rv.resume(rv.halts()[0]!.id)).toBe(1);
    expect(rv.resume()).toBe(2);
    expect((await run.call({ tool: "read", reason: "x", execute: () => 1 })).status).toBe("executed");
  });

  it("advise mode runs the call and reports what would have happened", async () => {
    const policy = Policy.from({ rules: [{ id: "no", match: { tool: "read" }, action: "deny" }] });
    const { rv } = make({ policy });
    const run = rv.startRun({ actor: "a", scope: SealedScope.seal(["p"]), mode: "advise" });
    const r = await run.call({ tool: "read", reason: "x", execute: () => 1 });
    expect(r).toMatchObject({ status: "executed", observed_violations: [expect.stringContaining("policy `no`")] });
    expect(rv.ledger.records().some((x) => x.event === "would_block")).toBe(true);
  });

  it("tenant flows from the run into policy matching", async () => {
    const policy = Policy.from({ rules: [{ id: "acme-no-pay", match: { tenant: "acme", tool: "pay" }, action: "deny" }] });
    const { rv } = make({ policy });
    const acme = rv.startRun({ actor: "a", scope: SealedScope.seal(["p"]), tenant: "acme" });
    const globex = rv.startRun({ actor: "b", scope: SealedScope.seal(["p"]), tenant: "globex" });
    expect((await acme.call({ tool: "pay", reason: "x", execute: () => ({}) })).status).toBe("blocked");
    const g = await globex.begin({ tool: "pay", reason: "x" });
    expect(g).toMatchObject({ decision: "block", reasons: [expect.stringContaining("approval required")] }); // not denied by the tenant rule; the manifest still wants approval
  });
});
