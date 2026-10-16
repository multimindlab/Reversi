import { describe, expect, it } from "vitest";
import {
  CaptureStore,
  ContentChecker,
  Ledger,
  MemoryKvStore,
  Policy,
  Registry,
  Reversi,
  SealedScope,
  detectPii,
  maskPii,
  parsePolicy,
  previewImpact,
  redactForCapture,
  replayRun,
  simulatePolicy,
  speculate,
} from "../src/index.js";

describe("personal data detection", () => {
  it("finds and masks emails, cards, IBANs, SSNs and phone numbers, and only with valid checksums", () => {
    const text = "mail ada@example.com, card 4111 1111 1111 1111, iban GB82 WEST 1234 5698 7654 32, ssn 123-45-6789, call +1 415-555-0132";
    expect(detectPii(text).sort()).toEqual(["credit_card", "email", "iban", "phone", "ssn"]);
    expect(maskPii(text)).toBe("mail [PII:email], card [PII:credit_card], iban [PII:iban], ssn [PII:ssn], call [PII:phone]");
    expect(detectPii("order 4111 1111 1111 1112 failed")).toEqual([]); // fails Luhn
    expect(detectPii("GB82 WEST 1234 5698 7654 33")).toEqual([]); // fails the IBAN check
    expect(detectPii("version 1.2.3 build 20261015")).toEqual([]);
  });

  it("a pii content check flags, asks or denies", () => {
    const c = new ContentChecker({ pii: "require_approval" });
    expect(c.inspect({ note: "contact ada@example.com" })).toEqual([{ kind: "pii", action: "require_approval", detail: "personal data (email)" }]);
    expect(new ContentChecker().inspect({ note: "contact ada@example.com" })).toEqual([]); // off unless configured
    expect(() => parsePolicy({ content: { pii: "sometimes" } })).toThrow();
  });
});

describe("capture", () => {
  const cap = (cfg = {}, t = () => 1_000) => new CaptureStore(new MemoryKvStore(), { enabled: true, ...cfg }, t);

  it("redacts credentials, personal data and manifest-listed paths on the way in", () => {
    const out = redactForCapture({ to: "ada@example.com", token: "ghp_" + "a".repeat(36), client_secret: "s3cr3t", nested: { n: 1 } }, { redact_pii: true, max_chars: 100, paths: ["$args.client_secret"], root: "args" }) as Record<string, unknown>;
    expect(out).toEqual({ to: "[PII:email]", token: "[REDACTED:github_token]", client_secret: "[REDACTED]", nested: { n: 1 } });
    expect(redactForCapture({ big: "x".repeat(500) }, { redact_pii: false, max_chars: 10 })).toEqual({ big: "xxxxxxxxxx…[cut]" });
    expect(redactForCapture({ n: Infinity }, { redact_pii: false, max_chars: 10 })).toEqual({ n: "Infinity" });
  });

  it("does nothing unless enabled", () => {
    const c = new CaptureStore(new MemoryKvStore());
    expect(c.record({ run_id: "r", step: 0, tool: "t", actor: "a", environment: "e", args: {}, decision: "allow", reasons: [] })).toBeNull();
    expect(c.list()).toEqual([]);
  });

  it("expires, purges and lists by run and tool", () => {
    let t = 1_000;
    const c = cap({ ttl_ms: 5_000 }, () => t);
    c.record({ run_id: "r1", step: 0, tool: "a", actor: "x", environment: "e", args: { k: 1 }, decision: "allow", reasons: [] });
    t = 2_000;
    c.record({ run_id: "r2", step: 0, tool: "b", actor: "x", environment: "e", args: {}, decision: "block", reasons: ["nope"] });
    expect(c.list()).toHaveLength(2);
    expect(c.list({ run_id: "r1" }).map((r) => r.tool)).toEqual(["a"]);
    expect(c.list({ tool: "b" })).toHaveLength(1);
    t = 7_000; // r1 (kept until 6,000) has expired, r2 (until 7,000) too
    expect(c.list()).toEqual([]);
    expect(c.purge()).toBe(2);
    expect(c.purge()).toBe(0);
    t = 8_000;
    c.record({ run_id: "r3", step: 0, tool: "a", actor: "x", environment: "e", args: {}, decision: "allow", reasons: [] });
    expect(c.purge({ run_id: "r3" })).toBe(1);
  });

  it("the engine captures decisions, blocked calls and outcomes, with redaction", async () => {
    const capture = cap();
    const rv = new Reversi({
      registry: Registry.from([
        { tool: "send", effect: "irreversible", permission: "p", audit: { redaction: ["$args.api_key", "$result.secret"] } },
        { tool: "read", effect: "read_only", permission: "p" },
      ]),
      ledger: new Ledger(),
      capture,
      approver: () => true,
    });
    const run = rv.startRun({ run_id: "r1", actor: "agent", scope: SealedScope.seal(["p"]), tenant: "acme" });
    await run.call({ tool: "send", args: { to: "ada@example.com", api_key: "k-123" }, reason: "x", execute: () => ({ ok: true, secret: "shh" }) });
    await run.call({ tool: "nope", args: { q: 1 }, reason: "x", execute: () => 1 });
    const recs = capture.list({ run_id: "r1" });
    expect(recs[0]).toMatchObject({ tool: "send", step: 0, decision: "allow", outcome: "succeeded", tenant: "acme", args: { to: "[PII:email]", api_key: "[REDACTED]" }, result: { ok: true, secret: "[REDACTED]" } });
    expect(recs[1]).toMatchObject({ tool: "nope", step: null, decision: "block" });
    expect(capture.get("r1", 0)?.tool).toBe("send");
  });
});

const MANIFESTS = [
  { tool: "orders.create", effect: "reversible", permission: "p", compensation: { tool: "orders.cancel", argument_map: { id: "$result.id" }, residue: [] } },
  { tool: "orders.cancel", effect: "idempotent", permission: "p" },
  { tool: "pay.charge", effect: "compensable", permission: "p", risk: { data_class: "financial", blast_radius: "high" }, requires: ["orders.create"], compensation: { tool: "pay.refund", residue: ["statement line stays"], argument_map: { charge: "$result.charge_id", amount: "$args.amount" }, verification: { tool: "pay.get", arguments: { charge: "$result.charge_id" }, expect: { status: "refunded" } } } },
  { tool: "pay.refund", effect: "idempotent", permission: "p" },
  { tool: "pay.get", effect: "read_only", permission: "p" },
  { tool: "mail.send", effect: "irreversible", permission: "p" },
];
const registry = () => Registry.from(MANIFESTS);

function rec(over: object): import("../src/index.js").CaptureRecord {
  return { run_id: "r1", step: 0, tool: "orders.create", actor: "agent", environment: "prod", args: {}, decision: "allow", reasons: [], outcome: "succeeded", ts_ms: 1, expires_ms: 9e12, ...over } as never;
}

describe("policy simulation against history", () => {
  const history = [
    rec({ step: 0, ts_ms: 1, tool: "orders.create", result: { id: "o1" } }),
    rec({ step: 1, ts_ms: 2, tool: "pay.charge", args: { amount: 50 }, result: { charge_id: "c1" } }),
    rec({ step: 2, ts_ms: 3, tool: "pay.charge", args: { amount: 5000 }, result: { charge_id: "c2" } }),
    rec({ run_id: "r2", step: null, ts_ms: 4, tool: "mail.send", decision: "block", reasons: ["approval required: request apr_1 is pending"] }),
  ];

  it("reports what a stricter policy would have blocked, what needs approval, and what it would newly allow", async () => {
    const policy = parsePolicy({
      rules: [
        { id: "big", match: { tool: "pay.charge" }, when: [{ path: "$args.amount", op: "gt", value: 1000 }], action: "deny", reason: "too large" },
        { id: "mail-ok", match: { tool: "mail.send" }, action: "allow" },
      ],
    });
    const rep = await simulatePolicy(history, { registry: registry(), policy, environment: "prod" });
    expect(rep).toMatchObject({ calls: 4, runs: 2 });
    expect(rep.newly_blocked).toEqual([expect.objectContaining({ tool: "pay.charge", step: 2, before: "allow", after: "block" })]);
    expect(rep.newly_blocked[0]?.reasons[0]).toContain("too large");
    // mail.send is irreversible so the manifest still wants approval; it was already waiting for it: unchanged
    expect(rep.unchanged).toBe(3);
    const none = await simulatePolicy(history, { registry: registry(), environment: "prod" });
    expect(none.newly_blocked).toEqual([]);
    const tight = await simulatePolicy(history.slice(0, 2), { registry: registry(), policy: parsePolicy({ rules: [{ id: "all", match: { tool: "pay.*" }, action: "require_approval" }] }) });
    expect(tight.newly_needs_approval.map((c) => c.tool)).toEqual(["pay.charge"]);
  });

  it("does not touch real state: the sandbox has its own ledger and counters", async () => {
    const policy = parsePolicy({ limits: [{ id: "one", match: { tool: "orders.create" }, max_calls: 1, window_seconds: 60, per: "global" }] });
    const a = await simulatePolicy([rec({ step: 0 }), rec({ step: 1, ts_ms: 2 })], { registry: registry(), policy });
    expect(a.newly_blocked).toHaveLength(1);
    const b = await simulatePolicy([rec({ step: 0 })], { registry: registry(), policy }); // a fresh sandbox: the limit is not remembered
    expect(b.newly_blocked).toHaveLength(0);
  });
});

describe("replay with a change", () => {
  it("shows the decision that changes and how the rollback outlook changes", async () => {
    const run = [
      rec({ step: 0, ts_ms: 1, tool: "orders.create", result: { id: "o1" } }),
      rec({ step: 1, ts_ms: 2, tool: "pay.charge", args: { amount: 50 }, result: { charge_id: "c1" } }),
    ];
    const policy = parsePolicy({ rules: [{ id: "big", match: { tool: "pay.charge" }, when: [{ path: "$args.amount", op: "gt", value: 1000 }], action: "deny", reason: "too large" }] });
    const rep = await replayRun(run, { registry: registry(), policy }, [{ tool: "pay.charge", path: "$args.amount", value: 9000 }]);
    expect(rep.baseline.map((s) => s.verdict)).toEqual(["allow", "allow"]);
    expect(rep.variant.map((s) => s.verdict)).toEqual(["allow", "block"]);
    expect(rep.differences).toEqual([expect.objectContaining({ index: 1, tool: "pay.charge", before: "allow", after: "block" })]);
    expect(rep.baseline_plan?.actions.map((a) => a.tool)).toEqual(["pay.charge", "orders.create"]);
    expect(rep.baseline_plan?.actions[0]).toMatchObject({ residue: ["statement line stays"], verified: true });
  });
});

describe("speculative execution", () => {
  it("compares alternative plans and recommends the safest one that can run", async () => {
    const ctx = { registry: registry(), policy: parsePolicy({ risk: { thresholds: { deny: 95 } } }), environment: "prod" };
    const report = await speculate(
      [
        { name: "charge then email", calls: [{ tool: "orders.create" }, { tool: "pay.charge", args: { amount: 20 } }, { tool: "mail.send" }] },
        { name: "charge only", calls: [{ tool: "orders.create" }, { tool: "pay.charge", args: { amount: 20 } }] },
        { name: "charge without an order", calls: [{ tool: "pay.charge", args: { amount: 20 } }] },
      ],
      ctx,
    );
    expect(report.recommended).toBe("charge only");
    expect(report.plans.map((p) => p.name)).toEqual(["charge only", "charge then email", "charge without an order"]);
    const [only, withMail, bad] = report.plans as [(typeof report.plans)[number], (typeof report.plans)[number], (typeof report.plans)[number]];
    expect(only).toMatchObject({ fully_reversible: true, irreversible: [], approvals_needed: 0 });
    expect(only.residue).toEqual(["statement line stays"]);
    expect(withMail).toMatchObject({ irreversible: ["mail.send"], approvals_needed: 1, fully_reversible: false });
    expect(withMail.rank).toBeGreaterThan(only.rank);
    expect(bad.blocked_at).toBe(0);
    expect(bad.steps[0]?.reasons[0]).toContain("requires `orders.create`");
    expect(only.notes[0]).toContain("synthesized");
  });
});

describe("impact preview", () => {
  it("says what approving would do and what could be undone", async () => {
    const policy = parsePolicy({ risk: { thresholds: { approve: 50 } } });
    const p = await previewImpact({ registry: registry(), policy, environment: "prod" }, { tool: "pay.charge", args: { amount: 20 }, actor: "agent" });
    expect(p).toMatchObject({
      known: true,
      effect: "compensable",
      verdict: "needs_approval",
      risk: { data_class: "financial", blast_radius: "high" },
      requires: ["orders.create"],
      compensation: { tool: "pay.refund", residue: ["statement line stays"], verified: true },
    });
    expect(p.risk_score?.score).toBe(80);
    expect(p.rollback_outlook).toEqual(["undo by calling pay.refund", "but statement line stays", "the undo is read back and verified"]);
    expect(p.warnings).toEqual([]);

    const mail = await previewImpact({ registry: registry() }, { tool: "mail.send" });
    expect(mail.warnings).toContain("irreversible: once approved, this cannot be taken back");
    expect(mail.rollback_outlook[0]).toContain("cannot be undone");

    const unknown = await previewImpact({ registry: registry() }, { tool: "mystery" });
    expect(unknown).toMatchObject({ known: false, verdict: "block", warnings: ["unclassified tool"] });
  });
});
