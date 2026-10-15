import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Ledger, Registry, Reversi, parseJsonl, verifyRecords } from "@multimindlab/reversi";
import { Grants, createApp } from "../src/index.js";

const MANIFESTS = [
  { tool: "create_order", effect: "reversible", permission: "orders:write", compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } } },
  { tool: "cancel_order", effect: "idempotent", permission: "orders:write" },
  { tool: "send_email", effect: "irreversible", permission: "mail:send" },
  { tool: "reverse", effect: "idempotent", permission: "orders:write" },
  { tool: "risky", effect: "compensable", permission: "orders:write", compensation: { tool: "reverse", requires_approval: true } },
];

function make() {
  const grants = new Grants();
  const reversi = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(), approver: grants.asApprover() });
  const app = createApp({
    reversi,
    grants,
    keys: [
      { name: "agent-a", role: "agent", key: "ka", max_permissions: ["orders:write", "mail:send"] },
      { name: "agent-b", role: "agent", key: "kb" },
      { name: "ops", role: "operator", key_sha256: createHash("sha256").update("ko").digest("hex") },
    ],
  });
  const call = async (key: string | null, method: string, path: string, body?: unknown) => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (key) headers.authorization = `Bearer ${key}`;
    const res = await app.request(path, { method, headers, body: body === undefined || method === "GET" ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let json: any;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: res.status, json, text };
  };
  return { call, reversi };
}

async function newRun(call: ReturnType<typeof make>["call"], id = "r1", key = "ka") {
  return call(key, "POST", "/v1/runs", { run_id: id, permissions: ["orders:write", "mail:send"] });
}

describe("auth", () => {
  it("healthz is open; everything else needs a key", async () => {
    const { call } = make();
    expect((await call(null, "GET", "/healthz")).status).toBe(200);
    expect((await call(null, "GET", "/v1/runs")).status).toBe(401);
    expect((await call("wrong", "GET", "/v1/runs")).status).toBe(401);
  });
  it("agent keys cannot reach the operator plane", async () => {
    const { call } = make();
    await newRun(call);
    for (const [m, p] of [
      ["GET", "/v1/runs/r1/plan"],
      ["POST", "/v1/runs/r1/steps/0/compensation"],
      ["POST", "/v1/runs/r1/approvals"],
      ["GET", "/v1/runs/r1/export"],
      ["GET", "/v1/ledger/verify"],
    ] as const) {
      expect((await call("ka", m, p, {})).status, p).toBe(403);
    }
  });
  it("agents cannot see each other's runs", async () => {
    const { call } = make();
    await newRun(call);
    expect((await call("kb", "GET", "/v1/runs/r1")).status).toBe(404);
    expect((await call("kb", "POST", "/v1/runs/r1/intents", { tool: "create_order", reason: "x" })).status).toBe(404);
    expect((await call("kb", "GET", "/v1/runs")).json.runs).toEqual([]);
    expect((await call("ko", "GET", "/v1/runs")).json.runs).toEqual(["r1"]);
  });
  it("the actor is the key's name, not whatever the body claims", async () => {
    const { call, reversi } = make();
    await call("ka", "POST", "/v1/runs", { run_id: "r1", permissions: ["orders:write"], actor: "root" });
    expect(reversi.openRun("r1").state().actor).toBe("agent-a");
  });
  it("enforces a key's permission cap", async () => {
    const { call } = make();
    const r = await call("ka", "POST", "/v1/runs", { permissions: ["admin:*"] });
    expect(r.status).toBe(403);
  });
});

describe("validation", () => {
  it("rejects bad bodies and ids", async () => {
    const { call } = make();
    expect((await call("ka", "POST", "/v1/runs", { permissions: "x" })).status).toBe(400);
    expect((await call("ka", "POST", "/v1/runs", { run_id: "../x", permissions: [] })).status).toBe(400);
    expect((await call("ka", "POST", "/v1/runs", { permissions: [], mode: "yolo" })).status).toBe(400);
    await newRun(call);
    expect((await call("ka", "POST", "/v1/runs/r1/intents", { tool: "create_order" })).status).toBe(400); // no reason
    expect((await call("ka", "POST", "/v1/runs/r1/intents", [1])).status).toBe(400);
    expect((await call("ka", "POST", "/v1/runs/r1/steps/x/outcome", { status: "succeeded" })).status).toBe(400);
  });
  it("duplicate run ids conflict", async () => {
    const { call } = make();
    await newRun(call);
    expect((await newRun(call)).status).toBe(409);
  });
  it("caps body size", async () => {
    const { call } = make();
    await newRun(call);
    const r = await call("ka", "POST", "/v1/runs/r1/intents", { tool: "create_order", reason: "x", args: "a".repeat(1_100_000) });
    expect(r.status).toBe(413);
  });
});

describe("full flow", () => {
  it("intent -> outcome -> plan -> compensation -> export verifies", async () => {
    const { call } = make();
    await newRun(call);
    const i = await call("ka", "POST", "/v1/runs/r1/intents", { tool: "create_order", args: { sku: "A1" }, reason: "order" });
    expect(i.json).toEqual({ decision: "allow", step: 0 });
    expect((await call("ka", "POST", "/v1/runs/r1/steps/0/outcome", { status: "succeeded", result: { id: 5 } })).json).toEqual({ step: 0, status: "succeeded" });
    // an outcome cannot be reported twice
    expect((await call("ka", "POST", "/v1/runs/r1/steps/0/outcome", { status: "failed" })).status).toBe(409);

    const plan = await call("ko", "GET", "/v1/runs/r1/plan");
    expect(plan.json.actions[0]).toMatchObject({ kind: "compensate", compensation_tool: "cancel_order", args: { id: 5 } });

    const start = await call("ko", "POST", "/v1/runs/r1/steps/0/compensation");
    expect(start.json.decision).toBe("go");
    expect(start.json.call).toMatchObject({ tool: "cancel_order", args: { id: 5 } });
    expect((await call("ko", "POST", "/v1/runs/r1/steps/0/compensation/outcome", { status: "compensated" })).status).toBe(200);

    const ex = await call("ko", "GET", "/v1/runs/r1/export");
    expect(ex.status).toBe(200);
    expect(verifyRecords(parseJsonl(ex.text)).ok).toBe(true);
    expect((await call("ko", "GET", "/v1/ledger/verify")).json.ok).toBe(true);
    expect(ex.text).not.toContain("A1");
  });

  it("blocks out-of-scope calls", async () => {
    const { call } = make();
    await call("ka", "POST", "/v1/runs", { run_id: "r1", permissions: ["orders:write"] });
    const r = await call("ka", "POST", "/v1/runs/r1/intents", { tool: "send_email", reason: "mail" });
    expect(r.json.decision).toBe("block");
  });

  it("an irreversible call needs an operator grant, and a grant is single-use", async () => {
    const { call } = make();
    await newRun(call);
    const intent = () => call("ka", "POST", "/v1/runs/r1/intents", { tool: "send_email", reason: "mail" });
    expect((await intent()).json.decision).toBe("block");
    // the agent cannot grant itself approval
    expect((await call("ka", "POST", "/v1/runs/r1/approvals", { tool: "send_email" })).status).toBe(403);
    expect((await call("ko", "POST", "/v1/runs/r1/approvals", { tool: "send_email" })).status).toBe(201);
    expect((await intent()).json.decision).toBe("allow");
    expect((await intent()).json.decision).toBe("block");
  });

  it("compensations that need approval wait for a grant", async () => {
    const { call } = make();
    await newRun(call);
    await call("ka", "POST", "/v1/runs/r1/intents", { tool: "risky", reason: "x" });
    await call("ka", "POST", "/v1/runs/r1/steps/0/outcome", { status: "succeeded", result: {} });
    expect((await call("ko", "POST", "/v1/runs/r1/steps/0/compensation")).json.decision).toBe("awaiting_approval");
    await call("ko", "POST", "/v1/runs/r1/approvals", { tool: "reverse", kind: "compensation" });
    expect((await call("ko", "POST", "/v1/runs/r1/steps/0/compensation")).json.decision).toBe("go");
  });

  it("reports unresolved intents on run state", async () => {
    const { call } = make();
    await newRun(call);
    await call("ka", "POST", "/v1/runs/r1/intents", { tool: "create_order", reason: "x" });
    expect((await call("ka", "GET", "/v1/runs/r1")).json.unresolved).toEqual([0]);
  });
});
