import { describe, expect, it } from "vitest";
import { parsePolicy } from "@multimindlab/reversi";
import { allowDenyPolicy } from "../src/index.js";
import { AGENT, OPERATOR, build, connect, fakeUpstream, json, textOf } from "./helpers.js";

const orders = () =>
  fakeUpstream("shop", {
    create_order: () => json({ id: 42 }),
    cancel_order: () => json({ ok: true }),
    refund: () => json({ refunded: true }),
    lookup: () => json({ found: true }),
    mystery: () => json({ x: 1 }),
    flaky: () => ({ isError: true, content: [{ type: "text", text: "nope" }] }),
  });

const events = (rv: ReturnType<typeof build>["reversi"]) => rv.ledger.records().map((r) => `${r.event}:${r.tool}`);

describe("observe mode", () => {
  it("forwards tools/list, journals intent then outcome, returns the upstream result unchanged", async () => {
    const up = await orders();
    const { gateway, reversi } = build({ fakes: [up], mode: "observe" });
    const { client, run } = await connect(gateway, AGENT);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(["create_order", "mystery", "reversi.get_run"]));
    const res = await client.callTool({ name: "create_order", arguments: { sku: "A1" } });
    expect(textOf(res)).toBe('{"id":42}');
    expect(up.calls).toEqual([{ name: "create_order", args: { sku: "A1" }, meta: undefined }]);
    expect(events(reversi)).toEqual(["run_started:-", "intended:create_order", "succeeded:create_order"]);
    expect(reversi.ledger.verify().ok).toBe(true);
    expect(run?.plan().actions[0]).toMatchObject({ kind: "compensate", compensation_tool: "cancel_order", args: { id: 42 } });
  });

  it("uses _meta reason, records isError as failed, and never blocks (would_block)", async () => {
    const up = await orders();
    const { gateway, reversi } = build({ fakes: [up], mode: "observe", manifests: [...(await import("./helpers.js")).MANIFESTS, { tool: "flaky", effect: "idempotent", permission: "orders:write" }] });
    const { client } = await connect(gateway, AGENT);
    await client.callTool({ name: "lookup", arguments: {}, _meta: { "reversi/reason": "customer asked" } });
    expect(reversi.ledger.records().find((r) => r.event === "intended")?.reason).toBe("customer asked");
    expect((await client.callTool({ name: "flaky", arguments: {} })).isError).toBe(true);
    await client.callTool({ name: "mystery", arguments: {} });
    expect(up.calls.map((c) => c.name)).toEqual(["lookup", "flaky", "mystery"]);
    expect(events(reversi)).toContain("would_block:mystery");
    expect(events(reversi)).toContain("failed:flaky");
  });
});

describe("enforce mode", () => {
  it("blocks calls with no manifest or out of scope without forwarding them", async () => {
    const up = await orders();
    const { gateway, reversi } = build({ fakes: [up], gw: { permissions: ["orders:read"] } });
    const { client } = await connect(gateway, AGENT);
    const a = await client.callTool({ name: "mystery", arguments: {} });
    const b = await client.callTool({ name: "create_order", arguments: {} });
    expect(a.isError).toBe(true);
    expect(textOf(a)).toContain("Blocked by Reversi");
    expect(textOf(b)).toContain("not in the run's scope");
    expect((await client.callTool({ name: "lookup", arguments: {} })).isError).toBeFalsy();
    expect(up.calls.map((c) => c.name)).toEqual(["lookup"]);
    expect(events(reversi).filter((e) => e.startsWith("blocked"))).toHaveLength(2);
  });

  it("caps the scope at the principal's max_permissions", async () => {
    const up = await orders();
    const { gateway } = build({ fakes: [up] });
    const { client } = await connect(gateway, { ...AGENT, max_permissions: ["orders:read"] });
    expect((await client.callTool({ name: "create_order", arguments: {} })).isError).toBe(true);
    expect((await client.callTool({ name: "lookup", arguments: {} })).isError).toBeFalsy();
  });

  it("allow and deny lists hide tools and block calls", async () => {
    const up = await orders();
    const cfg = { allow: ["lookup", "create_*"], deny: ["create_order"] };
    const policy = allowDenyPolicy(cfg);
    const { gateway, reversi } = build({ fakes: [up], policy, gw: { allow: cfg.allow, deny: cfg.deny } });
    const { client } = await connect(gateway, AGENT);
    const names = (await client.listTools()).tools.map((t) => t.name).filter((n) => !n.startsWith("reversi."));
    expect(names).toEqual(["lookup"]);
    expect(textOf(await client.callTool({ name: "create_order", arguments: {} }))).toContain("gateway-deny-0");
    expect(textOf(await client.callTool({ name: "refund", arguments: {} }))).toContain("default deny");
    expect((await client.callTool({ name: "lookup", arguments: {} })).isError).toBeFalsy();
    expect(up.calls.map((c) => c.name)).toEqual(["lookup"]);
    expect(reversi.ledger.verify().ok).toBe(true);
  });

  it("policy rules, content checks and the kill switch apply", async () => {
    const up = await orders();
    const policy = parsePolicy({ rules: [{ id: "no-refund", match: { tool: "refund" }, action: "deny" }] });
    const { gateway, reversi } = build({ fakes: [up], policy, content: true });
    const { client } = await connect(gateway, AGENT);
    expect(textOf(await client.callTool({ name: "refund", arguments: {} }))).toContain("no-refund");
    const enc = Buffer.from("ghp_" + "a".repeat(36) + " and more text").toString("base64");
    expect(textOf(await client.callTool({ name: "lookup", arguments: { q: enc } }))).toContain("approval required");
    reversi.halt("incident");
    expect(textOf(await client.callTool({ name: "lookup", arguments: {} }))).toContain("kill switch: incident");
  });

  it("an upstream transport error is journaled as uncertain and surfaces to the client", async () => {
    const up = await orders();
    const { gateway, reversi } = build({ fakes: [up] });
    const { client, run } = await connect(gateway, AGENT);
    await up.entry.client.close();
    await expect(client.callTool({ name: "lookup", arguments: {} })).rejects.toThrow();
    expect(events(reversi).slice(-1)).toEqual(["uncertain:lookup"]);
    expect(run?.unresolved()).toEqual([0]);
  });
});

describe("approval flow across endpoints", () => {
  it("queues, an operator approves through the operator endpoint, the agent retries once", async () => {
    const up = await orders();
    const { gateway } = build({ fakes: [up] });
    const agent = await connect(gateway, AGENT);
    const ops = await connect(gateway, OPERATOR, true);

    const first = await agent.client.callTool({ name: "refund", arguments: { amount: 5 } });
    expect(first.isError).toBe(true);
    expect(textOf(first)).toContain("pending an operator decision");
    expect(up.calls).toHaveLength(0);

    const pending = JSON.parse(textOf(await ops.client.callTool({ name: "reversi.list_approvals", arguments: { status: "pending" } }))).approvals;
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ tool: "refund", arg_keys: ["amount"] });
    await ops.client.callTool({ name: "reversi.approve_action", arguments: { id: pending[0].id, note: "ok" } });

    expect((await agent.client.callTool({ name: "refund", arguments: { amount: 5 } })).isError).toBeFalsy();
    expect(up.calls.map((c) => c.name)).toEqual(["refund"]);
    expect((await agent.client.callTool({ name: "refund", arguments: { amount: 5 } })).isError).toBe(true); // consumed
  });

  it("agents cannot see or call operator tools", async () => {
    const up = await orders();
    const { gateway } = build({ fakes: [up] });
    const agent = await connect(gateway, AGENT);
    const names = (await agent.client.listTools()).tools.map((t) => t.name).filter((n) => n.startsWith("reversi."));
    expect(names).toEqual(expect.arrayContaining(["reversi.get_run", "reversi.plan_rollback"]));
    for (const forbidden of ["reversi.approve_action", "reversi.execute_rollback", "reversi.halt", "reversi.export_evidence", "reversi.list_approvals"]) {
      expect(names).not.toContain(forbidden);
      await expect(agent.client.callTool({ name: forbidden, arguments: { id: "x", run_id: "x", reason: "x", confirm: true } })).rejects.toThrow(/unknown tool/);
    }
  });

  it("operator tools follow the principal's roles", async () => {
    const up = await orders();
    const { gateway } = build({ fakes: [up] });
    const audit = await connect(gateway, { name: "aud", roles: ["auditor"], via: "api_key" }, true);
    const names = (await audit.client.listTools()).tools.map((t) => t.name);
    expect(names).toContain("reversi.list_approvals");
    expect(names).not.toContain("reversi.approve_action");
    expect(names).not.toContain("reversi.halt");
    expect(names).not.toContain("create_order"); // no upstream tools on the operator endpoint
    const appr = await connect(gateway, { name: "ap", roles: ["approver"], via: "api_key" }, true);
    expect((await appr.client.listTools()).tools.map((t) => t.name)).not.toContain("reversi.execute_rollback");
  });
});

describe("reversi tools for agents", () => {
  it("show an agent only its own runs", async () => {
    const up = await orders();
    const { gateway } = build({ fakes: [up] });
    const a = await connect(gateway, AGENT);
    const b = await connect(gateway, { name: "agent-2", roles: ["agent"], via: "api_key" });
    await a.client.callTool({ name: "lookup", arguments: {} });
    const mine = JSON.parse(textOf(await a.client.callTool({ name: "reversi.list_runs", arguments: {} }))).runs;
    expect(mine).toEqual([a.run?.run_id]);
    const state = JSON.parse(textOf(await a.client.callTool({ name: "reversi.get_run", arguments: { run_id: a.run?.run_id } })));
    expect(state.steps).toHaveLength(1);
    const other = await b.client.callTool({ name: "reversi.get_run", arguments: { run_id: a.run?.run_id } });
    expect(other.isError).toBe(true);
    expect(textOf(other)).toContain("not found");
    const trace = JSON.parse(textOf(await a.client.callTool({ name: "reversi.get_action_trace", arguments: { run_id: a.run?.run_id } })));
    expect(trace.records.map((r: { event: string }) => r.event)).toEqual(["run_started", "intended", "succeeded"]);
    const plan = JSON.parse(textOf(await a.client.callTool({ name: "reversi.plan_rollback", arguments: { run_id: a.run?.run_id } })));
    expect(plan.fully_reversible).toBe(true);
  });

  it("validates manifests", async () => {
    const up = await orders();
    const { gateway } = build({ fakes: [up] });
    const a = await connect(gateway, AGENT);
    const bad = JSON.parse(textOf(await a.client.callTool({ name: "reversi.validate_manifest", arguments: { manifest: { tool: "x", effect: "reversible", permission: "p" } } })));
    expect(bad.valid).toBe(false);
    expect(bad.errors.join()).toContain("must declare a compensation");
  });
});

describe("rollback through the upstreams", () => {
  it("dry-runs by default, executes with confirm, passes the idempotency key, and is repeatable", async () => {
    const up = await orders();
    const { gateway, reversi } = build({ fakes: [up] });
    const agent = await connect(gateway, AGENT);
    const ops = await connect(gateway, OPERATOR, true);
    await agent.client.callTool({ name: "create_order", arguments: { sku: "A" } });
    const id = agent.run?.run_id;

    const dry = JSON.parse(textOf(await ops.client.callTool({ name: "reversi.execute_rollback", arguments: { run_id: id } })));
    expect(dry.dry_run).toBe(true);
    expect(up.calls.map((c) => c.name)).toEqual(["create_order"]);

    const done = JSON.parse(textOf(await ops.client.callTool({ name: "reversi.execute_rollback", arguments: { run_id: id, confirm: true } })));
    expect(done.report).toMatchObject({ complete: true, compensated: [0] });
    const comp = up.calls.at(-1);
    expect(comp).toMatchObject({ name: "cancel_order", args: { id: 42 } });
    expect((comp?.meta as Record<string, unknown>)["reversi/idempotency_key"]).toMatch(/^[0-9a-f]{64}$/);
    expect(reversi.ledger.records().at(-1)).toMatchObject({ event: "compensated", actor: "ops" });
    expect(reversi.ledger.verify().ok).toBe(true);

    const again = JSON.parse(textOf(await ops.client.callTool({ name: "reversi.execute_rollback", arguments: { run_id: id, confirm: true } })));
    expect(again.report.compensated).toEqual([]);
    expect(up.calls.filter((c) => c.name === "cancel_order")).toHaveLength(1);
  });

  it("refuses a second concurrent rollback of the same run, so compensations are not run twice", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const up = await fakeUpstream("shop", { create_order: () => json({ id: 1 }), cancel_order: async () => { await gate; return json({ ok: true }); } });
    const { gateway } = build({ fakes: [up] });
    const agent = await connect(gateway, AGENT);
    const ops = await connect(gateway, OPERATOR, true);
    await agent.client.callTool({ name: "create_order", arguments: {} });
    const args = { run_id: agent.run?.run_id, confirm: true };
    const first = ops.client.callTool({ name: "reversi.execute_rollback", arguments: args });
    await new Promise((r) => setTimeout(r, 50));
    const second = await ops.client.callTool({ name: "reversi.execute_rollback", arguments: args });
    expect(second.isError).toBe(true);
    expect(textOf(second)).toContain("already in progress");
    release();
    expect(JSON.parse(textOf(await first)).report.complete).toBe(true);
    expect(up.calls.filter((c) => c.name === "cancel_order")).toHaveLength(1);
    // and the lock is released afterwards
    expect(JSON.parse(textOf(await ops.client.callTool({ name: "reversi.execute_rollback", arguments: args }))).report.compensated).toEqual([]);
  });

  it("reports a failed compensation honestly", async () => {
    const up = await fakeUpstream("shop", { create_order: () => json({ id: 1 }), cancel_order: () => ({ isError: true, content: [{ type: "text", text: "locked" }] }) });
    const { gateway } = build({ fakes: [up] });
    const agent = await connect(gateway, AGENT);
    const ops = await connect(gateway, OPERATOR, true);
    await agent.client.callTool({ name: "create_order", arguments: {} });
    const out = JSON.parse(textOf(await ops.client.callTool({ name: "reversi.execute_rollback", arguments: { run_id: agent.run?.run_id, confirm: true } })));
    expect(out.report.complete).toBe(false);
    expect(out.report.failed[0].error).toContain("locked");
    expect(out.report.failed[0].error).toContain("after 3 attempts");
  });

  it("compensations that need approval run only when the operator passes approve_compensations", async () => {
    const manifests = [
      { tool: "create_order", effect: "compensable", permission: "orders:write", compensation: { tool: "cancel_order", requires_approval: true, argument_map: { id: "$result.id" } } },
      { tool: "cancel_order", effect: "idempotent", permission: "orders:write" },
    ];
    const up = await orders();
    const { gateway } = build({ fakes: [up], manifests });
    const agent = await connect(gateway, AGENT);
    await agent.client.callTool({ name: "create_order", arguments: {} });
    const operator = await connect(gateway, { name: "op", roles: ["operator"], via: "api_key" }, true);
    const id = agent.run?.run_id;
    const first = JSON.parse(textOf(await operator.client.callTool({ name: "reversi.execute_rollback", arguments: { run_id: id, confirm: true } })));
    expect(first.report.awaiting_approval).toEqual([0]);
    expect(up.calls.map((c) => c.name)).toEqual(["create_order"]);
    const second = JSON.parse(textOf(await operator.client.callTool({ name: "reversi.execute_rollback", arguments: { run_id: id, confirm: true, approve_compensations: true } })));
    expect(second.report).toMatchObject({ complete: true, compensated: [0] });
    expect(up.calls.map((c) => c.name)).toEqual(["create_order", "cancel_order"]);
  });
});

describe("multiple upstreams", () => {
  it("namespaces tool names and routes calls to the right upstream", async () => {
    const a = await fakeUpstream("github", { create_issue: () => json({ n: 1 }) }, true);
    const b = await fakeUpstream("jira", { create_issue: () => json({ n: 2 }) }, true);
    const { gateway } = build({
      fakes: [a, b],
      manifests: [
        { tool: "github.create_issue", effect: "idempotent", permission: "gh:w" },
        { tool: "jira.create_issue", effect: "idempotent", permission: "jira:w" },
      ],
    });
    const { client } = await connect(gateway, AGENT);
    expect((await client.listTools()).tools.map((t) => t.name)).toEqual(expect.arrayContaining(["github.create_issue", "jira.create_issue"]));
    expect(textOf(await client.callTool({ name: "jira.create_issue", arguments: {} }))).toBe('{"n":2}');
    expect(textOf(await client.callTool({ name: "github.create_issue", arguments: {} }))).toBe('{"n":1}');
    expect(a.calls.map((c) => c.name)).toEqual(["create_issue"]);
    expect(b.calls).toHaveLength(1);
  });

  it("refuses to expose colliding names without namespacing", async () => {
    const a = await fakeUpstream("a", { t: () => json(1) }, false);
    const b = await fakeUpstream("b", { t: () => json(2) }, false);
    const { gateway } = build({ fakes: [a, b], manifests: [{ tool: "t", effect: "read_only", permission: "p" }] });
    const { client } = await connect(gateway, AGENT);
    await expect(client.listTools()).rejects.toThrow(/collision/);
  });
});

describe("allowDenyPolicy", () => {
  it("is undefined with no lists, deny-only keeps default allow, allow makes default deny", () => {
    expect(allowDenyPolicy({ allow: [], deny: [] })).toBeUndefined();
    expect(allowDenyPolicy({ allow: [], deny: ["x"] })?.default).toBe("allow");
    expect(allowDenyPolicy({ allow: ["x"], deny: [] })?.default).toBe("deny");
  });
});

describe("continuing a run across sessions", () => {
  it("a reconnecting agent that names its run keeps its approvals and plan; others cannot take it", async () => {
    const up = await orders();
    const { gateway, reversi } = build({ fakes: [up] });
    const first = gateway.createSession({ principal: AGENT, operator: false, run_id: "my-run" });
    expect(first.run?.run_id).toBe("my-run");
    const again = gateway.createSession({ principal: AGENT, operator: false, run_id: "my-run" });
    expect(again.run?.run_id).toBe("my-run");
    expect(reversi.ledger.records().filter((r) => r.event === "run_started")).toHaveLength(1); // continued, not restarted
    expect(() => gateway.createSession({ principal: { ...AGENT, name: "other" }, operator: false, run_id: "my-run" })).toThrow(/another principal/);
  });
});

describe("tools no upstream offers", () => {
  it("in observe mode the call is journaled as failed (nothing was sent), not uncertain", async () => {
    const up = await orders();
    const { gateway, reversi } = build({ fakes: [up], mode: "observe" });
    const { client } = await connect(gateway, AGENT);
    await expect(client.callTool({ name: "no_such_tool", arguments: {} })).rejects.toThrow(/unknown tool/);
    expect(events(reversi).slice(-2)).toEqual(["intended:no_such_tool", "failed:no_such_tool"]);
  });
});
