import { describe, expect, it } from "vitest";
import { AGENT, MANIFESTS, OPERATOR, build, connect, fakeUpstream, json, textOf } from "./helpers.js";
import { validateSchema } from "../src/schema.js";
import { schemaHash } from "@multimindlab/reversi";

describe("schema checker", () => {
  const schema = { type: "object", required: ["amount"], additionalProperties: false, properties: { amount: { type: "number", minimum: 1, maximum: 100 }, note: { type: "string", maxLength: 5 }, kind: { enum: ["a", "b"] } } };
  it("accepts good values and names what is wrong", () => {
    expect(validateSchema(schema, { amount: 5 })).toEqual([]);
    expect(validateSchema(schema, {})).toEqual([expect.stringContaining("missing required `amount`")]);
    expect(validateSchema(schema, { amount: 500 })[0]).toContain("above maximum");
    expect(validateSchema(schema, { amount: "5" })[0]).toContain("expected number");
    expect(validateSchema(schema, { amount: 5, extra: 1 })[0]).toContain("unexpected `extra`");
    expect(validateSchema(schema, { amount: 5, kind: "z" })[0]).toContain("one of");
    expect(validateSchema({ anyOf: [{ type: "string" }, { type: "number" }] }, true)[0]).toContain("none of");
  });
});

describe("gateway features", () => {
  it("blocks arguments that do not match the tool's input schema", async () => {
    const f = await fakeUpstream("up", { create_order: () => json({ id: "o1" }), cancel_order: () => json({}), lookup: () => json({}), refund: () => json({}) }, false, {
      create_order: { inputSchema: { required: ["sku"], properties: { sku: { type: "string" } } } },
    });
    const { gateway } = build({ fakes: [f] });
    const { client } = await connect(gateway, AGENT);
    const bad = await client.callTool({ name: "create_order", arguments: { sku: 5 } });
    expect(bad.isError).toBe(true);
    expect(textOf(bad)).toContain("input schema");
    expect(f.calls).toHaveLength(0);
    expect((await client.callTool({ name: "create_order", arguments: { sku: "x" } })).isError).toBeFalsy();
  });

  it("marks a result that breaks the output schema, and does not trust it for the undo", async () => {
    const f = await fakeUpstream("up", { create_order: () => ({ content: [{ type: "text", text: "{}" }], structuredContent: { id: 7 } }), cancel_order: () => json({}), lookup: () => json({}), refund: () => json({}) }, false, {
      create_order: { outputSchema: { type: "object", required: ["id"], properties: { id: { type: "string" } } } },
    });
    const { gateway, reversi } = build({ fakes: [f] });
    const { client, run } = await connect(gateway, AGENT);
    await client.callTool({ name: "create_order", arguments: {} });
    const detail = reversi.ledger.forRun(run!.run_id).map((r) => r.detail ?? "").join(" ");
    expect(detail).toContain("output schema");
  });

  it("notices a tool whose schema changed since the manifest was approved", async () => {
    const tool = { name: "create_order", inputSchema: { type: "object", properties: { sku: { type: "string" } } } };
    const manifests = [{ ...MANIFESTS[0]!, schema_hash: schemaHash(tool as never) }, ...MANIFESTS.slice(1)];
    const f = await fakeUpstream("up", { create_order: () => json({ id: "o1" }), cancel_order: () => json({}), lookup: () => json({}), refund: () => json({}) }, false, {
      create_order: { inputSchema: { properties: { sku: { type: "string" }, extra: { type: "string" } } } }, // upstream added a field
    });
    const { gateway } = build({ fakes: [f], manifests });
    const { client } = await connect(gateway, AGENT);
    const r = await client.callTool({ name: "create_order", arguments: {} });
    expect(r.isError).toBe(true);
    expect(textOf(r)).toContain("schema changed");
  });

  it("lets an unclassified read through when asked to, and still blocks unclassified changes", async () => {
    const f = await fakeUpstream("up", { peek: () => json({ ok: 1 }), mutate: () => json({}), create_order: () => json({ id: "o" }), cancel_order: () => json({}), lookup: () => json({}), refund: () => json({}) }, false, {
      peek: { annotations: { readOnlyHint: true } },
    });
    const { gateway } = build({ fakes: [f], gw: { unclassified_reads: "observe" } });
    const { client } = await connect(gateway, AGENT);
    expect((await client.callTool({ name: "peek", arguments: {} })).isError).toBeFalsy();
    expect((await client.callTool({ name: "mutate", arguments: {} })).isError).toBe(true);
    const strict = build({ fakes: [f] });
    const s = await connect(strict.gateway, AGENT);
    expect((await s.client.callTool({ name: "peek", arguments: {} })).isError).toBe(true);
  });

  it("adds an advisory note in advise mode and blocks nothing", async () => {
    const f = await fakeUpstream("up", { mystery: () => json({ ok: 1 }) });
    const { gateway } = build({ fakes: [f], mode: "advise" });
    const { client } = await connect(gateway, AGENT);
    const r = await client.callTool({ name: "mystery", arguments: {} });
    expect(r.isError).toBeFalsy();
    expect(JSON.stringify(r.content)).toContain("Reversi advisory");
  });

  it("times out a slow tool as uncertain, and retries only safe tools", async () => {
    let slow = 0;
    let flaky = 0;
    const f = await fakeUpstream("up", {
      slow: async () => {
        slow++;
        await new Promise((r) => setTimeout(r, 300));
        return json({});
      },
      flaky: () => {
        if (++flaky < 3) throw new Error("boom");
        return json({ ok: true });
      },
    });
    const manifests = [
      { tool: "slow", effect: "idempotent", permission: "p", timeout_ms: 50 },
      { tool: "flaky", effect: "read_only", permission: "p", retry: { attempts: 3, base_ms: 1, max_ms: 5 } },
    ];
    const { gateway } = build({ fakes: [f], manifests });
    const { client, run } = await connect(gateway, AGENT);
    expect((await client.callTool({ name: "flaky", arguments: {} })).isError).toBeFalsy();
    expect(flaky).toBe(3);
    await client.callTool({ name: "slow", arguments: {} }).catch(() => undefined);
    expect(slow).toBe(1);
    expect(run!.state().steps.find((s) => s.tool === "slow")?.status).not.toBe("succeeded");
  });

  it("classifies the upstream tools and previews impact", async () => {
    const f = await fakeUpstream("up", { create_order: () => json({}), cancel_order: () => json({}), lookup: () => json({}), refund: () => json({}), novel: () => json({}) });
    const { gateway } = build({ fakes: [f] });
    const c = await gateway.classification();
    expect(c.rows.find((r) => r.name === "novel")?.class).toBe("unclassified_mutation");
    expect(c.banner).toContain("no manifest");
    const { client } = await connect(gateway, AGENT);
    const prev = (await client.callTool({ name: "reversi.preview_impact", arguments: { tool: "create_order" } })).structuredContent as { effect: string; rollback_outlook: string[] };
    expect(prev.effect).toBe("reversible");
    expect(prev.rollback_outlook.length).toBeGreaterThan(0);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toContain("reversi.search");
    expect(names).not.toContain("reversi.reload");
    const op = await connect(gateway, OPERATOR, true);
    expect((await op.client.listTools()).tools.map((t) => t.name)).toContain("reversi.reload");
  });

  it("reports connectors with their classification counts", async () => {
    const f = await fakeUpstream("up", { create_order: () => json({}), novel: () => json({}) });
    const { gateway } = build({ fakes: [f] });
    const rows = await gateway.connectors();
    expect(rows[0]).toMatchObject({ name: "up", kind: "stdio", healthy: true, tools: 2, classified: 1, unclassified: 1 });
  });
});
