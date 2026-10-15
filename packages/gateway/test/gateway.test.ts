import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Ledger, Registry, Reversi } from "@multimindlab/reversi";
import { describe, expect, it } from "vitest";
import { createGateway } from "../src/index.js";

const MANIFESTS = [
  {
    tool: "create_order",
    effect: "reversible",
    permission: "orders:write",
    compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } },
  },
  { tool: "cancel_order", effect: "idempotent", permission: "orders:write" },
  { tool: "flaky", effect: "idempotent", permission: "orders:write" },
];

const TOOLS = ["create_order", "cancel_order", "flaky", "mystery"].map((name) => ({
  name,
  description: name,
  inputSchema: { type: "object" as const, properties: {} },
}));

async function setup() {
  const seen: Array<{ name: string; args: unknown }> = [];
  const fake = new Server({ name: "fake", version: "1" }, { capabilities: { tools: {} } });
  fake.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  fake.setRequestHandler(CallToolRequestSchema, async (req) => {
    seen.push({ name: req.params.name, args: req.params.arguments });
    if (req.params.name === "flaky") return { isError: true, content: [{ type: "text", text: "nope" }] };
    if (req.params.name === "create_order") return { content: [{ type: "text", text: JSON.stringify({ id: 42 }) }] };
    return { content: [{ type: "text", text: "ok" }] };
  });
  const [upServer, upClient] = InMemoryTransport.createLinkedPair();
  await fake.connect(upServer);
  const upstream = new Client({ name: "gw", version: "1" });
  await upstream.connect(upClient);

  const reversi = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger() });
  const { server, run } = createGateway({ reversi, upstream, actor: "mcp-client", permissions: ["orders:write"] });
  const [gwServer, gwClient] = InMemoryTransport.createLinkedPair();
  await server.connect(gwServer);
  const client = new Client({ name: "agent", version: "1" });
  await client.connect(gwClient);
  return { client, reversi, run, seen };
}

const events = (rv: Reversi) => rv.ledger.records().map((r) => `${r.event}:${r.tool}`);

describe("observe-mode gateway", () => {
  it("forwards tools/list unchanged", async () => {
    const { client } = await setup();
    expect((await client.listTools()).tools.map((t) => t.name)).toEqual(TOOLS.map((t) => t.name));
  });

  it("journals intent then outcome and returns the upstream result unchanged", async () => {
    const { client, reversi, run, seen } = await setup();
    const res = await client.callTool({ name: "create_order", arguments: { sku: "A1" } });
    expect(res.content).toEqual([{ type: "text", text: JSON.stringify({ id: 42 }) }]);
    expect(seen).toEqual([{ name: "create_order", args: { sku: "A1" } }]);
    expect(events(reversi)).toEqual(["run_started:-", "intended:create_order", "succeeded:create_order"]);
    expect(reversi.ledger.verify().ok).toBe(true);
    // The JSON result feeds the compensation handle, so rollback is planned for the real id.
    const plan = run.plan();
    expect(plan.actions[0]).toMatchObject({ kind: "compensate", compensation_tool: "cancel_order", args: { id: 42 } });
  });

  it("uses the reason from _meta when given", async () => {
    const { client, reversi } = await setup();
    await client.callTool({ name: "cancel_order", arguments: {}, _meta: { "reversi/reason": "customer asked" } });
    expect(reversi.ledger.records().find((r) => r.event === "intended")?.reason).toBe("customer asked");
  });

  it("records isError results as failed and still returns them", async () => {
    const { client, reversi, run } = await setup();
    const res = await client.callTool({ name: "flaky", arguments: {} });
    expect(res.isError).toBe(true);
    expect(events(reversi).slice(-1)).toEqual(["failed:flaky"]);
    expect(run.state().steps[0]?.status).toBe("failed");
  });

  it("never blocks: an unmanifested tool runs and is journaled as would_block", async () => {
    const { client, reversi, seen } = await setup();
    const res = await client.callTool({ name: "mystery", arguments: {} });
    expect(res.isError).toBeFalsy();
    expect(seen.map((s) => s.name)).toEqual(["mystery"]);
    expect(events(reversi)).toEqual([
      "run_started:-",
      "would_block:mystery",
      "intended:mystery",
      "succeeded:mystery",
    ]);
  });
});
