import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { Approvals, ContentChecker, Ledger, Policy, Registry, Reversi, type Principal, type PolicyDoc } from "@multimindlab/reversi";
import { Gateway, UpstreamPool, type GatewayOptions } from "../src/index.js";

export type Handler = (args: Record<string, unknown> | undefined, meta: Record<string, unknown> | undefined) => CallToolResult | Promise<CallToolResult>;
export interface Fake {
  entry: { name: string; client: Client; namespace: boolean };
  calls: Array<{ name: string; args: unknown; meta: unknown }>;
}

export const json = (v: unknown): CallToolResult => ({ content: [{ type: "text", text: JSON.stringify(v) }] });

export async function fakeUpstream(name: string, tools: Record<string, Handler>, namespace = false): Promise<Fake> {
  const calls: Fake["calls"] = [];
  const server = new Server({ name, version: "1" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: Object.keys(tools).map((n) => ({ name: n, description: n, inputSchema: { type: "object" as const, properties: {} } })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    calls.push({ name: req.params.name, args: req.params.arguments, meta: req.params._meta });
    const h = tools[req.params.name];
    if (!h) throw new Error("unknown");
    return h(req.params.arguments, req.params._meta);
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name: "gw", version: "1" });
  await client.connect(b);
  return { entry: { name, client, namespace }, calls };
}

export const MANIFESTS = [
  { tool: "create_order", effect: "reversible", permission: "orders:write", compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } } },
  { tool: "cancel_order", effect: "idempotent", permission: "orders:write" },
  { tool: "refund", effect: "idempotent", permission: "pay:write", approval: "always" },
  { tool: "lookup", effect: "read_only", permission: "orders:read" },
];

export const AGENT: Principal = { name: "agent-1", roles: ["agent"], via: "api_key" };
export const OPERATOR: Principal = { name: "ops", roles: ["admin"], via: "api_key" };

export function build(opts: { fakes: Fake[]; manifests?: unknown[]; mode?: "observe" | "enforce"; policy?: PolicyDoc; content?: boolean; gw?: Partial<GatewayOptions> }) {
  const approvals = new Approvals();
  const reversi = new Reversi({
    registry: Registry.from(opts.manifests ?? MANIFESTS),
    ledger: new Ledger(),
    approver: approvals.asApprover(),
    policy: opts.policy ? new Policy(opts.policy) : undefined,
    content: opts.content ? new ContentChecker() : undefined,
  });
  const pool = new UpstreamPool(opts.fakes.map((f) => f.entry));
  const gateway = new Gateway({ reversi, approvals, pool, mode: opts.mode ?? "enforce", ...opts.gw });
  return { reversi, approvals, pool, gateway };
}

export async function connect(gateway: Gateway, principal: Principal, operator = false) {
  const { server, run } = gateway.createSession({ principal, operator });
  const [s, c] = InMemoryTransport.createLinkedPair();
  await server.connect(s);
  const client = new Client({ name: "agent", version: "1" });
  await client.connect(c);
  return { client, run };
}

export const textOf = (r: { content?: unknown }) => ((r.content as Array<{ text?: string }>)?.[0]?.text ?? "") as string;
