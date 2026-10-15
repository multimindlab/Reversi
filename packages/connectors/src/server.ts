import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { EffectUncertainError } from "@multimindlab/reversi";
import type { Connector, ToolHandler } from "./common.js";

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** An MCP server exposing every tool of the given connectors, named `<connector>.<tool>`. */
export function createConnectorServer(connectors: Connector[]): Server {
  const handlers = new Map<string, ToolHandler>();
  const tools: Array<{ name: string; description?: string; inputSchema: { type: "object"; [k: string]: unknown } }> = [];
  for (const c of connectors) {
    for (const [name, handler] of Object.entries(c.tools)) {
      if (handlers.has(name)) throw new Error(`duplicate tool name \`${name}\``);
      handlers.set(name, handler);
      const schema = (c.inputSchemas[name] ?? { type: "object", properties: {} }) as Record<string, unknown>;
      const { description, ...inputSchema } = schema;
      tools.push({
        name,
        description: typeof description === "string" ? description : undefined,
        inputSchema: { ...inputSchema, type: "object" },
      });
    }
  }

  const server = new Server({ name: "reversi-connectors", version: "0.1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const handler = handlers.get(req.params.name);
    if (!handler) throw new McpError(ErrorCode.InvalidParams, `unknown tool \`${req.params.name}\``);
    try {
      const result = await handler(req.params.arguments ?? {}, {});
      const text = JSON.stringify(result ?? null);
      return isPlainObject(result)
        ? { content: [{ type: "text" as const, text }], structuredContent: result }
        : { content: [{ type: "text" as const, text }] };
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (e instanceof EffectUncertainError) throw new McpError(ErrorCode.InternalError, message);
      return { isError: true, content: [{ type: "text" as const, text: message }] };
    }
  });
  return server;
}
