/**
 * MCP gateway, observe mode. Sits between an MCP client and one upstream MCP server: `tools/list`
 * is forwarded as is, and every `tools/call` is journaled (intent first, then outcome) before and
 * after being forwarded. The upstream result is returned unchanged. Nothing is ever blocked:
 * policy violations are journaled as `would_block`.
 *
 * The gateway is one run. MCP has no field for "why", so the reason comes from the call's
 * `_meta["reversi/reason"]`, or a generic one.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";
import { SealedScope, type Outcome, type Reversi, type Run } from "@multimindlab/reversi";

export interface GatewayOptions {
  reversi: Reversi;
  /** A connected client for the upstream MCP server. */
  upstream: Client;
  actor: string;
  /** Permissions for the run's scope. Default: every permission named in the manifests. */
  permissions?: string[];
  run_id?: string;
}

export const REASON_META_KEY = "reversi/reason";

/** The value compensation arguments (`$result.*`) are resolved from. */
export function resultForHandle(result: object): unknown {
  const r = result as { structuredContent?: unknown; content?: unknown };
  if (r.structuredContent !== undefined) return r.structuredContent;
  const parts = Array.isArray(r.content) ? r.content : [];
  const only = parts.length === 1 ? (parts[0] as { type?: string; text?: unknown }) : undefined;
  if (only?.type === "text" && typeof only.text === "string") {
    try {
      return JSON.parse(only.text);
    } catch {
      /* not JSON: fall through */
    }
  }
  return result;
}

/** Errors that say the call was refused are failures; anything else may have taken effect. */
function outcomeForError(e: unknown): Outcome {
  const error = e instanceof Error ? e.message : String(e);
  const refused = e instanceof McpError && (e.code === ErrorCode.InvalidParams || e.code === ErrorCode.MethodNotFound);
  return refused ? { status: "failed", error } : { status: "uncertain", error };
}

export function createGateway(opts: GatewayOptions): { server: Server; run: Run } {
  const permissions = opts.permissions ?? [...new Set(opts.reversi.registry.list().map((m) => m.permission))];
  const run = opts.reversi.startRun({
    run_id: opts.run_id,
    actor: opts.actor,
    scope: SealedScope.seal(permissions),
    mode: "observe",
    reason: "MCP gateway session",
  });

  const server = new Server({ name: "reversi-gateway", version: "0.1.0" }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async (req) => opts.upstream.listTools(req.params));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args, _meta } = req.params;
    const metaReason = _meta?.[REASON_META_KEY];
    const reason = typeof metaReason === "string" && metaReason.trim() ? metaReason : `MCP tools/call ${name}`;

    const begin = await run.begin({ tool: name, args, reason });
    if (begin.decision === "block") {
      // Unreachable in observe mode; fail closed if it ever happens.
      return { isError: true, content: [{ type: "text", text: `blocked by Reversi: ${begin.reasons.join("; ")}` }] };
    }

    let result;
    try {
      result = await opts.upstream.callTool({ name, arguments: args });
    } catch (e) {
      run.complete(begin.step, outcomeForError(e));
      throw e;
    }
    if (result.isError) {
      run.complete(begin.step, { status: "failed", error: "upstream returned isError" });
    } else {
      run.complete(begin.step, { status: "succeeded", result: resultForHandle(result) });
    }
    return result;
  });

  return { server, run };
}
