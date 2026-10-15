/** One or more upstream MCP servers behind the gateway, with optional name prefixes to avoid collisions. */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { expandEnv, type UpstreamConfig } from "./config.js";

export interface UpstreamEntry {
  name: string;
  client: Client;
  namespace: boolean;
}

/** The gateway has no upstream for this tool name, so nothing was sent anywhere. */
export class UnknownToolError extends Error {
  constructor(readonly tool: string) {
    super(`unknown tool \`${tool}\``);
    this.name = "UnknownToolError";
  }
}

export class UpstreamPool {
  private routes = new Map<string, { entry: UpstreamEntry; original: string }>();
  constructor(readonly entries: UpstreamEntry[]) {
    if (entries.length === 0) throw new Error("the gateway needs at least one upstream");
  }

  static async connect(cfgs: UpstreamConfig[], env: Record<string, string | undefined> = process.env): Promise<UpstreamPool> {
    const many = cfgs.length > 1;
    const entries: UpstreamEntry[] = [];
    try {
      for (const c of cfgs) {
        const client = new Client({ name: "reversi-gateway", version: "0.1.0" });
        const expandAll = (m: Record<string, string> | undefined) => Object.fromEntries(Object.entries(m ?? {}).map(([k, v]) => [k, expandEnv(v, env)]));
        const transport = c.url
          ? new StreamableHTTPClientTransport(new URL(c.url), { requestInit: { headers: expandAll(c.headers) } })
          : new StdioClientTransport({
              command: c.command as string,
              args: (c.args ?? []).map((a) => expandEnv(a, env)),
              env: expandAll(c.env), // the SDK adds only a safe default set (PATH, HOME...): Reversi's own secrets are not inherited
              cwd: c.cwd,
              stderr: "inherit",
            });
        await client.connect(transport);
        entries.push({ name: c.name, client, namespace: c.namespace ?? many });
      }
    } catch (e) {
      await Promise.allSettled(entries.map((x) => x.client.close()));
      throw e;
    }
    return new UpstreamPool(entries);
  }

  /** Every upstream's tools under the names clients see. Also refreshes routing. */
  async listTools(): Promise<Tool[]> {
    const out: Tool[] = [];
    const routes = new Map<string, { entry: UpstreamEntry; original: string }>();
    for (const entry of this.entries) {
      let cursor: string | undefined;
      do {
        const page = await entry.client.listTools(cursor ? { cursor } : undefined);
        for (const t of page.tools) {
          const exposed = entry.namespace ? `${entry.name}.${t.name}` : t.name;
          const clash = routes.get(exposed);
          if (clash) throw new Error(`tool name collision: \`${exposed}\` comes from \`${clash.entry.name}\` and \`${entry.name}\`; enable namespacing`);
          routes.set(exposed, { entry, original: t.name });
          out.push({ ...t, name: exposed });
        }
        cursor = page.nextCursor;
      } while (cursor);
    }
    this.routes = routes;
    return out;
  }

  async resolve(exposed: string): Promise<{ entry: UpstreamEntry; original: string } | undefined> {
    if (!this.routes.has(exposed)) await this.listTools();
    return this.routes.get(exposed);
  }

  async call(exposed: string, args: Record<string, unknown> | undefined, meta?: Record<string, unknown>): Promise<CallToolResult> {
    const r = await this.resolve(exposed);
    if (!r) throw new UnknownToolError(exposed);
    const res = await r.entry.client.callTool({ name: r.original, arguments: args, ...(meta ? { _meta: meta } : {}) });
    return res as CallToolResult;
  }

  async status(): Promise<Array<{ name: string; ok: boolean }>> {
    return Promise.all(
      this.entries.map(async (e) => {
        try {
          await e.client.ping();
          return { name: e.name, ok: true };
        } catch {
          return { name: e.name, ok: false };
        }
      }),
    );
  }

  async close(): Promise<void> {
    await Promise.allSettled(this.entries.map((e) => e.client.close()));
  }
}
