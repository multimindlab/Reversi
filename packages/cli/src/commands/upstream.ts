/** Connecting to an MCP server from the CLI: to lint against it, draft manifests from it, or check it is healthy. */
import { loadGatewayConfig, parseGatewayConfig, UpstreamPool, type UpstreamConfig } from "@multimindlab/reversi-gateway";
import type { McpToolInfo } from "@multimindlab/reversi";
import type { Command } from "commander";
import { Fail } from "../context.js";

export interface UpstreamFlags {
  upstreamCmd?: string;
  upstreamArg?: string[];
  upstreamUrl?: string;
  gatewayConfig?: string;
}

export function upstreamOpts(c: Command): Command {
  return c
    .option("--gateway-config <file>", "read the upstreams from a gateway config file")
    .option("--upstream-cmd <cmd>", "an MCP server to start over stdio")
    .option("--upstream-arg <arg>", "an argument for --upstream-cmd (repeatable)", (v: string, prev: string[] = []) => [...prev, v])
    .option("--upstream-url <url>", "a Streamable HTTP MCP server");
}

export function hasUpstream(o: UpstreamFlags): boolean {
  return !!(o.upstreamCmd || o.upstreamUrl || o.gatewayConfig);
}

export function upstreamConfigs(o: UpstreamFlags): UpstreamConfig[] {
  if (o.gatewayConfig) return loadGatewayConfig(o.gatewayConfig).upstreams;
  if (!!o.upstreamCmd === !!o.upstreamUrl) throw new Fail("give --gateway-config, or exactly one of --upstream-cmd / --upstream-url");
  return parseGatewayConfig({ upstreams: [o.upstreamUrl ? { name: "upstream", url: o.upstreamUrl } : { name: "upstream", command: o.upstreamCmd, args: o.upstreamArg ?? [] }] }).upstreams;
}

/** Connect, list the tools (named as the gateway would expose them), and disconnect. */
export async function fetchUpstreamTools(o: UpstreamFlags): Promise<{ tools: McpToolInfo[]; server: string }> {
  const cfgs = upstreamConfigs(o);
  const pool = await UpstreamPool.connect(cfgs);
  try {
    const tools = (await pool.listTools()) as unknown as McpToolInfo[];
    return { tools, server: cfgs.length === 1 ? (cfgs[0] as UpstreamConfig).name : "upstream" };
  } finally {
    await pool.close();
  }
}
