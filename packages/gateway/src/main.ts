#!/usr/bin/env node
import { parseArgs } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadRegistry, openLocal } from "@multimindlab/reversi";
import { createGateway } from "./gateway.js";

const USAGE = `reversi-gateway: journal an MCP server's tool calls (observe mode). Speaks MCP on stdio.

  --manifests <path>       manifest file or directory (required)
  --upstream-cmd <cmd>     start an upstream MCP server over stdio; repeat --upstream-arg for its arguments
  --upstream-arg <arg>
  --upstream-url <url>     or connect to an upstream over Streamable HTTP
  --data <dir>             ledger and run state (default ./reversi-data)
  --actor <name>           actor recorded in the ledger (default mcp-client)
  --run-id <id>            run id (default: generated)

Logs go to stderr; stdout is the MCP channel.`;

const { values: v } = parseArgs({
  options: {
    manifests: { type: "string" },
    "upstream-cmd": { type: "string" },
    "upstream-arg": { type: "string", multiple: true },
    "upstream-url": { type: "string" },
    data: { type: "string", default: "./reversi-data" },
    actor: { type: "string", default: "mcp-client" },
    "run-id": { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});

if (v.help || !v.manifests || !!v["upstream-cmd"] === !!v["upstream-url"]) {
  console.error(USAGE);
  process.exit(v.help ? 0 : 64);
}

const reversi = openLocal(v.data as string, loadRegistry(v.manifests));
const upstream = new Client({ name: "reversi-gateway", version: "0.1.0" });
await upstream.connect(
  v["upstream-url"]
    ? new StreamableHTTPClientTransport(new URL(v["upstream-url"]))
    : new StdioClientTransport({ command: v["upstream-cmd"] as string, args: v["upstream-arg"] ?? [], stderr: "inherit" }),
);

const { server, run } = createGateway({ reversi, upstream, actor: v.actor as string, run_id: v["run-id"] });
await server.connect(new StdioServerTransport());
console.error(`reversi-gateway: run ${run.run_id}, observe mode, data in ${v.data}`);
