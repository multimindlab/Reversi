#!/usr/bin/env node
// A tiny MCP client for trying the gateway by hand.
//
//   node examples/gateway/mcp.mjs http://127.0.0.1:7431/mcp list --token AGENT_KEY
//   node examples/gateway/mcp.mjs http://127.0.0.1:7431/mcp call fs.write_file '{"path":"a.txt","content":"hi"}' --token AGENT_KEY --reason "why I am doing this"
//   ... --run my-run     continue (or create) a run, so approvals and rollback apply across separate invocations
//   node examples/gateway/mcp.mjs stdio list -- node packages/gateway/dist/main.js --config examples/gateway/gateway.yaml --manifests examples/gateway/manifests
//
// Run from the repository root after `npm run build`.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const argv = process.argv.slice(2);
const dd = argv.indexOf("--");
const rest = dd === -1 ? argv : argv.slice(0, dd);
const stdioCmd = dd === -1 ? [] : argv.slice(dd + 1);
const flag = (name) => {
  const i = rest.indexOf(name);
  if (i === -1) return undefined;
  const v = rest[i + 1];
  rest.splice(i, 2);
  return v;
};
const token = flag("--token");
const reason = flag("--reason");
const runId = flag("--run");
const [target, action, tool, json] = rest;
if (!target || !["list", "call"].includes(action)) {
  console.error("usage: mcp.mjs <url|stdio> list|call [tool] [json-args] [--token T] [--reason R] [-- stdio command...]");
  process.exit(64);
}

const client = new Client({ name: "reversi-try", version: "1" });
try {
  await client.connect(
    target === "stdio"
      ? new StdioClientTransport({ command: stdioCmd[0], args: stdioCmd.slice(1), stderr: "inherit" })
      : new StreamableHTTPClientTransport(new URL(target), { requestInit: { headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(runId ? { "Reversi-Run-Id": runId } : {}) } } }),
  );
} catch (e) {
  console.error(`could not connect: ${e.message}`);
  process.exit(1);
}
try {
  if (action === "list") {
    for (const t of (await client.listTools()).tools) console.log(t.name.padEnd(34), (t.description ?? "").split("\n")[0].slice(0, 70));
  } else {
    const res = await client.callTool({ name: tool, arguments: json ? JSON.parse(json) : {}, ...(reason ? { _meta: { "reversi/reason": reason } } : {}) });
    console.log(res.isError ? "ERROR RESULT:" : "RESULT:");
    for (const c of res.content ?? []) console.log(c.type === "text" ? c.text : JSON.stringify(c));
    process.exitCode = res.isError ? 2 : 0;
  }
} catch (e) {
  console.error("request failed:", e.message);
  process.exitCode = 1;
} finally {
  await client.close();
}
