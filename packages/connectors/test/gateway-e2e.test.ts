// The whole stack: agent -> Reversi gateway -> filesystem connector (as an MCP server), then an
// operator rolls the run back through the gateway and the files are restored.
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Gateway, UpstreamPool } from "@multimindlab/reversi-gateway";
import { Approvals, Ledger, Registry, Reversi } from "@multimindlab/reversi";
import { afterEach, describe, expect, it } from "vitest";
import { createConnectorServer, createFilesystemConnector } from "../src/index.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

async function connect(gateway: Gateway, name: string, roles: Array<"agent" | "admin">, operator: boolean) {
  const { server, run } = gateway.createSession({ principal: { name, roles, via: "api_key" }, operator });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name, version: "1" });
  await client.connect(b);
  return { client, run };
}
const parse = (r: { content?: unknown }) => JSON.parse((r.content as Array<{ text: string }>)[0]?.text ?? "null");

describe("gateway + filesystem connector", () => {
  it("journals real writes and rolls them back through the gateway", async () => {
    const root = mkdtempSync(join(tmpdir(), "rv-e2e-"));
    dirs.push(root);
    writeFileSync(join(root, "notes.txt"), "original");

    const fs = createFilesystemConnector({ root });
    const server = createConnectorServer([fs]);
    const [s, c] = InMemoryTransport.createLinkedPair();
    await server.connect(s);
    const upstream = new Client({ name: "gw", version: "1" });
    await upstream.connect(c);

    const approvals = new Approvals();
    const reversi = new Reversi({ registry: Registry.from(fs.manifests), ledger: new Ledger(), approver: approvals.asApprover() });
    const gateway = new Gateway({ reversi, approvals, pool: new UpstreamPool([{ name: "fs", client: upstream, namespace: false }]), mode: "enforce" });

    const agent = await connect(gateway, "agent", ["agent"], false);
    await agent.client.callTool({ name: "fs.write_file", arguments: { path: "notes.txt", content: "changed by agent" } });
    await agent.client.callTool({ name: "fs.write_file", arguments: { path: "new.txt", content: "brand new" } });
    await agent.client.callTool({ name: "fs.make_dir", arguments: { path: "out" } });
    expect(readFileSync(join(root, "notes.txt"), "utf8")).toBe("changed by agent");
    expect(existsSync(join(root, "new.txt"))).toBe(true);

    const plan = parse(await agent.client.callTool({ name: "reversi.plan_rollback", arguments: { run_id: agent.run?.run_id } }));
    expect(plan.fully_reversible).toBe(true);

    const ops = await connect(gateway, "ops", ["admin"], true);
    const out = parse(await ops.client.callTool({ name: "reversi.execute_rollback", arguments: { run_id: agent.run?.run_id, confirm: true } }));
    expect(out.report).toMatchObject({ complete: true, compensated: [2, 1, 0] });

    expect(readFileSync(join(root, "notes.txt"), "utf8")).toBe("original");
    expect(existsSync(join(root, "new.txt"))).toBe(false);
    expect(existsSync(join(root, "out"))).toBe(false);
    expect(reversi.ledger.verify().ok).toBe(true);

    // The path guard holds through the gateway too: the call is journaled as failed, and nothing outside the root is touched.
    const escape = await agent.client.callTool({ name: "fs.write_file", arguments: { path: "../escape.txt", content: "x" } });
    expect(escape.isError).toBe(true);
    expect(existsSync(join(root, "..", "escape.txt"))).toBe(false);
  });
});
