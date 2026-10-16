import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Registry } from "@multimindlab/reversi";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { allConnectors, createConnectorServer, createFilesystemConnector, createSlackConnector } from "../src/index.js";
import { failingFetch } from "./helpers.js";

async function connect(connectors: Parameters<typeof createConnectorServer>[0]) {
  const server = createConnectorServer(connectors);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name: "t", version: "1" });
  await client.connect(b);
  return client;
}

describe("MCP server", () => {
  const root = mkdtempSync(path.join(tmpdir(), "rv-srv-"));
  const fsc = createFilesystemConnector({ root });

  it("lists every tool with its JSON schema", async () => {
    const client = await connect([fsc]);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(Object.keys(fsc.tools).sort());
    const w = tools.find((t) => t.name === "fs.write_file")!;
    expect(w.inputSchema).toMatchObject({ type: "object", required: ["path", "content"], additionalProperties: false });
  });

  it("returns text and structured content on success", async () => {
    const client = await connect([fsc]);
    const res = await client.callTool({ name: "fs.write_file", arguments: { path: "m.txt", content: "mcp" } });
    expect(res.isError).toBeFalsy();
    expect(res.structuredContent).toMatchObject({ path: "m.txt", existed: false });
    expect(JSON.parse((res.content as Array<{ text: string }>)[0]!.text)).toMatchObject({ path: "m.txt" });
    expect(readFileSync(path.join(root, "m.txt"), "utf8")).toBe("mcp");
  });

  it("returns isError with the message on failure", async () => {
    const client = await connect([fsc]);
    const res = await client.callTool({ name: "fs.read_file", arguments: { path: "../x" } });
    expect(res.isError).toBe(true);
    expect((res.content as Array<{ text: string }>)[0]!.text).toContain("..");
  });

  it("rejects unknown tools and raises uncertain effects as protocol errors", async () => {
    const slack = createSlackConnector({ token: "xoxb-x", fetch: failingFetch("reset") });
    const client = await connect([fsc, slack]);
    await expect(client.callTool({ name: "fs.nope", arguments: {} })).rejects.toThrow("unknown tool");
    await expect(
      client.callTool({ name: "slack.post_message", arguments: { channel: "C0123ABCDE", text: "x" } }),
    ).rejects.toThrow("effect may have happened");
  });

  it("rejects duplicate tool names", () => {
    expect(() => createConnectorServer([fsc, fsc])).toThrow("duplicate tool name");
  });
});

describe("allConnectors", () => {
  it("builds only the configured connectors and all manifests validate together", () => {
    const cs = allConnectors({
      fs: { root: "." },
      github: { token: "t" },
      slack: { token: "t" },
      stripe: { secretKey: "k" },
    });
    expect(cs.map((c) => c.name)).toEqual(["fs", "github", "slack", "stripe"]);
    expect(Registry.from(cs.flatMap((c) => c.manifests)).size).toBe(9 + 9 + 5 + 6);
    expect(allConnectors({ slack: { token: "t" } }).map((c) => c.name)).toEqual(["slack"]);
  });
});

describe("reversi-connectors binary", () => {
  const main = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "main.js");
  const run = (args: string[], input?: string, env: Record<string, string> = {}) =>
    spawnSync(process.execPath, [main, ...args], { input, encoding: "utf8", env: { PATH: process.env.PATH ?? "", ...env } });

  it.skipIf(!existsSync(main))("prints manifests as YAML and JSON", () => {
    const yaml = execFileSync(process.execPath, [main, "manifests", "stripe"], { encoding: "utf8" });
    const list = parse(yaml) as Array<{ tool: string }>;
    expect(list.map((m) => m.tool)).toContain("stripe.create_refund");
    Registry.from(list);
    const json = JSON.parse(run(["manifests", "all", "--format", "json"]).stdout) as unknown[];
    expect(Registry.from(json).size).toBe(84);
  });

  it.skipIf(!existsSync(main))("serve refuses to start without its credential and never takes it from flags", () => {
    const r = run(["serve", "github"]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("GITHUB_TOKEN is not set");
    expect(run(["serve", "github", "--token", "abc"]).status).toBe(1);
  });

  it.skipIf(!existsSync(main))("compensate runs a CompensationCall from stdin", () => {
    const root = mkdtempSync(path.join(tmpdir(), "rv-cmp-"));
    const fsc = createFilesystemConnector({ root });
    writeFileSync(path.join(root, "f.txt"), "hello");
    return fsc.tools["fs.delete_file"]!({ path: "f.txt" }, {}).then((res) => {
      const call = {
        run_id: "r",
        step: 0,
        tool: "fs.restore_file",
        original_tool: "fs.delete_file",
        args: { path: "f.txt", backup_id: (res as { backup_id: string }).backup_id },
        idempotency_key: "k",
      };
      expect(existsSync(path.join(root, "f.txt"))).toBe(false);
      const ok = run(["compensate", "--root", root], JSON.stringify(call));
      expect(ok.status).toBe(0);
      expect(readFileSync(path.join(root, "f.txt"), "utf8")).toBe("hello");
      expect(run(["compensate", "--root", root], JSON.stringify(call)).status).toBe(0);
      const bad = run(["compensate", "--root", root], JSON.stringify({ ...call, tool: "github.close_issue" }));
      expect(bad.status).toBe(1);
      expect(bad.stderr).toContain("no connector provides");
      expect(run(["compensate", "--root", root], "not json").status).toBe(1);
    });
  });
});
