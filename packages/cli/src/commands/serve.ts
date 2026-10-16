/** Starting things from the CLI: draft manifests from a server, run the gateway, open the console on your machine. */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { serve } from "@hono/node-server";
import type { Command } from "commander";
import { stringify } from "yaml";
import { Registry, suggestManifests } from "@multimindlab/reversi";
import { createApp } from "@multimindlab/reversi-server";
import { Fail, type Ctx } from "../context.js";
import { fetchUpstreamTools, hasUpstream, upstreamOpts } from "./upstream.js";
import { loadRegistry } from "@multimindlab/reversi";

export function registerServeCommands(program: Command, ctx: Ctx): void {
  const { io } = ctx;

  upstreamOpts(
    program
      .command("suggest-manifest")
      .description("connect to an MCP server and draft a manifest for every tool that has none. Drafts need a person's approval before they are enforced")
      .option("-m, --manifests <path>", "existing manifests: tools that already have one are skipped")
      .option("-o, --out <dir>", "write one YAML file per tool here (default: print them)")
      .option("--server <name>", "name used for permissions, like <name>:read"),
  ).action(async (o) => {
    if (!hasUpstream(o)) throw new Fail("give --upstream-cmd, --upstream-url or --gateway-config");
    const { tools, server } = await fetchUpstreamTools(o);
    let existing: Registry | undefined;
    const mpath = o.manifests ?? process.env.REVERSI_MANIFESTS ?? ctx.project()?.manifests;
    if (mpath && existsSync(mpath)) existing = loadRegistry(mpath);
    const r = suggestManifests(tools, { server: o.server ?? server, existing });
    if (o.out) mkdirSync(o.out, { recursive: true });
    for (const s of r.suggestions) {
      const text = stringify(s.manifest, { lineWidth: 100 });
      const name = String(s.manifest.tool);
      if (o.out) {
        const file = join(o.out, `${name.replace(/[^A-Za-z0-9._-]/g, "_")}.yaml`);
        writeFileSync(file, `# DRAFT (${s.confidence} confidence). Review before enforcing.\n${s.notes.map((n) => `# - ${n}`).join("\n")}\n${text}`);
        io.out(`${file}  ${s.confidence}`);
      } else io.out(`# ${name} (${s.confidence} confidence)\n${s.notes.map((n) => `#   ${n}`).join("\n")}\n${text}---`);
    }
    io.err(`${r.suggestions.length} drafted, ${r.skipped.length} skipped (already have manifests)${r.ignored.length ? `, ${r.ignored.length} ignored` : ""}`);
  });

  program
    .command("gateway [args...]")
    .description("run the MCP gateway (same options as reversi-gateway; try `reversi gateway --help`)")
    .allowUnknownOption()
    .helpOption(false)
    .action(async (args: string[]) => {
      const main = join(dirname(fileURLToPath(import.meta.resolve("@multimindlab/reversi-gateway"))), "main.js");
      const child = spawn(process.execPath, [main, ...args], { stdio: "inherit" });
      ctx.code = await new Promise<number>((resolve) => child.on("close", (c) => resolve(c ?? 1)));
    });

  ctx
    .dataOpts(program.command("console").description("open the console on this machine: no login, loopback only, never admin. Stop it with Ctrl-C"))
    .option("--policy <file>", "policy file")
    .option("--port <n>", "port (default 7421)", "7421")
    .option("--role <role>", "auditor | approver | operator (default operator)", "operator")
    .action(async (o) => {
      if (!["auditor", "approver", "operator"].includes(o.role)) throw new Fail("--role must be auditor, approver or operator (the open console is never admin)");
      const e = await ctx.engine(o, { allow_empty_manifests: !o.manifests && !ctx.project(o)?.manifests });
      const app = createApp({ reversi: e.reversi, approvals: e.approvals, keys: [], engine: e, signing_key: e.signing_key, console: { mode: "open", role: o.role } });
      const server = serve({ fetch: app.fetch, port: Number(o.port), hostname: "127.0.0.1" }, (i) => io.out(`console: http://localhost:${i.port}/console  (open mode as ${o.role}; Ctrl-C to stop)`));
      await new Promise<void>((resolve) => {
        const stop = () => server.close(() => resolve());
        process.once("SIGINT", stop);
        process.once("SIGTERM", stop);
      });
      await e.close();
    });
}
