#!/usr/bin/env node
import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { stringify } from "yaml";
import { compensatorFor } from "./compensate.js";
import type { Connector } from "./common.js";
import { allConnectors, type AllConnectorsConfig } from "./index.js";
import { createConnectorServer } from "./server.js";

const USAGE = `reversi-connectors: real tool connectors with Reversi manifests and working compensations.

  serve <fs|github|slack|stripe> [--root dir] [--backup-dir dir]
      Serve one connector as an MCP server on stdio. Credentials come from the environment:
      GITHUB_TOKEN, SLACK_BOT_TOKEN, STRIPE_SECRET_KEY. Never from flags.
  manifests <fs|github|slack|stripe|all> [--format json|yaml]
      Print the connector's Reversi tool manifests (default yaml).
  compensate [--root dir] [--backup-dir dir]
      Read one CompensationCall as JSON on stdin and run it. Connectors are enabled by their
      credentials in the environment (fs is always on, rooted at --root, default the current directory).
      Use as: reversi rollback --compensator-cmd "reversi-connectors compensate --root ."

Logs go to stderr; with \`serve\`, stdout is the MCP channel.`;

const NAMES = ["fs", "github", "slack", "stripe"] as const;
type Name = (typeof NAMES)[number];

function fail(msg: string): never {
  process.stderr.write(`reversi-connectors: ${msg}\n`);
  process.exit(1);
}

function env(name: string): string | undefined {
  const v = process.env[name];
  return v ? v : undefined;
}

function need(name: string): string {
  return env(name) ?? fail(`${name} is not set`);
}

function configFor(which: Name, root: string, backupDir: string | undefined, placeholder: boolean): AllConnectorsConfig {
  const secret = (n: string) => (placeholder ? "unused" : need(n));
  switch (which) {
    case "fs":
      return { fs: { root, backupDir } };
    case "github":
      return { github: { token: secret("GITHUB_TOKEN") } };
    case "slack":
      return { slack: { token: secret("SLACK_BOT_TOKEN") } };
    case "stripe":
      return { stripe: { secretKey: secret("STRIPE_SECRET_KEY") } };
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

async function main(): Promise<void> {
  const { values: v, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      root: { type: "string", default: "." },
      "backup-dir": { type: "string" },
      format: { type: "string", default: "yaml" },
      help: { type: "boolean", short: "h" },
    },
  });
  const [cmd, name] = positionals;
  if (v.help || !cmd) {
    process.stdout.write(USAGE + "\n");
    return;
  }
  const root = v.root as string;
  const backupDir = v["backup-dir"];

  if (cmd === "serve") {
    if (!NAMES.includes(name as Name)) fail(`serve needs one of: ${NAMES.join(", ")}`);
    const connectors = allConnectors(configFor(name as Name, root, backupDir, false));
    const server = createConnectorServer(connectors);
    await server.connect(new StdioServerTransport());
    process.stderr.write(`reversi-connectors: serving ${name} on stdio\n`);
    return;
  }

  if (cmd === "manifests") {
    let connectors: Connector[];
    if (name === "all") {
      connectors = NAMES.flatMap((n) => allConnectors(configFor(n, root, backupDir, true)));
    } else if (NAMES.includes(name as Name)) {
      connectors = allConnectors(configFor(name as Name, root, backupDir, true));
    } else {
      return fail(`manifests needs one of: ${NAMES.join(", ")}, all`);
    }
    const manifests = connectors.flatMap((c) => c.manifests);
    if (v.format === "json") process.stdout.write(JSON.stringify(manifests, null, 2) + "\n");
    else if (v.format === "yaml") process.stdout.write(stringify(manifests));
    else fail("--format must be json or yaml");
    return;
  }

  if (cmd === "compensate") {
    let call: unknown;
    try {
      call = JSON.parse(await readStdin());
    } catch {
      return fail("stdin is not valid JSON");
    }
    const c = call as Record<string, unknown> | null;
    if (
      !c ||
      typeof c !== "object" ||
      typeof c.tool !== "string" ||
      typeof c.idempotency_key !== "string" ||
      typeof c.args !== "object" ||
      c.args === null ||
      Array.isArray(c.args)
    ) {
      return fail("stdin must be a CompensationCall with `tool`, `args` and `idempotency_key`");
    }
    const config: AllConnectorsConfig = { fs: { root, backupDir } };
    if (env("GITHUB_TOKEN")) config.github = { token: need("GITHUB_TOKEN") };
    if (env("SLACK_BOT_TOKEN")) config.slack = { token: need("SLACK_BOT_TOKEN") };
    if (env("STRIPE_SECRET_KEY")) config.stripe = { secretKey: need("STRIPE_SECRET_KEY") };
    try {
      await compensatorFor(allConnectors(config))(call as Parameters<ReturnType<typeof compensatorFor>>[0]);
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e));
    }
    process.stdout.write('{"ok":true}\n');
    return;
  }

  fail(`unknown command \`${cmd}\`\n\n${USAGE}`);
}

main().catch((e: unknown) => fail(e instanceof Error ? e.message : String(e)));
