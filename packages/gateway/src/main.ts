#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { KeyRing, OidcVerifier, dataOptionsFromEnv, openEngine, storeKindFrom, type ApiKey, type SigningKey } from "@multimindlab/reversi";
import { ConfigError, allowDenyPolicy, loadGatewayConfig, parseGatewayConfig, type GatewayConfig } from "./config.js";
import { Gateway } from "./gateway.js";
import { createHttpGateway } from "./http.js";
import { UpstreamPool } from "./upstream.js";

const USAGE = `reversi-gateway: journal, police and roll back an MCP server's tool calls.

  --config <file>          gateway config (YAML/JSON): upstreams, mode, allow/deny, listen, auth
  --manifests <path>       tool manifests (file or directory)                       (required)
  --policy <file>          policy rules, limits and content checks
  --data <dir>             data directory (default ./reversi-data)
  --store <kind>           files | sqlite | postgres (default files)
  --database-url <url>     PostgreSQL URL (or REVERSI_DATABASE_URL)
  --environment <name>     environment name matched by policy rules
  --signing-key <pem>      Ed25519 private key for signed evidence bundles

Shortcuts instead of --config, for one upstream over stdio on stdio:
  --upstream-cmd <cmd> [--upstream-arg <arg>]...   or   --upstream-url <url>
  --mode observe|enforce   (default enforce)
  --actor <name>           actor recorded for unauthenticated sessions (default mcp-client)
  --run-id <id>            stdio mode: the run id to use, or continue if it exists (HTTP clients send a Reversi-Run-Id header)

Without a "listen" section the gateway speaks MCP on stdio, so logs go to stderr.`;

const { values: v } = parseArgs({
  options: {
    config: { type: "string" },
    manifests: { type: "string" },
    policy: { type: "string" },
    data: { type: "string" },
    store: { type: "string" },
    "database-url": { type: "string" },
    environment: { type: "string" },
    "signing-key": { type: "string" },
    "upstream-cmd": { type: "string" },
    "upstream-arg": { type: "string", multiple: true },
    "upstream-url": { type: "string" },
    mode: { type: "string" },
    actor: { type: "string" },
    "run-id": { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});

function die(msg: string): never {
  console.error(`error: ${msg}\n`);
  console.error(USAGE);
  process.exit(64);
}

if (v.help) {
  console.error(USAGE);
  process.exit(0);
}
if (!v.manifests) die("--manifests is required");

let cfg: GatewayConfig;
try {
  if (v.config) cfg = loadGatewayConfig(v.config);
  else {
    if (!!v["upstream-cmd"] === !!v["upstream-url"]) die("give --config, or exactly one of --upstream-cmd / --upstream-url");
    cfg = parseGatewayConfig({
      mode: v.mode ?? "enforce",
      actor: v.actor,
      upstreams: [v["upstream-url"] ? { name: "upstream", url: v["upstream-url"] } : { name: "upstream", command: v["upstream-cmd"], args: v["upstream-arg"] ?? [] }],
    });
  }
} catch (e) {
  if (e instanceof ConfigError) die(e.errors.join("\n       "));
  throw e;
}

const dataOpts = dataOptionsFromEnv();
if (v.data) dataOpts.dir = v.data;
if (v.store) dataOpts.store = storeKindFrom(v.store);
if (v["database-url"]) dataOpts.postgres_url = v["database-url"];

const engine = await openEngine({
  manifests: v.manifests,
  data: dataOpts,
  policy: v.policy ?? process.env.REVERSI_POLICY,
  environment: v.environment ?? process.env.REVERSI_ENV,
  kill_switch_file: process.env.REVERSI_KILL_FILE,
  approval_webhook: process.env.REVERSI_APPROVAL_WEBHOOK,
  console_url: process.env.REVERSI_CONSOLE_URL,
  extra_policy: allowDenyPolicy(cfg),
});

let signing_key: SigningKey | undefined;
if (v["signing-key"]) {
  const { createPrivateKey, createPublicKey } = await import("node:crypto");
  const private_pem = readFileSync(v["signing-key"], "utf8");
  signing_key = { private_pem, public_pem: createPublicKey(createPrivateKey(private_pem)).export({ type: "spki", format: "pem" }).toString() };
}

const pool = await UpstreamPool.connect(cfg.upstreams);
const gateway = new Gateway({ reversi: engine.reversi, approvals: engine.approvals, pool, mode: cfg.mode, permissions: cfg.permissions, allow: cfg.allow, deny: cfg.deny, signing_key });

const shutdown = async (code = 0) => {
  await pool.close();
  engine.data.close();
  process.exit(code);
};
process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());

if (cfg.listen) {
  const keys = cfg.auth?.keys ? new KeyRing(JSON.parse(readFileSync(cfg.auth.keys, "utf8")) as ApiKey[]) : undefined;
  const oidc = cfg.auth?.oidc ? new OidcVerifier({ ...cfg.auth.oidc }) : undefined;
  const http = createHttpGateway({
    gateway,
    pool,
    host: cfg.listen.host,
    port: cfg.listen.port,
    keys,
    oidc,
    resource_url: cfg.resource_url,
    anonymous_actor: cfg.actor,
    allowed_hosts: cfg.allowed_hosts,
    allowed_origins: cfg.allowed_origins,
  });
  http.server.listen(cfg.listen.port, cfg.listen.host, () => {
    const a = http.server.address();
    console.error(`reversi-gateway: ${cfg.mode} mode, agent endpoint http://${cfg.listen?.host}:${typeof a === "object" && a ? a.port : cfg.listen?.port}/mcp, ${engine.data.kind} store`);
  });
} else {
  const { server, run } = gateway.createSession({ principal: { name: cfg.actor, roles: ["agent"], via: "api_key" }, operator: false, run_id: v["run-id"] });
  await server.connect(new StdioServerTransport());
  console.error(`reversi-gateway: run ${run?.run_id}, ${cfg.mode} mode, ${engine.data.kind} store`);
}
