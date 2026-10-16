#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { parseArgs } from "node:util";
import { getRequestListener } from "@hono/node-server";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  KeyRing,
  ManifestRegistry,
  OidcVerifier,
  PolicyVersions,
  checkUrl,
  dataOptionsFromEnv,
  engineConfigFromEnv,
  findProjectConfig,
  loadProjectConfig,
  openEngine,
  storeKindFrom,
  type ApiKey,
  type ProjectConfig,
  type Role,
} from "@multimindlab/reversi";
import { createApp } from "@multimindlab/reversi-server";
import { ConfigError, allowDenyPolicy, loadGatewayConfig, parseGatewayConfig, type GatewayConfig } from "./config.js";
import { Gateway, IDEMPOTENCY_META_KEY, resultForHandle } from "./gateway.js";
import { createHttpGateway } from "./http.js";
import { UpstreamPool } from "./upstream.js";

const USAGE = `reversi-gateway: journal, police and roll back an MCP server's tool calls.

  --config <file>          gateway config (YAML/JSON): upstreams, mode, allow/deny, listen, auth, console
  --manifests <path>       tool manifests (file, directory, registry or URL). Optional: with none, the gateway starts in observe
                           mode, lets everything through and journals it, and shows what to classify. ./manifests is used if it exists.
  --policy <file>          policy rules, limits and content checks
  --data <dir>             data directory (default ./reversi-data)
  --store <kind>           files | sqlite | postgres (default files)
  --database-url <url>     PostgreSQL URL (or REVERSI_DATABASE_URL)
  --environment <name>     environment name matched by policy rules
  --signing-key <pem>      Ed25519 private key for signed evidence bundles
  --console <mode>         off (default) | open | login: the operator console on the gateway's own port (needs "listen")
  --console-role <role>    role in open mode: auditor | approver | operator (default operator; never admin)

Shortcuts instead of --config, for one upstream over stdio on stdio:
  --upstream-cmd <cmd> [--upstream-arg <arg>]...   or   --upstream-url <url>
  --mode observe|advise|enforce   (default enforce; observe when there are no manifests yet)
  --actor <name>           actor recorded for unauthenticated sessions (default mcp-client)
  --run-id <id>            stdio mode: the run id to use, or continue if it exists (HTTP clients send a Reversi-Run-Id header)

Reversi reads reversi.config.yaml from the current directory or above (or REVERSI_CONFIG) for everything else.
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
    console: { type: "string" },
    "console-role": { type: "string" },
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

let cfg: GatewayConfig;
try {
  if (v.config) cfg = loadGatewayConfig(v.config);
  else {
    if (!!v["upstream-cmd"] === !!v["upstream-url"]) die("give --config, or exactly one of --upstream-cmd / --upstream-url");
    cfg = parseGatewayConfig({
      ...(v.mode ? { mode: v.mode } : {}),
      actor: v.actor,
      upstreams: [v["upstream-url"] ? { name: "upstream", url: v["upstream-url"] } : { name: "upstream", command: v["upstream-cmd"], args: v["upstream-arg"] ?? [] }],
    });
  }
  if (v.mode && v.config) cfg = { ...cfg, mode: v.mode as GatewayConfig["mode"], mode_explicit: true };
} catch (e) {
  if (e instanceof ConfigError) die(e.errors.join("\n       "));
  throw e;
}

const env = process.env;
let project: ProjectConfig | undefined;
try {
  const file = findProjectConfig(process.cwd(), undefined, env);
  project = file ? loadProjectConfig(file, env) : undefined;
} catch (e) {
  die(e instanceof Error ? e.message : String(e));
}

const dataOpts = dataOptionsFromEnv({ ...(project?.data?.dir ? { REVERSI_DATA: project.data.dir } : {}), ...(project?.data?.store ? { REVERSI_STORE: project.data.store } : {}), ...(project?.data?.database_url ? { REVERSI_DATABASE_URL: project.data.database_url } : {}), ...env });
if (v.data) dataOpts.dir = v.data;
if (v.store) dataOpts.store = storeKindFrom(v.store);
if (v["database-url"]) dataOpts.postgres_url = v["database-url"];

const manifests = v.manifests ?? env.REVERSI_MANIFESTS ?? project?.manifests ?? (existsSync("./manifests") ? "./manifests" : undefined);
const base = engineConfigFromEnv({ ...env, REVERSI_MANIFESTS: manifests ?? "-" }, dataOpts, project);
let engine: Awaited<ReturnType<typeof openEngine>>;
try {
  engine = await openEngine({
  ...base,
  manifests: manifests ?? "",
  allow_empty_manifests: !manifests,
  policy: v.policy ?? base.policy,
  environment: v.environment ?? base.environment,
  signing_key: v["signing-key"] ?? base.signing_key,
  extra_policy: allowDenyPolicy(cfg),
});
} catch (e) {
  die(e instanceof Error ? e.message : String(e));
}

// Observe-first: no manifests and no explicit mode means nothing is blocked while the picture builds up.
let mode = cfg.mode;
if (engine.registry.size === 0 && !cfg.mode_explicit) {
  mode = "observe";
  console.error("reversi-gateway: no manifests yet, so starting in observe mode: everything runs and is journaled. Run `reversi suggest-manifest` to draft manifests for what the upstream offers.");
}

for (const u of cfg.upstreams) if (u.url) await checkUrl(engine.egress, u.url).catch((e) => die(`upstream ${u.name}: ${e instanceof Error ? e.message : e}`));
const pool = await UpstreamPool.connect(cfg.upstreams);
const gateway = new Gateway({
  reversi: engine.reversi,
  approvals: engine.approvals,
  pool,
  mode,
  permissions: cfg.permissions,
  allow: cfg.allow,
  deny: cfg.deny,
  signing_key: engine.signing_key,
  unclassified_reads: cfg.unclassified_reads,
  validate_schemas: cfg.validate_schemas,
  reload: (by) => engine.reload(by),
  capture: engine.capture,
  environment: engine.config.environment,
});

try {
  console.error((await gateway.classification()).banner);
} catch (e) {
  console.error(`reversi-gateway: could not list the upstream tools: ${e instanceof Error ? e.message : e}`);
}

engine.start({ health: () => pool.status() });
if (project?.reload?.watch !== false) engine.watch(project?.reload?.interval_ms);
process.on("SIGHUP", () => void engine.reload("sighup"));

const shutdown = async (code = 0) => {
  await pool.close();
  await engine.close();
  process.exit(code);
};
process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());

const dirOf = (p: string | undefined, versioned: (d: string) => boolean) => (p && existsSync(p) && statSync(p).isDirectory() && (versioned(p) || readdirSync(p).length === 0) ? p : undefined);

if (cfg.listen) {
  const keys = cfg.auth?.keys ? new KeyRing(JSON.parse(readFileSync(cfg.auth.keys, "utf8")) as ApiKey[]) : undefined;
  const oidc = cfg.auth?.oidc ? new OidcVerifier({ ...cfg.auth.oidc }) : undefined;

  const consoleMode = (v.console ?? cfg.console?.mode ?? project?.console?.mode ?? "off") as "off" | "open" | "login";
  const consoleRole = (v["console-role"] ?? cfg.console?.role ?? project?.console?.role ?? "operator") as Role;
  if (!["off", "open", "login"].includes(consoleMode)) die("--console must be off, open or login");
  if (consoleMode === "open") {
    if (!["127.0.0.1", "::1", "localhost"].includes(cfg.listen.host)) die(`the open console has no login, so the gateway must listen on loopback, not ${cfg.listen.host}. Use --console login.`);
    if (consoleRole === "admin") die("the open console never runs as admin");
  }
  if (consoleMode === "login" && !keys && !oidc) die("--console login needs auth.keys or auth.oidc to log in with");
  const consoleApp =
    consoleMode === "off"
      ? undefined
      : createApp({
          reversi: engine.reversi,
          approvals: engine.approvals,
          keys: keys ?? [],
          oidc,
          engine,
          signing_key: engine.signing_key,
          console: { mode: consoleMode, role: consoleRole as never },
          secure_cookies: env.REVERSI_SECURE_COOKIES === "1",
          session_secret: env.REVERSI_SESSION_SECRET,
          registry_dir: dirOf(engine.config.manifests, (d) => ManifestRegistry.isRegistry(d)),
          policy_dir: dirOf(engine.config.policy, (d) => PolicyVersions.isVersioned(d)),
          compensator: async (call) => {
            const r = await pool.call(call.tool, call.args, { [IDEMPOTENCY_META_KEY]: call.idempotency_key, "reversi/run_id": call.run_id, "reversi/step": call.step });
            if (r.isError) throw new Error(`compensation ${call.tool} returned an error`);
          },
          verifier: async (tool, a) => resultForHandle(await pool.call(tool, a)),
          connectors: () => gateway.connectors(),
          upstream_tools: () => gateway.toolInfos(),
          health: () => pool.status(),
        });
  const listener = consoleApp ? getRequestListener(consoleApp.fetch) : undefined;

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
    console: listener,
  });
  http.server.listen(cfg.listen.port, cfg.listen.host, () => {
    const a = http.server.address();
    const port = typeof a === "object" && a ? a.port : cfg.listen?.port;
    console.error(`reversi-gateway: ${mode} mode, agent endpoint http://${cfg.listen?.host}:${port}/mcp, ${engine.data.kind} store${consoleApp ? `, console http://${cfg.listen?.host}:${port}/console (${consoleMode})` : ""}`);
  });
} else {
  if (v.console && v.console !== "off") die("--console needs an HTTP gateway: add a `listen` section to the config");
  const { server, run } = gateway.createSession({ principal: { name: cfg.actor, roles: ["agent"], via: "api_key" }, operator: false, run_id: v["run-id"] });
  await server.connect(new StdioServerTransport());
  console.error(`reversi-gateway: run ${run?.run_id}, ${mode} mode, ${engine.data.kind} store`);
}
