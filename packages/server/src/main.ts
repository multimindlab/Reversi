#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync, watchFile } from "node:fs";
import { serve } from "@hono/node-server";
import { KeyRing, ManifestRegistry, OidcVerifier, PolicyVersions, ROLES, dataOptionsFromEnv, engineConfigFromEnv, findProjectConfig, loadProjectConfig, openEngine, type ApiKey, type CompensationCall, type Role, type SigningKey } from "@multimindlab/reversi";
import { createApp } from "./app.js";

const HELP = `reversi-server. Configuration is by environment variable:

  REVERSI_MANIFESTS        manifest file or directory (required)
  REVERSI_KEYS             JSON file of API keys (required unless OIDC is configured); reloaded on SIGHUP or file change
  REVERSI_DATA             data directory (default ./reversi-data)
  REVERSI_STORE            files | sqlite | postgres (default files)
  REVERSI_DATABASE_URL     PostgreSQL connection URL (postgres store)
  REVERSI_POLICY           policy file (rules, limits, content checks)
  REVERSI_ENV              environment name matched by policy rules (default "default")
  REVERSI_KILL_FILE        while this file exists, new calls are blocked
  REVERSI_APPROVAL_WEBHOOK URL told about each new approval request (Slack/Teams incoming-webhook compatible)
  REVERSI_CONSOLE_URL      public URL of this server, linked from notifications
  REVERSI_SIGNING_KEY      PEM file with an Ed25519 private key, for signed evidence bundles
  REVERSI_OIDC_ISSUER, REVERSI_OIDC_AUDIENCE, REVERSI_OIDC_ROLE_MAP   OIDC bearer tokens; role map is JSON like {"reversi-ops":"operator"}
  REVERSI_OIDC_ROLE_CLAIM  claim holding roles (default "roles"; dots allowed: realm_access.roles)
  REVERSI_OIDC_ACTOR_CLAIM claim used as the principal name (default "sub")
  REVERSI_CONFIG           project file (reversi.config.yaml); found by searching upward from the current directory otherwise
  REVERSI_CONSOLE          off (default) | open | login. open: no login, loopback only, fixed role (never admin); login: paste an API key
  REVERSI_CONSOLE_ROLE     role used in open mode: auditor | approver | operator (default operator)
  REVERSI_COMPENSATOR_CMD  command run for each undo; receives the call as JSON on stdin; exit 0 = done. Needed for server-side rollback
  REVERSI_READER_CMD       command that runs a manifest's declared read-back after an undo: gets {"tool","arguments"} JSON on stdin, prints the JSON result
  REVERSI_CAPTURE          1 to keep redacted, time-limited call arguments for replay and policy simulation
  REVERSI_SLACK_SIGNING_SECRET  with REVERSI_SLACK_USERS (JSON file mapping Slack user ids to {"name","roles","groups"}): decide approvals from Slack buttons
  REVERSI_SESSION_SECRET   signs console cookies (default: random per start)
  REVERSI_SECURE_COOKIES   1 behind HTTPS
  REVERSI_METRICS_PUBLIC   1 to serve /metrics without credentials (keep it on a private network)
  REVERSI_LOG              json to log one JSON line per request to stdout
  PORT (7421), HOST (127.0.0.1)
`;

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(HELP);
  process.exit(0);
}

const env = process.env;
let engine;
let project;
try {
  const file = findProjectConfig(process.cwd(), undefined, env);
  project = file ? loadProjectConfig(file, env) : undefined;
  const data = dataOptionsFromEnv({ ...(project?.data?.dir ? { REVERSI_DATA: project.data.dir } : {}), ...(project?.data?.store ? { REVERSI_STORE: project.data.store } : {}), ...(project?.data?.database_url ? { REVERSI_DATABASE_URL: project.data.database_url } : {}), ...env });
  engine = await openEngine(engineConfigFromEnv(env, data, project));
} catch (e) {
  console.error(`error: ${e instanceof Error ? e.message : String(e)}\n`);
  console.error(HELP);
  process.exit(64);
}

const readKeys = (path: string) => JSON.parse(readFileSync(path, "utf8")) as ApiKey[];
const ring = new KeyRing(env.REVERSI_KEYS ? readKeys(env.REVERSI_KEYS) : []);
if (env.REVERSI_KEYS) {
  const reload = () => {
    try {
      ring.replace(readKeys(env.REVERSI_KEYS as string));
      console.error(`reversi-server: reloaded ${ring.size} API keys`);
    } catch (e) {
      console.error(`reversi-server: key reload failed, keeping the old keys: ${e instanceof Error ? e.message : e}`);
    }
  };
  process.on("SIGHUP", reload);
  watchFile(env.REVERSI_KEYS, { interval: 2000 }, reload);
}

let oidc: OidcVerifier | undefined;
if (env.REVERSI_OIDC_ISSUER) {
  if (!env.REVERSI_OIDC_AUDIENCE || !env.REVERSI_OIDC_ROLE_MAP) {
    console.error("error: REVERSI_OIDC_AUDIENCE and REVERSI_OIDC_ROLE_MAP are required with REVERSI_OIDC_ISSUER");
    process.exit(64);
  }
  const role_map = JSON.parse(env.REVERSI_OIDC_ROLE_MAP) as Record<string, Role>;
  if (Object.values(role_map).some((r) => !ROLES.includes(r))) {
    console.error(`error: REVERSI_OIDC_ROLE_MAP values must be among ${ROLES.join(", ")}`);
    process.exit(64);
  }
  oidc = new OidcVerifier({ issuer: env.REVERSI_OIDC_ISSUER, audience: env.REVERSI_OIDC_AUDIENCE, role_map, role_claim: env.REVERSI_OIDC_ROLE_CLAIM, actor_claim: env.REVERSI_OIDC_ACTOR_CLAIM });
}
if (ring.size === 0 && !oidc) {
  console.error("error: no credentials configured: set REVERSI_KEYS and/or REVERSI_OIDC_ISSUER");
  process.exit(64);
}

let signing_key: SigningKey | undefined;
if (env.REVERSI_SIGNING_KEY) {
  const private_pem = readFileSync(env.REVERSI_SIGNING_KEY, "utf8");
  const { createPrivateKey, createPublicKey } = await import("node:crypto");
  signing_key = { private_pem, public_pem: createPublicKey(createPrivateKey(private_pem)).export({ type: "spki", format: "pem" }).toString() };
}

const consoleMode = (env.REVERSI_CONSOLE ?? project?.console?.mode ?? "off") as "off" | "open" | "login";
if (!["off", "open", "login"].includes(consoleMode)) {
  console.error("error: REVERSI_CONSOLE must be off, open or login");
  process.exit(64);
}
const consoleRole = (env.REVERSI_CONSOLE_ROLE ?? project?.console?.role ?? "operator") as Role;
const host = env.HOST ?? "127.0.0.1";
const loopback = ["127.0.0.1", "::1", "localhost"].includes(host);
if (consoleMode === "open" && !loopback) {
  console.error(`error: the open console has no login, so it only runs on a loopback HOST (127.0.0.1, ::1, localhost), not ${host}. Use REVERSI_CONSOLE=login.`);
  process.exit(64);
}
if (consoleMode === "open" && consoleRole === "admin") {
  console.error("error: the open console never runs as admin");
  process.exit(64);
}

// Where manifests and policy can be edited from the console: only if they are versioned folders.
const dirOf = (p: string | undefined, versioned: (d: string) => boolean) => (p && existsSync(p) && statSync(p).isDirectory() && (versioned(p) || readdirSync(p).length === 0) ? p : undefined);
const registry_dir = dirOf(engine.config.manifests, (d) => ManifestRegistry.isRegistry(d));
const policy_dir = dirOf(engine.config.policy, (d) => PolicyVersions.isVersioned(d));

const compensator = env.REVERSI_COMPENSATOR_CMD
  ? (call: CompensationCall) =>
      new Promise<void>((resolve, reject) => {
        const child = spawn(env.REVERSI_COMPENSATOR_CMD as string, { shell: true, stdio: ["pipe", "ignore", "pipe"] });
        let err = "";
        child.stderr.on("data", (d: Buffer) => (err += d.toString().slice(0, 2000)));
        child.on("error", reject);
        child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`compensator exited ${code}: ${err.trim()}`))));
        child.stdin.end(JSON.stringify(call));
      })
  : undefined;

let slack;
if (env.REVERSI_SLACK_SIGNING_SECRET) {
  if (!env.REVERSI_SLACK_USERS) {
    console.error("error: REVERSI_SLACK_USERS (a JSON file mapping Slack user ids to Reversi identities) is required with REVERSI_SLACK_SIGNING_SECRET");
    process.exit(64);
  }
  slack = { signing_secret: env.REVERSI_SLACK_SIGNING_SECRET, users: JSON.parse(readFileSync(env.REVERSI_SLACK_USERS, "utf8")) };
}

const verifier = env.REVERSI_READER_CMD
  ? (tool: string, args: Record<string, unknown>) =>
      new Promise<unknown>((resolve, reject) => {
        const child = spawn(env.REVERSI_READER_CMD as string, { shell: true, stdio: ["pipe", "pipe", "pipe"], timeout: 30_000 });
        let out = "";
        let err = "";
        child.stdout.on("data", (d: Buffer) => (out += d.toString().slice(0, 1_000_000)));
        child.stderr.on("data", (d: Buffer) => (err += d.toString().slice(0, 2000)));
        child.on("error", reject);
        child.on("close", (code) => {
          if (code !== 0) return reject(new Error(`reader exited ${code}: ${err.trim()}`));
          try {
            resolve(JSON.parse(out));
          } catch {
            reject(new Error("reader did not print JSON"));
          }
        });
        child.stdin.end(JSON.stringify({ tool, arguments: args }));
      })
  : undefined;

const app = createApp({
  engine,
  verifier,
  delegations: engine.delegations,
  slack,
  registry_dir,
  policy_dir,
  compensator,
  keys_file: env.REVERSI_KEYS,
  console: { mode: consoleMode, role: consoleRole as never },
  reversi: engine.reversi,
  approvals: engine.approvals,
  keys: ring,
  oidc,
  signing_key,
  metrics_public: env.REVERSI_METRICS_PUBLIC === "1",
  session_secret: env.REVERSI_SESSION_SECRET,
  secure_cookies: env.REVERSI_SECURE_COOKIES === "1",
  logger: env.REVERSI_LOG === "json" ? (e) => console.log(JSON.stringify(e)) : undefined,
});

const port = Number(env.PORT ?? 7421);
const hostname = host;
engine.start();
if (project?.reload?.watch !== false) engine.watch(project?.reload?.interval_ms);
process.on("SIGHUP", () => void engine.reload("sighup").then((r) => console.error(r.error ? `reversi-server: reload failed, keeping the old configuration: ${r.error}` : `reversi-server: reloaded (${r.tools} tools)`)));
const server = serve({ fetch: app.fetch, port, hostname }, (i) =>
  console.log(`reversi-server listening on http://${hostname}:${i.port} (${engine.registry.size} tools, ${engine.data.kind} store, console ${consoleMode})`),
);
const stop = () => {
  server.close(() => {
    void engine.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 5000).unref();
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
