#!/usr/bin/env node
import { readFileSync, watchFile } from "node:fs";
import { serve } from "@hono/node-server";
import { KeyRing, OidcVerifier, ROLES, dataOptionsFromEnv, engineConfigFromEnv, openEngine, type ApiKey, type Role, type SigningKey } from "@multimindlab/reversi";
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
try {
  engine = await openEngine(engineConfigFromEnv(env, dataOptionsFromEnv(env)));
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

const app = createApp({
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
const hostname = env.HOST ?? "127.0.0.1";
const server = serve({ fetch: app.fetch, port, hostname }, (i) =>
  console.log(`reversi-server listening on http://${hostname}:${i.port} (${engine.registry.size} tools, ${engine.data.kind} store)`),
);
const stop = () => {
  server.close(() => {
    engine.data.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 5000).unref();
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
