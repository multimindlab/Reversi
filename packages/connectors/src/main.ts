#!/usr/bin/env node
import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { stringify } from "yaml";
import { compensatorFor } from "./compensate.js";
import type { Connector } from "./common.js";
import { CHECKS } from "./certify.js";
import { allConnectors, createPgPool, type AllConnectorsConfig, type PgLike } from "./index.js";
import { createConnectorServer } from "./server.js";

const USAGE = `reversi-connectors: real tool connectors with Reversi manifests and working compensations.

  serve <name> [--root dir] [--backup-dir dir]
      Serve one connector as an MCP server on stdio. Credentials come from the environment, never from flags:
        github      GITHUB_TOKEN
        slack       SLACK_BOT_TOKEN
        stripe      STRIPE_SECRET_KEY
        gitlab      GITLAB_TOKEN (optional GITLAB_BASE_URL for self-hosted)
        teams       TEAMS_TOKEN
        linear      LINEAR_API_KEY
        jira        JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN
        gcalendar   GOOGLE_CALENDAR_TOKEN
        postgres    POSTGRES_URL
        aws         AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION (optional AWS_SESSION_TOKEN)
        gcp         GCP_ACCESS_TOKEN
        azure       AZURE_STORAGE_TOKEN, AZURE_STORAGE_ACCOUNT
        kubernetes  KUBE_API_SERVER, KUBE_TOKEN (optional KUBE_CA_CERT, a path)
        fs          none (rooted at --root)
  manifests <name|all> [--format json|yaml]
      Print the connector's Reversi tool manifests (default yaml).
  compensate [--root dir] [--backup-dir dir]
      Read one CompensationCall as JSON on stdin and run it. Connectors are enabled by their
      credentials in the environment (fs is always on, rooted at --root, default the current directory).
      Use as: reversi rollback --compensator-cmd "reversi-connectors compensate --root ."
  certify <name|all>
      Print the twelve certification checks and where they are enforced. The checks run against fake backends
      in the test suite (npm test), not against live services.

Logs go to stderr; with \`serve\`, stdout is the MCP channel.`;

const NAMES = [
  "fs",
  "github",
  "slack",
  "stripe",
  "gitlab",
  "teams",
  "linear",
  "jira",
  "gcalendar",
  "postgres",
  "aws",
  "gcp",
  "azure",
  "kubernetes",
] as const;
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

const noPool: PgLike = {
  query: async () => {
    throw new Error("no database connection in placeholder mode");
  },
};

async function configFor(which: Name, root: string, backupDir: string | undefined, placeholder: boolean): Promise<AllConnectorsConfig> {
  const secret = (n: string, dummy = "unused") => (placeholder ? dummy : need(n));
  switch (which) {
    case "fs":
      return { fs: { root, backupDir } };
    case "github":
      return { github: { token: secret("GITHUB_TOKEN") } };
    case "slack":
      return { slack: { token: secret("SLACK_BOT_TOKEN") } };
    case "stripe":
      return { stripe: { secretKey: secret("STRIPE_SECRET_KEY") } };
    case "gitlab":
      return { gitlab: { token: secret("GITLAB_TOKEN"), baseUrl: env("GITLAB_BASE_URL") } };
    case "teams":
      return { teams: { token: secret("TEAMS_TOKEN") } };
    case "linear":
      return { linear: { apiKey: secret("LINEAR_API_KEY") } };
    case "jira":
      return {
        jira: {
          baseUrl: secret("JIRA_BASE_URL", "https://example.atlassian.net"),
          email: secret("JIRA_EMAIL"),
          apiToken: secret("JIRA_API_TOKEN"),
        },
      };
    case "gcalendar":
      return { gcalendar: { token: secret("GOOGLE_CALENDAR_TOKEN") } };
    case "postgres": {
      if (placeholder) return { postgres: { pool: noPool } };
      const url = need("POSTGRES_URL");
      let password = "";
      try {
        password = decodeURIComponent(new URL(url).password);
      } catch {
        /* not a URL: the whole string is still redacted */
      }
      return { postgres: { pool: await createPgPool(url), secrets: [url, password] } };
    }
    case "aws":
      return {
        aws: {
          accessKeyId: secret("AWS_ACCESS_KEY_ID"),
          secretAccessKey: secret("AWS_SECRET_ACCESS_KEY"),
          sessionToken: env("AWS_SESSION_TOKEN"),
          region: placeholder ? (env("AWS_REGION") ?? "us-east-1") : need("AWS_REGION"),
        },
      };
    case "gcp":
      return { gcp: { accessToken: secret("GCP_ACCESS_TOKEN") } };
    case "azure":
      return {
        azure: {
          token: secret("AZURE_STORAGE_TOKEN"),
          account: placeholder ? (env("AZURE_STORAGE_ACCOUNT") ?? "unused") : need("AZURE_STORAGE_ACCOUNT"),
        },
      };
    case "kubernetes":
      return {
        kubernetes: {
          apiServer: secret("KUBE_API_SERVER", "https://unused.invalid"),
          token: secret("KUBE_TOKEN"),
          caCertPath: placeholder ? undefined : env("KUBE_CA_CERT"),
        },
      };
  }
}

/** Connectors whose credentials are present in the environment, plus the filesystem. */
async function configFromEnv(root: string, backupDir: string | undefined): Promise<AllConnectorsConfig> {
  const config: AllConnectorsConfig = { fs: { root, backupDir } };
  const trigger: Array<[Name, string]> = [
    ["github", "GITHUB_TOKEN"],
    ["slack", "SLACK_BOT_TOKEN"],
    ["stripe", "STRIPE_SECRET_KEY"],
    ["gitlab", "GITLAB_TOKEN"],
    ["teams", "TEAMS_TOKEN"],
    ["linear", "LINEAR_API_KEY"],
    ["jira", "JIRA_API_TOKEN"],
    ["gcalendar", "GOOGLE_CALENDAR_TOKEN"],
    ["postgres", "POSTGRES_URL"],
    ["aws", "AWS_ACCESS_KEY_ID"],
    ["gcp", "GCP_ACCESS_TOKEN"],
    ["azure", "AZURE_STORAGE_TOKEN"],
    ["kubernetes", "KUBE_API_SERVER"],
  ];
  for (const [name, variable] of trigger) {
    if (env(variable)) Object.assign(config, await configFor(name, root, backupDir, false));
  }
  return config;
}

const CERT_TESTS =
  "packages/connectors/test/certify.test.ts (runs every check for every connector), driven by test/certification.ts and the per-connector fixtures in test/fixtures/<name>.ts";

function printCertification(which: string): void {
  const names = which === "all" ? [...NAMES] : [which];
  const out = [
    "Connector certification: the checks below are enforced by the test suite against fake backends,",
    "not against live services. The suite fails if any connector fails any check.",
    "",
  ];
  for (const c of CHECKS) out.push(`  ${c.id.padEnd(22)} ${c.verifies}`);
  out.push("", `Enforced in: ${CERT_TESTS}`, `Connectors: ${names.join(", ")}`);
  out.push("Run: npm test   (a connector that does not apply to a check must say why; see docs/connectors.mdx)");
  process.stdout.write(out.join("\n") + "\n");
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
    const connectors = allConnectors(await configFor(name as Name, root, backupDir, false));
    const server = createConnectorServer(connectors);
    await server.connect(new StdioServerTransport());
    process.stderr.write(`reversi-connectors: serving ${name} on stdio\n`);
    return;
  }

  if (cmd === "manifests") {
    let connectors: Connector[];
    if (name === "all") {
      connectors = [];
      for (const n of NAMES) connectors.push(...allConnectors(await configFor(n, root, backupDir, true)));
    } else if (NAMES.includes(name as Name)) {
      connectors = allConnectors(await configFor(name as Name, root, backupDir, true));
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
    const config = await configFromEnv(root, backupDir);
    try {
      await compensatorFor(allConnectors(config))(call as Parameters<ReturnType<typeof compensatorFor>>[0]);
    } catch (e) {
      return fail(e instanceof Error ? e.message : String(e));
    }
    process.stdout.write('{"ok":true}\n');
    return;
  }

  if (cmd === "certify") {
    if (name !== "all" && !NAMES.includes(name as Name)) return fail(`certify needs one of: ${NAMES.join(", ")}, all`);
    printCertification(name as string);
    return;
  }

  fail(`unknown command \`${cmd}\`\n\n${USAGE}`);
}

main().catch((e: unknown) => fail(e instanceof Error ? e.message : String(e)));
