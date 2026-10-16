/**
 * The project file, `reversi.config.yaml`: one place that says where manifests and policy live, where data is kept, who
 * is told about what, and so on. The CLI, the server and the gateway all read it; environment variables and command-line
 * flags override it. `${NAME}` in a string is replaced from the environment, so credentials stay out of the file.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { ROLES, type Role } from "./auth.js";
import type { AnchorSink } from "./anchor.js";
import { parseChannels, parseRoutes, type ChannelConfig, type Route } from "./channels.js";
import type { StoreKind } from "./data.js";
import type { EgressConfig } from "./egress.js";
import { parseDuration } from "./manifest.js";

export interface ProjectConfig {
  /** Directory the file was found in; relative paths are resolved against it. */
  root: string;
  file: string;
  manifests?: string;
  policy?: string;
  data?: { dir?: string; store?: StoreKind; database_url?: string };
  environment?: string;
  kill_switch_file?: string;
  approval?: { ttl_ms?: number; webhook?: string; console_url?: string };
  signing_key?: string;
  manifest_public_key?: string;
  capture?: { enabled: boolean; ttl_ms?: number; redact_pii?: boolean };
  notifications?: { channels: ChannelConfig[]; routes: Route[] };
  otel?: { endpoint: string; headers?: Record<string, string>; service_name?: string };
  anchor?: { sinks: AnchorSink[]; interval_ms?: number };
  egress?: EgressConfig;
  alerts?: { interval_ms?: number; remind_ms?: number; denial_spike?: number };
  console?: { mode: "off" | "open" | "login"; role?: Role };
  log?: { level?: "debug" | "info" | "warn" | "error"; format?: "json" | "pretty" };
  reload?: { watch?: boolean; interval_ms?: number };
}

export class ProjectConfigError extends Error {
  constructor(public readonly errors: string[]) {
    super(errors.join("; "));
    this.name = "ProjectConfigError";
  }
}

export const CONFIG_NAMES = ["reversi.config.yaml", "reversi.config.yml", "reversi.config.json"];

/** Look for the config file in `startDir` and its parents. `REVERSI_CONFIG` or an explicit path wins. */
export function findProjectConfig(startDir = process.cwd(), explicit?: string, env: Record<string, string | undefined> = process.env): string | undefined {
  const pinned = explicit ?? env.REVERSI_CONFIG;
  if (pinned) {
    if (!existsSync(pinned)) throw new ProjectConfigError([`config file not found: ${pinned}`]);
    return resolve(pinned);
  }
  for (let dir = resolve(startDir); ; dir = dirname(dir)) {
    for (const n of CONFIG_NAMES) if (existsSync(join(dir, n))) return join(dir, n);
    if (dirname(dir) === dir) return undefined;
  }
}

function expand(v: unknown, env: Record<string, string | undefined>, errors: string[], where: string): unknown {
  if (typeof v === "string") {
    return v.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_m, name: string, dflt: string | undefined) => {
      const val = env[name] ?? dflt;
      if (val === undefined) {
        errors.push(`${where}: environment variable ${name} is not set`);
        return "";
      }
      return val;
    });
  }
  if (Array.isArray(v)) return v.map((x, i) => expand(x, env, errors, `${where}[${i}]`));
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expand(x, env, errors, `${where}.${k}`)]));
  return v;
}

const isRec = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);

export function loadProjectConfig(file: string, env: Record<string, string | undefined> = process.env): ProjectConfig {
  const errors: string[] = [];
  let raw: unknown;
  try {
    const text = readFileSync(file, "utf8");
    raw = extname(file).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text);
  } catch (e) {
    throw new ProjectConfigError([`${file}: cannot read: ${e instanceof Error ? e.message : String(e)}`]);
  }
  if (raw === null || raw === undefined) raw = {};
  if (!isRec(raw)) throw new ProjectConfigError([`${file}: the config must be a mapping`]);
  const cfg = expand(raw, env, errors, "config") as Record<string, unknown>;
  const root = dirname(resolve(file));
  const path = (v: unknown, where: string): string | undefined => {
    if (v === undefined) return undefined;
    if (typeof v !== "string" || !v) {
      errors.push(`${where} must be a path`);
      return undefined;
    }
    return /^https?:\/\//.test(v) || isAbsolute(v) ? v : resolve(root, v);
  };
  const dur = (v: unknown, where: string): number | undefined => {
    if (v === undefined) return undefined;
    const d = parseDuration(v);
    if (d === undefined) errors.push(`${where} must be a duration like 30s or 15m`);
    return d;
  };
  const known = ["manifests", "policy", "data", "environment", "kill_switch_file", "approval", "signing_key", "manifest_public_key", "capture", "notifications", "otel", "anchor", "egress", "alerts", "console", "log", "reload"];
  for (const k of Object.keys(cfg)) if (!known.includes(k)) errors.push(`unknown setting \`${k}\``);
  const out: ProjectConfig = { root, file: resolve(file) };
  out.manifests = path(cfg.manifests, "manifests");
  out.policy = path(cfg.policy, "policy");
  out.signing_key = path(cfg.signing_key, "signing_key");
  out.manifest_public_key = path(cfg.manifest_public_key, "manifest_public_key");
  out.kill_switch_file = path(cfg.kill_switch_file, "kill_switch_file");
  if (cfg.environment !== undefined) typeof cfg.environment === "string" ? (out.environment = cfg.environment) : errors.push("environment must be a string");

  if (cfg.data !== undefined) {
    if (!isRec(cfg.data)) errors.push("data must be a mapping");
    else {
      for (const k of Object.keys(cfg.data)) if (!["dir", "store", "database_url"].includes(k)) errors.push(`data: unknown setting \`${k}\``);
      if (cfg.data.store !== undefined && !["files", "sqlite", "postgres"].includes(cfg.data.store as string)) errors.push("data.store must be files, sqlite or postgres");
      out.data = { dir: path(cfg.data.dir, "data.dir"), store: cfg.data.store as StoreKind | undefined, database_url: cfg.data.database_url as string | undefined };
    }
  }
  if (cfg.approval !== undefined) {
    if (!isRec(cfg.approval)) errors.push("approval must be a mapping");
    else {
      for (const k of Object.keys(cfg.approval)) if (!["ttl", "webhook", "console_url"].includes(k)) errors.push(`approval: unknown setting \`${k}\``);
      out.approval = { ttl_ms: dur(cfg.approval.ttl, "approval.ttl"), webhook: cfg.approval.webhook as string | undefined, console_url: cfg.approval.console_url as string | undefined };
    }
  }
  if (cfg.capture !== undefined) {
    if (!isRec(cfg.capture)) errors.push("capture must be a mapping");
    else {
      for (const k of Object.keys(cfg.capture)) if (!["enabled", "ttl", "redact_pii"].includes(k)) errors.push(`capture: unknown setting \`${k}\``);
      if (cfg.capture.enabled !== undefined && typeof cfg.capture.enabled !== "boolean") errors.push("capture.enabled must be true or false");
      out.capture = { enabled: cfg.capture.enabled === true, ttl_ms: dur(cfg.capture.ttl, "capture.ttl"), redact_pii: cfg.capture.redact_pii as boolean | undefined };
    }
  }
  if (cfg.notifications !== undefined) {
    if (!isRec(cfg.notifications)) errors.push("notifications must be a mapping");
    else {
      for (const k of Object.keys(cfg.notifications)) if (!["channels", "routes"].includes(k)) errors.push(`notifications: unknown setting \`${k}\``);
      const channels = parseChannels(cfg.notifications.channels, errors);
      out.notifications = { channels, routes: parseRoutes(cfg.notifications.routes, channels, errors) };
    }
  }
  if (cfg.otel !== undefined) {
    if (!isRec(cfg.otel) || typeof cfg.otel.endpoint !== "string") errors.push("otel needs an endpoint");
    else out.otel = cfg.otel as unknown as ProjectConfig["otel"];
  }
  if (cfg.anchor !== undefined) {
    if (!isRec(cfg.anchor) || !Array.isArray(cfg.anchor.sinks) || cfg.anchor.sinks.length === 0) errors.push("anchor needs a list of sinks");
    else {
      const sinks = (cfg.anchor.sinks as Array<Record<string, unknown>>).map((s, i) => {
        if (s.type === "file" && typeof s.path === "string") return { type: "file", path: path(s.path, `anchor.sinks[${i}].path`) as string } as AnchorSink;
        if (s.type === "webhook" && typeof s.url === "string") return { type: "webhook", url: s.url, ...(typeof s.secret === "string" ? { secret: s.secret } : {}) } as AnchorSink;
        errors.push(`anchor.sinks[${i}] must be { type: file, path } or { type: webhook, url }`);
        return undefined;
      });
      out.anchor = { sinks: sinks.filter((s): s is AnchorSink => !!s), interval_ms: dur(cfg.anchor.interval, "anchor.interval") };
    }
  }
  if (cfg.egress !== undefined) {
    if (!isRec(cfg.egress)) errors.push("egress must be a mapping");
    else {
      for (const k of Object.keys(cfg.egress)) if (!["allow", "block_private", "region", "allow_metadata"].includes(k)) errors.push(`egress: unknown setting \`${k}\``);
      out.egress = cfg.egress as EgressConfig;
    }
  }
  if (cfg.alerts !== undefined) {
    if (!isRec(cfg.alerts)) errors.push("alerts must be a mapping");
    else out.alerts = { interval_ms: dur(cfg.alerts.interval, "alerts.interval"), remind_ms: dur(cfg.alerts.remind, "alerts.remind"), denial_spike: cfg.alerts.denial_spike as number | undefined };
  }
  if (cfg.console !== undefined) {
    if (!isRec(cfg.console)) errors.push("console must be a mapping");
    else {
      if (!["off", "open", "login"].includes(cfg.console.mode as string)) errors.push("console.mode must be off, open or login");
      if (cfg.console.role !== undefined && (!ROLES.includes(cfg.console.role as Role) || cfg.console.role === "agent" || cfg.console.role === "admin")) errors.push("console.role must be auditor, approver or operator (an unauthenticated console is never admin)");
      out.console = { mode: cfg.console.mode as "off" | "open" | "login", role: cfg.console.role as Role | undefined };
    }
  }
  if (cfg.log !== undefined) {
    if (!isRec(cfg.log)) errors.push("log must be a mapping");
    else out.log = cfg.log as ProjectConfig["log"];
  }
  if (cfg.reload !== undefined) {
    if (!isRec(cfg.reload)) errors.push("reload must be a mapping");
    else out.reload = { watch: cfg.reload.watch as boolean | undefined, interval_ms: dur(cfg.reload.interval, "reload.interval") };
  }
  if (errors.length) throw new ProjectConfigError(errors.map((e) => `${file}: ${e}`));
  return out;
}

/** A starter config for `reversi init`. */
export function starterConfig(opts: { store: StoreKind }): string {
  return `# Reversi project configuration. Every setting is optional; see the docs for the full list.
manifests: ./manifests          # a folder of YAML/JSON files, a registry folder (reversi manifests publish), or an https URL
policy: ./policy.yaml
data:
  dir: ./reversi-data
  store: ${opts.store}            # files | sqlite | postgres
environment: dev                # matched by policy rules (dev, staging, prod)

# Who is told about what. Secrets come from the environment: \${SLACK_WEBHOOK_URL}.
# notifications:
#   channels:
#     - { type: slack, name: ops, url: "\${SLACK_WEBHOOK_URL}", interactive: false }
#   routes:
#     - { events: [approval_requested, rollback_failed, alert], channels: [ops] }

# Keep redacted arguments for replay and policy simulation (off by default).
# capture:
#   enabled: true
#   ttl: 7d

# console:
#   mode: open        # off (default) | open (no login, localhost only) | login (keys or SSO)
#   role: operator
`;
}
