/** Gateway configuration: a YAML or JSON file, validated up front with every error reported. */
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import { PolicyError, ROLES, parsePolicy, type PolicyDoc, type Role } from "@multimindlab/reversi";

export interface UpstreamConfig {
  name: string;
  /** stdio upstream: command plus arguments. */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  /** Streamable HTTP upstream. */
  url?: string;
  headers?: Record<string, string>;
  /** Prefix exposed tool names with `<name>.`. Default: true when there is more than one upstream. */
  namespace?: boolean;
}

export interface OidcConfig {
  issuer: string;
  audience: string;
  role_map: Record<string, Role>;
  role_claim?: string;
  jwks_uri?: string;
}

export interface GatewayConfig {
  /** `observe` journals and never blocks; `enforce` blocks. Default enforce. */
  mode: "observe" | "enforce";
  /** Actor recorded for unauthenticated sessions (stdio, or HTTP on loopback with no auth). */
  actor: string;
  /** Permissions for each session's scope. Default: every permission in the manifests. */
  permissions?: string[];
  upstreams: UpstreamConfig[];
  /** Tool-name globs (as exposed). If non-empty, only matching tools may be called. */
  allow: string[];
  deny: string[];
  /** HTTP mode. Omit to speak MCP on stdio. */
  listen?: { host: string; port: number };
  /** Public URL of this gateway; the OIDC audience should match it. Used for protected-resource metadata. */
  resource_url?: string;
  allowed_hosts?: string[];
  allowed_origins?: string[];
  auth?: { keys?: string; oidc?: OidcConfig };
}

export class ConfigError extends Error {
  constructor(public readonly errors: string[]) {
    super(errors.join("; "));
    this.name = "ConfigError";
  }
}

const isRec = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const strList = (x: unknown) => Array.isArray(x) && x.every((s) => typeof s === "string");
const strMap = (x: unknown) => isRec(x) && Object.values(x).every((v) => typeof v === "string");

/** `${NAME}` in strings becomes the environment variable, so secrets stay out of config files. */
export function expandEnv(s: string, env: Record<string, string | undefined> = process.env): string {
  return s.replace(/\$\{([A-Z_][A-Z0-9_]*)\}/gi, (_m, name: string) => {
    const v = env[name];
    if (v === undefined) throw new ConfigError([`environment variable ${name} is not set`]);
    return v;
  });
}

export function parseGatewayConfig(raw: unknown): GatewayConfig {
  const errors: string[] = [];
  if (!isRec(raw)) throw new ConfigError(["config must be an object"]);
  const known = ["mode", "actor", "permissions", "upstreams", "allow", "deny", "listen", "resource_url", "allowed_hosts", "allowed_origins", "auth"];
  for (const k of Object.keys(raw)) if (!known.includes(k)) errors.push(`unknown field \`${k}\``);
  const mode = raw.mode ?? "enforce";
  if (mode !== "observe" && mode !== "enforce") errors.push("`mode` must be observe or enforce");
  if (raw.actor !== undefined && (typeof raw.actor !== "string" || !raw.actor)) errors.push("`actor` must be a non-empty string");
  for (const k of ["permissions", "allow", "deny", "allowed_hosts", "allowed_origins"]) {
    if (raw[k] !== undefined && !strList(raw[k])) errors.push(`\`${k}\` must be a list of strings`);
  }

  const upstreams: UpstreamConfig[] = [];
  if (!Array.isArray(raw.upstreams) || raw.upstreams.length === 0) errors.push("`upstreams` must list at least one upstream MCP server");
  else {
    const names = new Set<string>();
    raw.upstreams.forEach((u: unknown, i: number) => {
      const w = `upstreams[${i}]`;
      if (!isRec(u)) return void errors.push(`${w}: must be an object`);
      for (const k of Object.keys(u)) if (!["name", "command", "args", "env", "cwd", "url", "headers", "namespace"].includes(k)) errors.push(`${w}: unknown field \`${k}\``);
      if (typeof u.name !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(u.name)) errors.push(`${w}: name must be letters, digits, _ or - (max 64)`);
      else if (names.has(u.name)) errors.push(`${w}: duplicate name \`${u.name}\``);
      else names.add(u.name);
      if (!!u.command === !!u.url) errors.push(`${w}: set exactly one of \`command\` (stdio) or \`url\` (Streamable HTTP)`);
      if (u.args !== undefined && !strList(u.args)) errors.push(`${w}: args must be a list of strings`);
      if (u.env !== undefined && !strMap(u.env)) errors.push(`${w}: env must map names to strings`);
      if (u.headers !== undefined && !strMap(u.headers)) errors.push(`${w}: headers must map names to strings`);
      if (u.url !== undefined) {
        try {
          const p = new URL(String(u.url));
          if (p.protocol !== "https:" && p.protocol !== "http:") errors.push(`${w}: url must be http(s)`);
        } catch {
          errors.push(`${w}: url is not valid`);
        }
      }
      upstreams.push(u as unknown as UpstreamConfig);
    });
  }

  let listen: GatewayConfig["listen"];
  if (raw.listen !== undefined) {
    const l = raw.listen;
    if (!isRec(l) || !Number.isInteger(l.port) || (l.port as number) < 0 || (l.port as number) > 65535) errors.push("`listen` needs a port (0-65535) and optional host");
    else listen = { host: typeof l.host === "string" ? l.host : "127.0.0.1", port: l.port as number };
  }

  let auth: GatewayConfig["auth"];
  if (raw.auth !== undefined) {
    const a = raw.auth;
    if (!isRec(a)) errors.push("`auth` must be an object");
    else {
      auth = {};
      for (const k of Object.keys(a)) if (!["keys", "oidc"].includes(k)) errors.push(`auth: unknown field \`${k}\``);
      if (a.keys !== undefined) typeof a.keys === "string" ? (auth.keys = a.keys) : errors.push("auth.keys must be a path to a JSON file of API keys");
      if (a.oidc !== undefined) {
        const o = a.oidc;
        if (!isRec(o) || typeof o.issuer !== "string" || typeof o.audience !== "string" || !isRec(o.role_map)) errors.push("auth.oidc needs issuer, audience and role_map");
        else {
          if (Object.values(o.role_map).some((r) => !ROLES.includes(r as Role))) errors.push(`auth.oidc.role_map values must be among ${ROLES.join(", ")}`);
          auth.oidc = o as unknown as OidcConfig;
        }
      }
    }
  }
  if (errors.length) throw new ConfigError(errors);
  return {
    mode: mode as GatewayConfig["mode"],
    actor: (raw.actor as string | undefined) ?? "mcp-client",
    permissions: raw.permissions as string[] | undefined,
    upstreams,
    allow: (raw.allow as string[] | undefined) ?? [],
    deny: (raw.deny as string[] | undefined) ?? [],
    listen,
    resource_url: raw.resource_url as string | undefined,
    allowed_hosts: raw.allowed_hosts as string[] | undefined,
    allowed_origins: raw.allowed_origins as string[] | undefined,
    auth,
  };
}

export function loadGatewayConfig(path: string): GatewayConfig {
  const text = readFileSync(path, "utf8");
  return parseGatewayConfig(extname(path).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text));
}

/** allow/deny lists as a policy document, merged with any policy file by the engine. */
export function allowDenyPolicy(cfg: Pick<GatewayConfig, "allow" | "deny">): PolicyDoc | undefined {
  if (cfg.allow.length === 0 && cfg.deny.length === 0) return undefined;
  try {
    return parsePolicy({
      version: 1,
      default: cfg.allow.length ? "deny" : "allow",
      rules: [
        ...cfg.deny.map((g, i) => ({ id: `gateway-deny-${i}`, match: { tool: g }, action: "deny", reason: "denied by the gateway's deny list" })),
        ...(cfg.allow.length ? [{ id: "gateway-allow", match: { tool: cfg.allow }, action: "allow" }] : []),
      ],
    });
  } catch (e) {
    throw e instanceof PolicyError ? new ConfigError(e.errors) : e;
  }
}
