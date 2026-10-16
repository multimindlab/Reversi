import { EffectUncertainError } from "@multimindlab/reversi";

export type Fetch = typeof fetch;

export interface ToolContext {
  idempotency_key?: string;
}
export type ToolHandler = (args: Record<string, unknown>, ctx: ToolContext) => Promise<unknown> | unknown;

export interface Connector {
  name: string;
  manifests: unknown[];
  tools: Record<string, ToolHandler>;
  inputSchemas: Record<string, object>;
}

export interface ToolSpec {
  /** Short name; the full tool name is `<connector>.<name>`. */
  name: string;
  description: string;
  effect: "read_only" | "idempotent" | "reversible" | "compensable" | "irreversible";
  permission: string;
  approval?: "never" | "always";
  /** `tool` is a short name within the same connector. */
  compensation?: { tool: string; argument_map: Record<string, string>; requires_approval?: boolean };
  properties: Record<string, object>;
  required?: string[];
  handler: ToolHandler;
}

type Args = Record<string, unknown>;

function isRecord(x: unknown): x is Args {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

export function defineConnector(name: string, specs: ToolSpec[]): Connector {
  const manifests: unknown[] = [];
  const tools: Record<string, ToolHandler> = {};
  const inputSchemas: Record<string, object> = {};
  for (const s of specs) {
    const full = `${name}.${s.name}`;
    const m: Record<string, unknown> = {
      tool: full,
      description: s.description,
      effect: s.effect,
      permission: s.permission,
    };
    if (s.approval) m.approval = s.approval;
    if (s.compensation) {
      m.compensation = {
        tool: `${name}.${s.compensation.tool}`,
        argument_map: s.compensation.argument_map,
        requires_approval: s.compensation.requires_approval ?? false,
      };
    }
    manifests.push(m);
    const allowed = new Set(Object.keys(s.properties));
    tools[full] = async (args, ctx) => {
      if (!isRecord(args)) throw new Error(`${full}: arguments must be an object`);
      for (const k of Object.keys(args)) {
        if (!allowed.has(k)) throw new Error(`${full}: unknown argument \`${k}\``);
      }
      return s.handler(args, ctx ?? {});
    };
    inputSchemas[full] = {
      type: "object",
      description: s.description,
      properties: s.properties,
      required: s.required ?? [],
      additionalProperties: false,
    };
  }
  return { name, manifests, tools, inputSchemas };
}

export function str(args: Args, key: string, opts: { max?: number } = {}): string {
  const v = args[key];
  if (typeof v !== "string" || v.length === 0) throw new Error(`\`${key}\` must be a non-empty string`);
  if (v.length > (opts.max ?? 65536)) throw new Error(`\`${key}\` is too long`);
  return v;
}

export function optStr(args: Args, key: string, opts: { max?: number } = {}): string | undefined {
  if (args[key] === undefined) return undefined;
  return str(args, key, opts);
}

export function posInt(args: Args, key: string): number {
  const v = args[key];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v <= 0) {
    throw new Error(`\`${key}\` must be a positive integer`);
  }
  return v;
}

export function optPosInt(args: Args, key: string): number | undefined {
  if (args[key] === undefined) return undefined;
  return posInt(args, key);
}

export function strList(args: Args, key: string, opts: { allowEmpty?: boolean } = {}): string[] {
  const v = args[key];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || x.length === 0 || x.length > 256)) {
    throw new Error(`\`${key}\` must be an array of non-empty strings`);
  }
  if (v.length === 0 && !opts.allowEmpty) throw new Error(`\`${key}\` must not be empty`);
  return v as string[];
}

export function optStrList(args: Args, key: string): string[] | undefined {
  if (args[key] === undefined) return undefined;
  return strList(args, key, { allowEmpty: true });
}

export function matches(args: Args, key: string, re: RegExp, what: string): string {
  const v = str(args, key, { max: 256 });
  if (!re.test(v)) throw new Error(`\`${key}\` is not a valid ${what}`);
  return v;
}

export function optMatches(args: Args, key: string, re: RegExp, what: string): string | undefined {
  if (args[key] === undefined) return undefined;
  return matches(args, key, re, what);
}

/** A string-to-string map; numbers and booleans are stringified. */
export function optStringMap(args: Args, key: string): Record<string, string> | undefined {
  const v = args[key];
  if (v === undefined) return undefined;
  if (!isRecord(v)) throw new Error(`\`${key}\` must be an object`);
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v)) {
    if (!/^[A-Za-z0-9_.-]{1,40}$/.test(k)) throw new Error(`\`${key}\` has an invalid key \`${k}\``);
    if (typeof val !== "string" && typeof val !== "number" && typeof val !== "boolean") {
      throw new Error(`\`${key}.${k}\` must be a string, number or boolean`);
    }
    out[k] = String(val);
  }
  return out;
}

export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export function redact(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) if (s) out = out.split(s).join("[redacted]");
  return out;
}

export interface Sent {
  status: number;
  ok: boolean;
  json: unknown;
  text: string;
  /** Raw body, set only when the request was sent with `binary: true`. */
  bytes?: Uint8Array;
  headers: Headers;
}

export interface SendOptions {
  label: string;
  mutating: boolean;
  secrets: string[];
  timeoutMs: number;
  /** Read the body as bytes (object downloads) instead of text. */
  binary?: boolean;
}

/**
 * One HTTP exchange. A transport failure or timeout on a mutating call throws EffectUncertainError,
 * because the request may have been applied. Never returns or throws the secret.
 */
export async function send(f: Fetch, url: string, init: RequestInit, o: SendOptions): Promise<Sent> {
  let res: Response;
  let text: string;
  let bytes: Uint8Array | undefined;
  try {
    res = await f(url, { ...init, signal: AbortSignal.timeout(o.timeoutMs) });
    if (o.binary) {
      bytes = new Uint8Array(await res.arrayBuffer());
      text = res.status >= 200 && res.status < 300 ? "" : new TextDecoder().decode(bytes);
    } else {
      text = await res.text();
    }
  } catch (e) {
    const msg = redact(e instanceof Error ? e.message : String(e), o.secrets);
    if (o.mutating) throw new EffectUncertainError(`${o.label}: no response (${msg}); the effect may have happened`);
    throw new Error(`${o.label}: request failed (${msg})`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: res.status, ok: res.status >= 200 && res.status < 300, json, text, bytes, headers: res.headers };
}

export function snippet(s: Sent, secrets: string[]): string {
  let m = s.text;
  if (isRecord(s.json)) {
    const e = s.json.error;
    if (typeof s.json.message === "string") m = s.json.message;
    else if (isRecord(e) && typeof e.message === "string") m = e.message;
    else if (typeof e === "string") m = e;
  }
  m = redact(m, secrets).replace(/\s+/g, " ").trim();
  return m.length > 200 ? m.slice(0, 200) + "…" : m;
}

export function asRecord(x: unknown): Args {
  return isRecord(x) ? x : {};
}

/** Text of the first `<tag>` element, with the five XML entities decoded. */
export function xmlText(xml: string, tag: string): string | undefined {
  const m = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`).exec(xml);
  return m ? xmlDecode(m[1]!) : undefined;
}

/** Inner XML of every `<tag>` element. */
export function xmlBlocks(xml: string, tag: string): string[] {
  return [...xml.matchAll(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "g"))].map((m) => m[1]!);
}

export function xmlDecode(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

/** A zero-or-more integer argument. */
export function nonNegInt(args: Args, key: string): number {
  const v = args[key];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
    throw new Error(`\`${key}\` must be a non-negative integer`);
  }
  return v;
}

/** Prefix under which object-store connectors keep the previous version of an object they overwrite or delete. */
export const BACKUP_PREFIX = ".reversi-backups/";

export function assertNotBackupKey(key: string, what: string): void {
  if (key.startsWith(BACKUP_PREFIX)) throw new Error(`\`${what}\` points into ${BACKUP_PREFIX}, which is reserved`);
}
