/**
 * Drafting manifests from what an MCP server says about its tools: names, descriptions, input schemas and annotations
 * (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), plus the `mcp-compensate` convention when a server
 * declares it. Annotations are the server's own claims, so they only ever seed a **draft**: nothing here grants anything.
 */
import { createHash } from "node:crypto";
import { canonicalize } from "./canonical.js";
import type { Registry } from "./manifest.js";

export interface McpToolInfo {
  name: string;
  description?: string;
  inputSchema?: { properties?: Record<string, unknown>; required?: string[]; type?: string };
  outputSchema?: { properties?: Record<string, unknown> } | undefined;
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean; title?: string } & Record<string, unknown>;
  _meta?: Record<string, unknown>;
}

export interface Hints {
  read_only?: boolean;
  destructive?: boolean;
  idempotent?: boolean;
  open_world?: boolean;
}

export function hintsOf(t: McpToolInfo): Hints {
  const a = t.annotations ?? {};
  return {
    ...(typeof a.readOnlyHint === "boolean" ? { read_only: a.readOnlyHint } : {}),
    ...(typeof a.destructiveHint === "boolean" ? { destructive: a.destructiveHint } : {}),
    ...(typeof a.idempotentHint === "boolean" ? { idempotent: a.idempotentHint } : {}),
    ...(typeof a.openWorldHint === "boolean" ? { open_world: a.openWorldHint } : {}),
  };
}

/** Hash of a tool's input schema, stored in a manifest as `schema_hash` so drift can be noticed. */
export function schemaHash(t: McpToolInfo): string {
  return createHash("sha256").update(canonicalize(t.inputSchema ?? {})).digest("hex").slice(0, 16);
}

export interface CompensateMeta {
  readonly?: boolean;
  compensable?: boolean;
  irreversible?: boolean;
  compensation?: { tool: string; mapping: Record<string, string> };
}

/**
 * Read the `mcp-compensate` convention from a tool: under `_meta["mcp-compensate"]`, `_meta.compensate` or
 * `annotations["mcp-compensate"]`, an object with `readonly`, `compensable`, `irreversible` flags and a
 * `compensation: { tool, parameters | params | mapping }` whose mapping is `{ compensationArg: "$result.x" | "$args.y" }`.
 * (This is the shape Reversi accepts; check it against your server's documentation.)
 */
export function compensateMetaOf(t: McpToolInfo): CompensateMeta | undefined {
  const raw = (t._meta?.["mcp-compensate"] ?? t._meta?.compensate ?? t.annotations?.["mcp-compensate"]) as Record<string, unknown> | undefined;
  if (typeof raw !== "object" || raw === null) return undefined;
  const out: CompensateMeta = {};
  if (typeof raw.readonly === "boolean") out.readonly = raw.readonly;
  if (typeof raw.compensable === "boolean") out.compensable = raw.compensable;
  if (typeof raw.irreversible === "boolean") out.irreversible = raw.irreversible;
  const c = raw.compensation as Record<string, unknown> | string | undefined;
  const tool = typeof c === "string" ? c : typeof c?.tool === "string" ? c.tool : undefined;
  if (tool) {
    const m = (typeof c === "object" ? (c.mapping ?? c.parameters ?? c.params) : undefined) as Record<string, unknown> | undefined;
    const mapping = Object.fromEntries(Object.entries(m ?? {}).filter(([, v]) => typeof v === "string" && /^\$(args|result)(\.[A-Za-z0-9_-]+)+$/.test(v as string)) as Array<[string, string]>);
    out.compensation = { tool, mapping };
  }
  return Object.keys(out).length ? out : undefined;
}

const READ_VERBS = ["get", "list", "read", "search", "find", "describe", "fetch", "query", "show", "view", "check", "lookup", "count", "head", "stat", "retrieve", "browse", "export"];
const DESTRUCTIVE_VERBS = ["delete", "remove", "drop", "destroy", "purge", "wipe", "erase", "truncate", "send", "publish", "charge", "pay", "transfer", "deploy", "merge", "execute", "exec", "run", "kill", "terminate", "revoke"];
// forward verb -> verbs that undo it
const INVERSES: Record<string, string[]> = {
  create: ["delete", "remove", "cancel", "close", "archive", "destroy"],
  add: ["remove", "delete", "unset"],
  open: ["close"],
  put: ["restore", "revert", "delete"],
  write: ["restore", "revert", "delete"],
  set: ["unset", "restore", "revert"],
  update: ["restore", "revert"],
  edit: ["restore", "revert"],
  post: ["delete", "remove"],
  enable: ["disable"],
  start: ["stop"],
  scale: ["restore", "unscale"],
  charge: ["refund"],
  grant: ["revoke"],
  lock: ["unlock"],
  subscribe: ["unsubscribe"],
  schedule: ["cancel", "unschedule"],
  insert: ["delete", "restore"],
  move: ["unmove", "restore"],
  transition: ["restore"],
  assign: ["unassign"],
  tag: ["untag"],
  label: ["unlabel"],
  react: ["unreact"],
};

function split(name: string): { prefix: string; verb: string; noun: string } {
  const dot = Math.max(name.lastIndexOf("."), name.lastIndexOf("/"), name.lastIndexOf(":"));
  const prefix = dot >= 0 ? name.slice(0, dot + 1) : "";
  const rest = name.slice(dot + 1);
  const words = rest.split(/[_\-\s]+|(?<=[a-z])(?=[A-Z])/).filter(Boolean).map((w) => w.toLowerCase());
  return { prefix, verb: words[0] ?? "", noun: words.slice(1).join("_") };
}

export interface Suggestion {
  manifest: Record<string, unknown>;
  confidence: "low" | "medium" | "high";
  notes: string[];
}

export interface SuggestOptions {
  /** Server name, used for permission names (`<server>:read`). */
  server?: string;
  /** Tools that already have manifests are skipped. */
  existing?: Registry;
  /** Draft only these tools. */
  only?: string[];
}

function dataClassOf(name: string, desc: string): string {
  const s = `${name} ${desc}`.toLowerCase();
  if (/(secret|token|credential|password|api[_ -]?key|private[_ -]?key)/.test(s)) return "secret";
  if (/(payment|invoice|charge|refund|billing|card|payout|ledger|price)/.test(s)) return "financial";
  if (/(customer|user|email|contact|person|employee|patient|profile|address|phone)/.test(s)) return "pii";
  return "internal";
}

function mapArgs(forward: McpToolInfo, comp: McpToolInfo, notes: string[]): Record<string, string> {
  const fProps = Object.keys(forward.inputSchema?.properties ?? {});
  const cProps = Object.keys(comp.inputSchema?.properties ?? {});
  const required = comp.inputSchema?.required ?? cProps;
  const out: Record<string, string> = {};
  for (const p of required.filter((x) => cProps.includes(x))) {
    if (fProps.includes(p) && !/(^|_)(id|number|key|ts|uuid)$/.test(p)) out[p] = `$args.${p}`;
    else if (/(^|_)(id|number|key|ts|uuid|name)$/.test(p) || p === "id") out[p] = `$result.${p}`;
    else if (fProps.includes(p)) out[p] = `$args.${p}`;
    else {
      out[p] = `$result.${p}`;
      notes.push(`could not tell where the undo's \`${p}\` comes from: assumed \`$result.${p}\`, check the tool's output`);
    }
  }
  return out;
}

export function suggestManifests(tools: McpToolInfo[], o: SuggestOptions = {}): { suggestions: Suggestion[]; skipped: string[]; ignored: string[] } {
  const byName = new Map(tools.map((t) => [t.name, t]));
  const server = (o.server ?? "upstream").replace(/[^A-Za-z0-9_.-]/g, "_");
  const suggestions: Suggestion[] = [];
  const skipped: string[] = [];
  const claimedAsUndo = new Set<string>();

  const parsed = tools.map((t) => ({ t, ...split(t.name), hints: hintsOf(t), cm: compensateMetaOf(t) }));
  const isReadLike = (p: (typeof parsed)[number]) => p.cm?.readonly === true || p.hints.read_only === true || (READ_VERBS.includes(p.verb) && p.hints.destructive !== true);
  const findInverse = (p: (typeof parsed)[number]): McpToolInfo | undefined => {
    for (const inv of INVERSES[p.verb] ?? []) {
      const cand = parsed.find((q) => q.t.name !== p.t.name && q.prefix === p.prefix && q.verb === inv && (q.noun === p.noun || (p.noun === "" && q.noun === "")));
      if (cand) return cand.t;
    }
    return undefined;
  };

  // Which tools are somebody's undo? They get drafted as idempotent helpers rather than as irreversible actions.
  const undoOf = new Set<string>();
  for (const p of parsed) {
    if (p.cm?.compensation) undoOf.add(p.cm.compensation.tool);
    else if (!isReadLike(p) && p.hints.destructive !== true) {
      const inv = findInverse(p);
      if (inv) undoOf.add(inv.name);
    }
  }
  for (const p of parsed) {
    if (o.only && !o.only.includes(p.t.name)) continue;
    if (o.existing?.has(p.t.name)) {
      skipped.push(p.t.name);
      continue;
    }
    const notes: string[] = [];
    let confidence: Suggestion["confidence"] = "low";
    const desc = p.t.description?.split("\n")[0]?.trim() ?? "";
    let effect: string;
    let compensation: Record<string, unknown> | undefined;

    const readByName = READ_VERBS.includes(p.verb);
    if (p.cm?.readonly === true || p.hints.read_only === true) {
      effect = "read_only";
      confidence = p.cm?.readonly ? "high" : "medium";
      notes.push(p.cm?.readonly ? "read-only per the server's mcp-compensate metadata" : "read-only per the server's readOnlyHint (a claim by the server, not verified)");
    } else if (p.cm?.irreversible === true) {
      effect = "irreversible";
      confidence = "high";
      notes.push("irreversible per the server's mcp-compensate metadata");
    } else if (p.cm?.compensation) {
      effect = p.cm.compensable === false ? "reversible" : "compensable";
      confidence = "high";
      const c = byName.get(p.cm.compensation.tool);
      compensation = { tool: p.cm.compensation.tool, argument_map: p.cm.compensation.mapping };
      if (!c) notes.push(`mcp-compensate names \`${p.cm.compensation.tool}\` as the undo but the server does not list it`);
      claimedAsUndo.add(p.cm.compensation.tool);
    } else if (readByName && p.hints.destructive !== true) {
      effect = "read_only";
      confidence = "low";
      notes.push(`classified read_only from the name \`${p.verb}_…\` only: confirm it changes nothing`);
    } else {
      const inv = findInverse(p);
      if (inv && p.hints.destructive !== true) {
        const map = mapArgs(p.t, inv, notes);
        effect = "compensable";
        compensation = { tool: inv.name, argument_map: map, kind: "compensation", residue: ["TODO describe what the undo cannot take back"] };
        confidence = "medium";
        notes.push(`undo guessed from the tool names: \`${inv.name}\`; check the argument map and decide whether it is a true inverse (reversible) or leaves residue (compensable)`);
        claimedAsUndo.add(inv.name);
      } else if (p.hints.idempotent === true && p.hints.destructive !== true) {
        effect = "idempotent";
        confidence = "medium";
        notes.push("idempotent per the server's idempotentHint (unverified)");
      } else if (undoOf.has(p.t.name)) {
        effect = "idempotent";
        confidence = "medium";
        notes.push("used as another tool's undo, so it is drafted idempotent: rollback may call it more than once; confirm that is safe");
      } else {
        effect = "irreversible";
        confidence = p.hints.destructive === true || DESTRUCTIVE_VERBS.includes(p.verb) ? "medium" : "low";
        notes.push(p.hints.destructive === true ? "marked destructive by the server and no undo tool was found" : "no undo tool was found, so it is drafted as irreversible: the safe default until you say otherwise");
      }
    }
    const props = Object.keys(p.t.inputSchema?.properties ?? {});
    const m: Record<string, unknown> = {
      tool: p.t.name,
      ...(desc ? { description: desc } : { description: `${p.t.name} (describe what this does)` }),
      effect,
      permission: `${server}:${effect === "read_only" ? "read" : effect === "irreversible" ? "admin" : "write"}`,
      status: "draft",
      ...(effect === "read_only" ? {} : { risk: { data_class: dataClassOf(p.t.name, desc), blast_radius: effect === "irreversible" ? "high" : "medium" } }),
      ...(compensation ? { compensation } : {}),
      ...(p.t.inputSchema ? { schema_hash: schemaHash(p.t) } : {}),
    };
    if (effect === "irreversible") m.approval = "always";
    if (props.length === 0 && effect !== "read_only") notes.push("the tool takes no arguments, so an undo cannot identify what to undo");
    if (p.hints.open_world === true) notes.push("openWorldHint: it reaches outside systems; consider a lower blast-radius budget and egress rules");
    suggestions.push({ manifest: m, confidence, notes });
  }
  // The undo tools themselves are idempotent helpers: draft them too if the server offers them and they were not drafted.
  for (const name of claimedAsUndo) {
    if (suggestions.some((s) => s.manifest.tool === name) || o.existing?.has(name) || (o.only && !o.only.includes(name))) continue;
    const t = byName.get(name);
    if (!t) continue;
    suggestions.push({
      manifest: { tool: name, description: t.description?.split("\n")[0]?.trim() || `${name} (undo helper)`, effect: "idempotent", permission: `${server}:write`, status: "draft", ...(t.inputSchema ? { schema_hash: schemaHash(t) } : {}) },
      confidence: "medium",
      notes: ["used as another tool's undo, so it is drafted idempotent: rollback may call it more than once; confirm that is safe"],
    });
  }
  const names = new Set(suggestions.map((s) => s.manifest.tool as string));
  return { suggestions, skipped, ignored: tools.filter((t) => !names.has(t.name) && !skipped.includes(t.name)).map((t) => t.name) };
}
