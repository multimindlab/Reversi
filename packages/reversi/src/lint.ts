/** Manifest linting: unsafe, incomplete or contradictory definitions that are still syntactically valid. */
import type { Registry, ToolManifest } from "./manifest.js";

export interface LintFinding {
  code: string;
  level: "error" | "warning" | "info";
  tool: string;
  message: string;
}

/** What an MCP server says about a tool, when known. */
export interface KnownTool {
  name: string;
  inputSchema?: { properties?: Record<string, unknown>; required?: string[] };
}

const MUTATING = (m: ToolManifest) => m.effect !== "read_only";

export function lintManifests(reg: Registry, opts: { tools?: KnownTool[] } = {}): LintFinding[] {
  const out: LintFinding[] = [];
  const all = reg.list();
  const add = (code: string, level: LintFinding["level"], m: ToolManifest, message: string) => out.push({ code, level, tool: m.tool, message });
  const schemas = new Map((opts.tools ?? []).map((t) => [t.name, t]));
  const writePerms = new Set(all.filter(MUTATING).map((m) => m.permission));

  for (const m of all) {
    if (MUTATING(m) && !m.description) add("L010", "warning", m, "mutating tool has no description: reviewers cannot tell what it does");
    if (MUTATING(m) && !m.owner) add("L011", "warning", m, "mutating tool has no owner: nobody is named to ask when it misbehaves");
    if (MUTATING(m) && !m.risk?.data_class) add("L012", "warning", m, "no risk.data_class: policy and retention cannot treat sensitive data differently");
    if (m.effect === "compensable" && !(m.compensation?.residue.length)) add("L013", "warning", m, "compensable means the undo leaves residue; declare what it leaves in compensation.residue");
    if (m.effect === "reversible" && m.compensation?.kind === "compensation" && m.compensation.residue.length) add("L030", "warning", m, "declared reversible but the compensation lists residue: it is compensable, not reversible");
    if (m.effect === "compensable" && m.compensation?.kind === "inverse") add("L031", "warning", m, "declared compensable but the compensation is an exact inverse: it may be reversible");
    if (m.compensation) {
      const ct = reg.get(m.compensation.tool);
      if (ct && ct.effect !== "idempotent") add("L014", "warning", m, `compensation \`${ct.tool}\` is ${ct.effect}, not idempotent: rollback retries it, so running twice must be safe`);
      if (!m.compensation.verification) add("L016", "info", m, "the undo is not verified: add compensation.verification to read back that it worked");
      if (Object.keys(m.compensation.argument_map).length === 0 && m.effect !== "irreversible") add("L032", "info", m, "compensation takes no arguments from the call: confirm it can identify what to undo");
    }
    if (m.effect === "irreversible") {
      if (!m.risk?.blast_radius && !m.approval_rules) add("L015", "warning", m, "irreversible with no blast_radius and no named approvers");
      if (m.audit?.evidence_export !== "required") add("L021", "info", m, "irreversible actions should set audit.evidence_export: required");
    }
    if (MUTATING(m) && !m.timeout_ms) add("L022", "info", m, "no timeout_ms: a hung call is only bounded by the gateway default");
    if (m.effect === "read_only" && writePerms.has(m.permission)) add("L019", "warning", m, `read-only tool shares permission \`${m.permission}\` with tools that change things: a read-only agent could not be scoped separately`);
    if (m.status === "draft") add("L024", "warning", m, "draft manifest: it is not enforceable until approved");
    if (!m.schema_hash && opts.tools) add("L027", "info", m, "no schema_hash: the gateway cannot notice if the upstream tool's input schema changes");

    const known = schemas.get(m.tool);
    if (known?.inputSchema?.properties) {
      const props = Object.keys(known.inputSchema.properties);
      const first = (ref: string) => ref.replace(/^\$args\./, "").split(".")[0] as string;
      for (const [k, ref] of Object.entries(m.compensation?.argument_map ?? {})) if (ref.startsWith("$args.") && !props.includes(first(ref))) add("L017", "error", m, `compensation.argument_map.${k} reads \`${ref}\` but the tool's input schema has no \`${first(ref)}\``);
      for (const ref of Object.values(m.compensation?.verification?.arguments ?? {})) if (ref.startsWith("$args.") && !props.includes(first(ref))) add("L017", "error", m, `verification reads \`${ref}\` but the tool's input schema has no \`${first(ref)}\``);
      for (const mm of m.idempotency?.key.matchAll(/\{\{\s*args\.([A-Za-z0-9_-]+)/g) ?? []) if (!props.includes(mm[1] as string)) add("L020", "error", m, `idempotency key uses args.${mm[1]} which the tool's input schema does not have`);
      for (const p of m.audit?.redaction ?? []) if (p.startsWith("$args.") && !props.includes(first(p))) add("L033", "warning", m, `redaction path \`${p}\` names an argument the input schema does not have`);
    } else if (opts.tools && !known) {
      add("L034", "warning", m, "no tool with this name was found on the upstream: the manifest may be stale or misnamed");
    }
  }

  // requires cycles
  const state = new Map<string, number>();
  const stack: string[] = [];
  const visit = (name: string): void => {
    if (state.get(name) === 2) return;
    if (state.get(name) === 1) {
      const m = reg.get(name);
      if (m) add("L023", "error", m, `\`requires\` forms a cycle: ${[...stack.slice(stack.indexOf(name)), name].join(" -> ")}`);
      return;
    }
    state.set(name, 1);
    stack.push(name);
    for (const r of reg.get(name)?.requires ?? []) visit(r);
    stack.pop();
    state.set(name, 2);
  };
  for (const m of all) visit(m.tool);

  // upstream tools with no manifest
  for (const t of opts.tools ?? []) if (!reg.has(t.name)) out.push({ code: "L035", level: "warning", tool: t.name, message: "the upstream offers this tool but no manifest describes it: it will be blocked in enforce mode" });
  return out;
}

export const hasErrors = (f: LintFinding[]) => f.some((x) => x.level === "error");
