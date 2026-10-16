/** What a gateway knows about each upstream tool at a glance: classified by a manifest, or not, and what the server claims. */
import type { Registry } from "./manifest.js";
import { hintsOf, type Hints, type McpToolInfo } from "./suggest.js";

export type ToolClass = "classified" | "unclassified_read_hint" | "unclassified_mutation" | "destructive_no_manifest";

export interface ClassifiedTool {
  name: string;
  class: ToolClass;
  effect?: string;
  status?: string;
  hints: Hints;
  /** Short human text for the startup banner. */
  line: string;
}

export function classifyTools(reg: Registry, tools: McpToolInfo[]): ClassifiedTool[] {
  return tools.map((t) => {
    const m = reg.get(t.name);
    const hints = hintsOf(t);
    if (m) return { name: t.name, class: "classified", effect: m.effect, status: m.status, hints, line: `OK     ${t.name} - ${m.effect}${m.status !== "approved" ? ` (${m.status})` : ""}` };
    if (hints.read_only === true) return { name: t.name, class: "unclassified_read_hint", hints, line: `NOTE   ${t.name} - no manifest; the server says it is read-only (unverified)` };
    if (hints.destructive === true) return { name: t.name, class: "destructive_no_manifest", hints, line: `BLOCK  ${t.name} - destructive per the server, no manifest` };
    return { name: t.name, class: "unclassified_mutation", hints, line: `WARN   ${t.name} - no manifest; treated as a change that could not be undone` };
  });
}

export function banner(rows: ClassifiedTool[], opts: { mode: string; next?: string }): string {
  const n = (c: ToolClass) => rows.filter((r) => r.class === c).length;
  const lines = [`Reversi gateway running in ${opts.mode} mode.`, "", ...rows.map((r) => r.line), ""];
  lines.push(`${n("classified")} classified, ${n("unclassified_read_hint")} unclassified reads, ${n("unclassified_mutation")} unclassified changes, ${n("destructive_no_manifest")} destructive without a manifest.`);
  if (opts.next) lines.push("", opts.next);
  return lines.join("\n");
}
