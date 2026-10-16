/**
 * The periodic report: what agents did, what was blocked or would have been (the observe/advise findings), what needed
 * approval, how rollbacks went, and what needs attention. Built from the ledger, run state and approvals.
 */
import type { Approvals } from "./approvals.js";
import type { Reversi } from "./engine.js";
import { searchRuns } from "./query.js";

export interface TopEntry {
  key: string;
  count: number;
}

export interface PeriodReport {
  from_ms: number;
  to_ms: number;
  runs: number;
  calls: number;
  actors: TopEntry[];
  tools: TopEntry[];
  /** Calls by the effect class of the manifest (or "no manifest"). */
  by_effect: TopEntry[];
  outcomes: { succeeded: number; failed: number; uncertain: number };
  blocked: { total: number; reasons: TopEntry[] };
  would_block: { total: number; reasons: TopEntry[] };
  unclassified_tools: TopEntry[];
  approvals: { requested: number; approved: number; denied: number; expired: number; escalated: number; median_latency_s: number | null };
  rollback: { compensated: number; failed: number; unverified: number; verified: number; success_rate: number | null };
  irreversible_executed: number;
  needs_attention: Array<{ run_id: string; actor: string; status: string }>;
  budget_warnings: TopEntry[];
  days: Array<{ day: string; calls: number; blocked: number }>;
}

const top = (m: Map<string, number>, n = 10): TopEntry[] => [...m].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n).map(([key, count]) => ({ key, count }));
const bump = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) ?? 0) + 1);
const reasonKey = (detail: string) => detail.replace(/apr_[0-9a-f-]+/g, "apr_…").replace(/`[^`]*`/g, (x) => x).slice(0, 140) || "(no detail)";

export function buildPeriodReport(rv: Reversi, approvals: Approvals | undefined, from_ms: number, to_ms: number = Date.now()): PeriodReport {
  const actors = new Map<string, number>();
  const tools = new Map<string, number>();
  const byEffect = new Map<string, number>();
  const blocked = new Map<string, number>();
  const wouldBlock = new Map<string, number>();
  const unclassified = new Map<string, number>();
  const budget = new Map<string, number>();
  const days = new Map<string, { calls: number; blocked: number }>();
  const runsSeen = new Set<string>();
  const out = { succeeded: 0, failed: 0, uncertain: 0 };
  const rb = { compensated: 0, failed: 0, unverified: 0, verified: 0 };
  let calls = 0;
  let irreversible = 0;
  let blockedTotal = 0;
  let wouldTotal = 0;
  const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);

  for (const r of rv.ledger.records()) {
    if (r.ts_ms < from_ms || r.ts_ms > to_ms) continue;
    if (r.run_id !== "-") runsSeen.add(r.run_id);
    const d = days.get(day(r.ts_ms)) ?? { calls: 0, blocked: 0 };
    switch (r.event) {
      case "intended":
        calls++;
        d.calls++;
        bump(actors, r.actor);
        bump(tools, r.tool);
        bump(byEffect, rv.registry.get(r.tool)?.effect ?? "no manifest");
        break;
      case "succeeded":
        out.succeeded++;
        if (rv.registry.get(r.tool)?.effect === "irreversible") irreversible++;
        break;
      case "failed":
        out.failed++;
        break;
      case "uncertain":
        out.uncertain++;
        break;
      case "blocked":
        if (!r.detail.startsWith("approval ") || r.detail.includes("was denied")) {
          blockedTotal++;
          d.blocked++;
          bump(blocked, reasonKey(r.detail));
        }
        if (/no manifest registered/.test(r.detail)) bump(unclassified, r.tool);
        break;
      case "would_block":
        wouldTotal++;
        bump(wouldBlock, reasonKey(r.detail));
        if (/no manifest registered/.test(r.detail)) bump(unclassified, r.tool);
        break;
      case "compensated":
        rb.compensated++;
        break;
      case "compensation_failed":
        rb.failed++;
        break;
      case "verified":
        rb.verified++;
        break;
      case "unverified":
        rb.unverified++;
        break;
      default:
        break;
    }
    const b = /budget `([^`]+)` at \d+%/.exec(r.detail);
    if (b) bump(budget, b[1] as string);
    days.set(day(r.ts_ms), d);
  }

  const appr = (approvals?.list() ?? []).filter((a) => a.requested_ms >= from_ms && a.requested_ms <= to_ms);
  const lat = appr.filter((a) => a.decided_ms !== null).map((a) => ((a.decided_ms as number) - a.requested_ms) / 1000).sort((a, b) => a - b);
  const attention = searchRuns(rv, { status: "needs_attention", limit: 100 }).runs.map((r) => ({ run_id: r.run_id, actor: r.actor, status: r.status }));
  const attempted = rb.compensated + rb.failed;
  return {
    from_ms,
    to_ms,
    runs: runsSeen.size,
    calls,
    actors: top(actors),
    tools: top(tools),
    by_effect: top(byEffect),
    outcomes: out,
    blocked: { total: blockedTotal, reasons: top(blocked) },
    would_block: { total: wouldTotal, reasons: top(wouldBlock) },
    unclassified_tools: top(unclassified),
    approvals: {
      requested: appr.length,
      approved: appr.filter((a) => a.status === "approved" || a.status === "consumed").length,
      denied: appr.filter((a) => a.status === "denied").length,
      expired: appr.filter((a) => a.status === "expired").length,
      escalated: appr.filter((a) => a.escalated).length,
      median_latency_s: lat.length ? (lat[Math.floor(lat.length / 2)] as number) : null,
    },
    rollback: { ...rb, success_rate: attempted ? Math.round((rb.compensated / attempted) * 1000) / 10 : null },
    irreversible_executed: irreversible,
    needs_attention: attention,
    budget_warnings: top(budget),
    days: [...days].sort((a, b) => a[0].localeCompare(b[0])).map(([d, v]) => ({ day: d, ...v })),
  };
}

const list = (t: TopEntry[]) => (t.length ? t.map((e) => `- ${e.key}: ${e.count}`).join("\n") : "- none");

export function renderPeriodMarkdown(r: PeriodReport, title = "Reversi report"): string {
  const iso = (ms: number) => new Date(ms).toISOString().slice(0, 16).replace("T", " ") + "Z";
  const lines = [
    `# ${title}`,
    "",
    `Period: ${iso(r.from_ms)} to ${iso(r.to_ms)}`,
    "",
    `**${r.calls}** tool calls in **${r.runs}** runs. ${r.outcomes.succeeded} succeeded, ${r.outcomes.failed} failed, ${r.outcomes.uncertain} with an unknown outcome.`,
    "",
    "## What the agents did",
    "Calls by tool:",
    list(r.tools),
    "",
    "By reversibility class:",
    list(r.by_effect),
    "",
    "By actor:",
    list(r.actors),
    "",
    `## Blocked: ${r.blocked.total}`,
    list(r.blocked.reasons),
    "",
    `## Would have been blocked (observe and advise modes): ${r.would_block.total}`,
    "These calls ran. Enforcing would have stopped them:",
    list(r.would_block.reasons),
    "",
    "## Tools called without a manifest",
    list(r.unclassified_tools),
    "",
    "## Approvals",
    `${r.approvals.requested} requested: ${r.approvals.approved} approved, ${r.approvals.denied} denied, ${r.approvals.expired} expired unanswered, ${r.approvals.escalated} escalated.${r.approvals.median_latency_s !== null ? ` Median time to a decision: ${Math.round(r.approvals.median_latency_s)}s.` : ""}`,
    "",
    "## Rollback",
    `${r.rollback.compensated} compensations succeeded, ${r.rollback.failed} failed${r.rollback.success_rate !== null ? ` (${r.rollback.success_rate}% success)` : ""}. ${r.rollback.verified} verified, ${r.rollback.unverified} could not be verified.`,
    `Irreversible actions executed: ${r.irreversible_executed}.`,
    "",
    "## Needs attention",
    r.needs_attention.length ? r.needs_attention.map((x) => `- ${x.run_id} (${x.actor})`).join("\n") : "- nothing",
    "",
    "## Budgets near their limit",
    list(r.budget_warnings),
    "",
    "## Calls per day",
    r.days.length ? r.days.map((d) => `- ${d.day}: ${d.calls} calls, ${d.blocked} blocked`).join("\n") : "- none",
    "",
  ];
  return lines.join("\n");
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

export function renderPeriodHtml(r: PeriodReport, title = "Reversi report"): string {
  const md = renderPeriodMarkdown(r, title);
  const body = md
    .split("\n")
    .map((l) => {
      if (l.startsWith("# ")) return `<h1>${esc(l.slice(2))}</h1>`;
      if (l.startsWith("## ")) return `<h2>${esc(l.slice(3))}</h2>`;
      if (l.startsWith("- ")) return `<li>${esc(l.slice(2))}</li>`;
      return l ? `<p>${esc(l).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")}</p>` : "";
    })
    .join("\n")
    .replace(/(<li>.*<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title><style>body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}h2{margin-top:1.6rem}</style></head><body>${body}</body></html>`;
}
