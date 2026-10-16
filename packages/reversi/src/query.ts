/** Searching runs and ledger records: filters, summaries and pagination. */
import type { Reversi } from "./engine.js";
import type { LedgerEvent, LedgerRecord } from "./ledger.js";
import type { RunState } from "./store.js";

export type RunStatus = "needs_attention" | "rolled_back" | "complete" | "blocked_only" | "empty";

export interface RunSummary {
  run_id: string;
  actor: string;
  tenant?: string;
  mode: string;
  started_ms: number;
  steps: number;
  tools: string[];
  status: RunStatus;
  unresolved: number[];
  failed_compensations: number;
}

export interface RunFilter {
  actor?: string;
  tenant?: string;
  tool?: string;
  status?: RunStatus;
  mode?: string;
  since_ms?: number;
  until_ms?: number;
  /** Matches the run id. */
  text?: string;
  limit?: number;
  /** Run id to continue after (the last one of the previous page). */
  after?: string;
}

const ATTENTION = new Set(["uncertain", "intended", "compensation_failed", "unrecoverable"]);

export function summarizeRun(state: RunState, unresolved: number[], blocked: number): RunSummary {
  const failed = state.steps.filter((s) => s.status === "compensation_failed").length;
  const standing = state.steps.filter((s) => !["failed", "compensated", "no_action"].includes(s.status));
  let status: RunStatus;
  if (state.steps.length === 0) status = blocked > 0 ? "blocked_only" : "empty";
  else if (unresolved.length || state.steps.some((s) => ATTENTION.has(s.status)) || standing.some((s) => s.effect === "irreversible")) status = "needs_attention";
  else if (state.steps.every((s) => ["compensated", "no_action", "failed"].includes(s.status)) && state.steps.some((s) => s.status === "compensated")) status = "rolled_back";
  else status = "complete";
  return {
    run_id: state.run_id,
    actor: state.actor,
    ...(state.tenant ? { tenant: state.tenant } : {}),
    mode: state.mode,
    started_ms: state.created_ms,
    steps: state.steps.length,
    tools: [...new Set(state.steps.map((s) => s.tool))],
    status,
    unresolved,
    failed_compensations: failed,
  };
}

/** Runs matching the filter, oldest first by id order, with the next page cursor. */
export function searchRuns(rv: Reversi, f: RunFilter = {}): { runs: RunSummary[]; next?: string } {
  const limit = Math.min(Math.max(f.limit ?? 100, 1), 1000);
  const blocked = new Map<string, number>();
  for (const r of rv.ledger.records()) if (r.event === "blocked" && r.step === null) blocked.set(r.run_id, (blocked.get(r.run_id) ?? 0) + 1);
  const ids = rv.runIds().sort();
  const out: RunSummary[] = [];
  for (const id of ids) {
    if (f.after && id <= f.after) continue;
    const run = rv.openRun(id);
    const st = run.state();
    if ((f.actor && st.actor !== f.actor) || (f.tenant && st.tenant !== f.tenant) || (f.mode && st.mode !== f.mode)) continue;
    if ((f.since_ms && st.created_ms < f.since_ms) || (f.until_ms && st.created_ms > f.until_ms)) continue;
    if (f.text && !id.includes(f.text)) continue;
    if (f.tool && !st.steps.some((s) => s.tool === f.tool) && !rv.ledger.forRun(id).some((r) => r.tool === f.tool)) continue;
    const sum = summarizeRun(st, run.unresolved(), blocked.get(id) ?? 0);
    if (f.status && sum.status !== f.status) continue;
    out.push(sum);
    if (out.length === limit) return { runs: out, next: id };
  }
  return { runs: out };
}

export interface RecordFilter {
  run_id?: string;
  actor?: string;
  tool?: string;
  event?: LedgerEvent | LedgerEvent[];
  since_ms?: number;
  until_ms?: number;
  /** Matches reason or detail. */
  text?: string;
  limit?: number;
  /** Return records with seq above this (cursor). */
  after_seq?: number;
}

export function searchRecords(rv: Reversi, f: RecordFilter = {}): { records: LedgerRecord[]; next_seq?: number } {
  const limit = Math.min(Math.max(f.limit ?? 200, 1), 5000);
  const events = f.event === undefined ? undefined : new Set(Array.isArray(f.event) ? f.event : [f.event]);
  const text = f.text?.toLowerCase();
  const out: LedgerRecord[] = [];
  for (const r of rv.ledger.records()) {
    if (f.after_seq !== undefined && r.seq <= f.after_seq) continue;
    if (f.run_id && r.run_id !== f.run_id) continue;
    if (f.actor && r.actor !== f.actor) continue;
    if (f.tool && r.tool !== f.tool) continue;
    if (events && !events.has(r.event)) continue;
    if (f.since_ms && r.ts_ms < f.since_ms) continue;
    if (f.until_ms && r.ts_ms > f.until_ms) continue;
    if (text && !`${r.reason} ${r.detail}`.toLowerCase().includes(text)) continue;
    out.push(r);
    if (out.length === limit) return { records: out, next_seq: r.seq };
  }
  return { records: out };
}
