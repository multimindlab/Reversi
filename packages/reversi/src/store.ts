/**
 * Run state: the steps of each run, their status, and the compensation handle needed to undo them.
 * The ledger is the evidence; run state is what the rollback planner works from.
 *
 * Call arguments are never stored. Only the compensation handle is kept: the few values (a charge
 * id, an issue number) the compensation needs, resolved from the manifest's `argument_map`.
 */
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import type { Effect } from "./manifest.js";

export type StepStatus =
  | "intended"
  | "succeeded"
  | "failed"
  | "uncertain"
  | "compensating"
  | "compensated"
  | "compensation_failed"
  | "no_action"
  | "unrecoverable";

export interface StepState {
  step: number;
  tool: string;
  reason: string;
  /** Null when the tool had no manifest (observe mode only). */
  effect: Effect | null;
  status: StepStatus;
  depends_on: number[];
  /** Snapshot of the manifest's compensation at call time, so later manifest edits cannot change history. */
  compensation_tool: string | null;
  compensation_requires_approval: boolean;
  argument_map: Record<string, string>;
  /** Values resolved from `$args.*` when the call began. */
  partial_handle: Record<string, unknown>;
  /** Complete compensation arguments, set when the call succeeds. */
  handle: Record<string, unknown> | null;
  /** Compensation arguments that could not be resolved. Non-empty means automatic undo is impossible. */
  handle_missing: string[];
  error: string | null;
  ts_ms: number;
  /** Manifest version at call time. */
  manifest_version?: number;
  /** `inverse` restores exact state; `compensation` may leave `residue`. Snapshotted with the compensation. */
  compensation_kind?: "inverse" | "compensation";
  residue?: string[];
  /** Read-back to run after the compensation: arguments resolved from this call's args and result. */
  verification?: { tool: string; refs: Record<string, string>; args: Record<string, unknown>; expect: Record<string, unknown>; retries: number; backoff_ms: number; missing: string[] };
  compensation_timeout_ms?: number;
  /** Rendered idempotency key, for duplicate detection. */
  idem_key?: string;
  /** Hash of the result: a reference to it that is safe to keep. */
  result_hash?: string;
  /** Risk score 0..100 computed when the call began, if risk scoring is configured. */
  risk_score?: number;
}

/** `advise` behaves like `observe` (nothing is blocked) and tells the caller what would have been. */
export type Mode = "enforce" | "observe" | "advise";

export interface RunState {
  run_id: string;
  actor: string;
  mode: Mode;
  scope: { permissions: string[]; seal: string; parent_seal: string | null };
  created_ms: number;
  /** Customer or team the run belongs to, for tenant-scoped policy and queries. */
  tenant?: string;
  steps: StepState[];
}

export interface RunStore {
  get(run_id: string): RunState | undefined;
  put(state: RunState): void;
  list(): string[];
  /** Remove a run's state (retention). The ledger records about it stay: the ledger is append-only. */
  delete(run_id: string): boolean;
}

export const RUN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export class MemoryRunStore implements RunStore {
  private readonly runs = new Map<string, RunState>();
  get(run_id: string): RunState | undefined {
    const s = this.runs.get(run_id);
    return s ? structuredClone(s) : undefined;
  }
  put(state: RunState): void {
    this.runs.set(state.run_id, structuredClone(state));
  }
  list(): string[] {
    return [...this.runs.keys()];
  }
  delete(run_id: string): boolean {
    return this.runs.delete(run_id);
  }
}

/** One JSON file per run. Writes go to a temp file, are fsynced, then renamed into place. */
export class FileRunStore implements RunStore {
  constructor(private readonly dir: string) {
    mkdirSync(dir, { recursive: true });
  }

  private file(run_id: string): string {
    // The pattern forbids path separators, so a run id can never escape the directory.
    if (!RUN_ID_PATTERN.test(run_id)) throw new Error(`invalid run id: ${JSON.stringify(run_id)}`);
    return join(this.dir, `${run_id}.json`);
  }

  get(run_id: string): RunState | undefined {
    const f = this.file(run_id);
    if (!existsSync(f)) return undefined;
    return JSON.parse(readFileSync(f, "utf8")) as RunState;
  }

  put(state: RunState): void {
    const f = this.file(state.run_id);
    const tmp = `${f}.${process.pid}.tmp`;
    const fd = openSync(tmp, "w");
    try {
      writeSync(fd, JSON.stringify(state, null, 2));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, f);
  }

  delete(run_id: string): boolean {
    const f = this.file(run_id);
    if (!existsSync(f)) return false;
    unlinkSync(f);
    return true;
  }

  list(): string[] {
    return readdirSync(this.dir)
      .filter((n) => n.endsWith(".json"))
      .map((n) => n.slice(0, -".json".length))
      .sort();
  }
}
