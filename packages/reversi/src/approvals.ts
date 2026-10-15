/**
 * Approvals: a queue of pending requests and the operator decisions on them. The engine asks the
 * approver for a decision; with no standing approval the request is queued and the call is blocked
 * with a message naming the approval id. After an operator approves it, the agent retries and the
 * approval is consumed exactly once. A call approval is bound to the hash of the arguments it was
 * requested for, so an approved call cannot be swapped for a different one.
 */
import { randomUUID } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import type { ApprovalDecision, ApprovalRequest, Approver } from "./engine.js";
import { redactSecrets } from "./redact.js";

export type ApprovalStatus = "pending" | "approved" | "denied" | "consumed" | "expired";

export interface ApprovalRecord {
  id: string;
  run_id: string;
  step: number | null;
  kind: "call" | "compensation";
  tool: string;
  reason: string;
  /** Why approval was needed: manifest, policy rule, content check. */
  triggers: string[];
  /** Names of the arguments, never their values. */
  arg_keys: string[];
  /** Null for a blanket grant that matches any arguments. */
  args_hash: string | null;
  status: ApprovalStatus;
  requested_ms: number;
  expires_ms: number;
  decided_by: string | null;
  decided_ms: number | null;
  decision_note: string | null;
}

export interface ApprovalStore {
  get(id: string): ApprovalRecord | undefined;
  put(rec: ApprovalRecord): void;
  list(): ApprovalRecord[];
  /**
   * Atomically change a record that is still in status `from`, merging `patch` into it. Returns false if it was
   * not in that status (someone else got there first). This is what makes "single use" and "decided once" hold
   * when several processes share a store.
   */
  transition(id: string, from: ApprovalStatus, patch: Partial<ApprovalRecord>): boolean;
}

export class MemoryApprovalStore implements ApprovalStore {
  private readonly items = new Map<string, ApprovalRecord>();
  get(id: string) {
    const r = this.items.get(id);
    return r ? structuredClone(r) : undefined;
  }
  put(rec: ApprovalRecord) {
    this.items.set(rec.id, structuredClone(rec));
  }
  list() {
    return [...this.items.values()].map((r) => structuredClone(r));
  }
  transition(id: string, from: ApprovalStatus, patch: Partial<ApprovalRecord>) {
    const r = this.items.get(id);
    if (!r || r.status !== from) return false;
    this.items.set(id, { ...r, ...patch });
    return true;
  }
}

/** One JSON file, rewritten atomically on every change. Fine for one operator at a time. */
export class FileApprovalStore implements ApprovalStore {
  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
  }
  private read(): Record<string, ApprovalRecord> {
    return existsSync(this.path) ? (JSON.parse(readFileSync(this.path, "utf8")) as Record<string, ApprovalRecord>) : {};
  }
  get(id: string) {
    return this.read()[id];
  }
  put(rec: ApprovalRecord) {
    const all = this.read();
    all[rec.id] = rec;
    const tmp = `${this.path}.${process.pid}.tmp`;
    const fd = openSync(tmp, "w");
    try {
      writeSync(fd, JSON.stringify(all, null, 2));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.path);
  }
  list() {
    return Object.values(this.read());
  }
  /** Read, compare and rename-over: atomic enough for one host; use SQLite or PostgreSQL to share across hosts. */
  transition(id: string, from: ApprovalStatus, patch: Partial<ApprovalRecord>) {
    const r = this.read()[id];
    if (!r || r.status !== from) return false;
    this.put({ ...r, ...patch });
    return true;
  }
}

export class ApprovalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalError";
  }
}

export interface ApprovalsOptions {
  /** How long a pending or approved request stays valid. Default 1 hour. */
  ttl_ms?: number;
  now?: () => number;
  /** Called when a new request is queued (to notify an approver). Must not throw; failures are the callback's to handle. */
  on_request?: (rec: ApprovalRecord) => void;
  /** Called after an approver approves or denies, so the decision can be written to the ledger. */
  on_decision?: (rec: ApprovalRecord, decision: "approved" | "denied") => void;
}

export class Approvals {
  private readonly ttl: number;
  private readonly now: () => number;
  private readonly onRequest: ((rec: ApprovalRecord) => void) | undefined;
  private readonly onDecision: ((rec: ApprovalRecord, d: "approved" | "denied") => void) | undefined;
  constructor(
    readonly store: ApprovalStore = new MemoryApprovalStore(),
    opts: ApprovalsOptions = {},
  ) {
    this.ttl = opts.ttl_ms ?? 3_600_000;
    this.now = opts.now ?? Date.now;
    this.onRequest = opts.on_request;
    this.onDecision = opts.on_decision;
  }

  private sweep(r: ApprovalRecord): ApprovalRecord {
    if ((r.status === "pending" || r.status === "approved") && this.now() >= r.expires_ms) {
      r.status = "expired";
      this.store.put(r);
    }
    return r;
  }

  list(filter: { status?: ApprovalStatus; run_id?: string } = {}): ApprovalRecord[] {
    return this.store
      .list()
      .map((r) => this.sweep(r))
      .filter((r) => (!filter.status || r.status === filter.status) && (!filter.run_id || r.run_id === filter.run_id))
      .sort((a, b) => a.requested_ms - b.requested_ms);
  }

  get(id: string): ApprovalRecord | undefined {
    const r = this.store.get(id);
    return r ? this.sweep(r) : undefined;
  }

  /** The engine's approver. Consumes a matching approval, or queues a request and says so. */
  asApprover(): Approver {
    return (req) => this.decide(req);
  }

  private decide(req: ApprovalRequest): ApprovalDecision {
    const mine = this.list({ run_id: req.run_id }).filter(
      (r) => r.kind === req.kind && r.tool === req.tool && (r.args_hash === null || r.args_hash === (req.args_hash ?? null)),
    );
    for (const standing of mine.filter((r) => r.status === "approved")) {
      // Claim it atomically: if another process consumed it first, try the next one.
      if (this.store.transition(standing.id, "approved", { status: "consumed" })) return true;
    }
    const denied = mine.find((r) => r.status === "denied" && r.args_hash === (req.args_hash ?? null) && r.step === req.step);
    if (denied) return { approved: false, message: `approval ${denied.id} was denied${denied.decision_note ? `: ${denied.decision_note}` : ""}` };
    const pending = mine.find((r) => r.status === "pending");
    if (pending) return { approved: false, message: `approval required: request ${pending.id} is pending an operator decision; retry after it is approved` };
    const rec: ApprovalRecord = {
      id: `apr_${randomUUID()}`,
      run_id: req.run_id,
      step: req.step,
      kind: req.kind,
      tool: req.tool,
      reason: redactSecrets(req.reason),
      triggers: req.triggers ?? [],
      arg_keys: req.arg_keys ?? [],
      args_hash: req.args_hash ?? null,
      status: "pending",
      requested_ms: this.now(),
      expires_ms: this.now() + this.ttl,
      decided_by: null,
      decided_ms: null,
      decision_note: null,
    };
    this.store.put(rec);
    try {
      this.onRequest?.(rec);
    } catch {
      /* a broken notifier must never change an approval decision */
    }
    return { approved: false, message: `approval required: request ${rec.id} is pending an operator decision; retry after it is approved` };
  }

  private decideOn(id: string, status: "approved" | "denied", by: string, note?: string): ApprovalRecord {
    const r = this.get(id);
    if (!r) throw new ApprovalError(`approval \`${id}\` not found`);
    if (r.status !== "pending") throw new ApprovalError(`approval \`${id}\` is ${r.status}, not pending`);
    const patch = { status, decided_by: by, decided_ms: this.now(), decision_note: note ? redactSecrets(note) : null };
    if (!this.store.transition(id, "pending", patch)) {
      throw new ApprovalError(`approval \`${id}\` was decided by someone else first`);
    }
    const done = { ...r, ...patch };
    try {
      this.onDecision?.(done, status);
    } catch {
      /* the decision stands even if recording it elsewhere failed; the approval store is the source of truth */
    }
    return done;
  }

  approve(id: string, by: string, note?: string): ApprovalRecord {
    return this.decideOn(id, "approved", by, note);
  }
  deny(id: string, by: string, note?: string): ApprovalRecord {
    return this.decideOn(id, "denied", by, note);
  }

  /** Operator pre-approval for a tool in a run, valid for `count` uses and any arguments. */
  add(run_id: string, kind: "call" | "compensation", tool: string, count = 1, by = "operator"): void {
    for (let i = 0; i < count; i++) {
      this.store.put({
        id: `apr_${randomUUID()}`,
        run_id,
        step: null,
        kind,
        tool,
        reason: "operator pre-approval",
        triggers: ["operator grant"],
        arg_keys: [],
        args_hash: null,
        status: "approved",
        requested_ms: this.now(),
        expires_ms: this.now() + this.ttl,
        decided_by: by,
        decided_ms: this.now(),
        decision_note: null,
      });
    }
  }
}
