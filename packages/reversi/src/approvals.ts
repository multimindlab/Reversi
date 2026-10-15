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
}

export class Approvals {
  private readonly ttl: number;
  private readonly now: () => number;
  constructor(
    readonly store: ApprovalStore = new MemoryApprovalStore(),
    opts: ApprovalsOptions = {},
  ) {
    this.ttl = opts.ttl_ms ?? 3_600_000;
    this.now = opts.now ?? Date.now;
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
    const standing = mine.find((r) => r.status === "approved");
    if (standing) {
      standing.status = "consumed";
      this.store.put(standing);
      return true;
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
      reason: req.reason,
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
    return { approved: false, message: `approval required: request ${rec.id} is pending an operator decision; retry after it is approved` };
  }

  private decideOn(id: string, status: "approved" | "denied", by: string, note?: string): ApprovalRecord {
    const r = this.get(id);
    if (!r) throw new ApprovalError(`approval \`${id}\` not found`);
    if (r.status !== "pending") throw new ApprovalError(`approval \`${id}\` is ${r.status}, not pending`);
    r.status = status;
    r.decided_by = by;
    r.decided_ms = this.now();
    r.decision_note = note ?? null;
    this.store.put(r);
    return r;
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
