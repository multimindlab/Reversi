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
import type { Delegations } from "./delegations.js";
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
  /** The actor of the run that asked. A requester may not approve their own request. */
  requested_by?: string;
  /** Reversi roles or group names that may approve. Empty: any approver. */
  required_roles?: string[];
  /** How many distinct approvers are needed (default 1). */
  quorum?: number;
  /** Counts decisions so far; lets stores detect two approvers racing. */
  decision_count?: number;
  decisions?: Array<{ by: string; on_behalf_of?: string; basis: string; decision: "approve" | "deny"; note: string | null; ms: number }>;
  on_timeout?: "deny" | "escalate";
  escalate_to?: string[];
  escalated?: boolean;
  /** The lifetime applied to this request, used again when it escalates. */
  ttl_ms?: number;
  break_glass?: { by: string; reason: string; evidence: string; ms: number };
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
  transition(id: string, from: ApprovalStatus, patch: Partial<ApprovalRecord>, expectCount?: number): boolean;
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
  transition(id: string, from: ApprovalStatus, patch: Partial<ApprovalRecord>, expectCount?: number) {
    const r = this.items.get(id);
    if (!r || r.status !== from || (expectCount !== undefined && (r.decision_count ?? 0) !== expectCount)) return false;
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
  transition(id: string, from: ApprovalStatus, patch: Partial<ApprovalRecord>, expectCount?: number) {
    const r = this.read()[id];
    if (!r || r.status !== from || (expectCount !== undefined && (r.decision_count ?? 0) !== expectCount)) return false;
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

/** Who is deciding: their Reversi roles and group names (from the key file or the identity provider). */
export interface ApproverIdentity {
  roles?: string[];
  groups?: string[];
}

export interface ApprovalsOptions {
  /** How long a pending or approved request stays valid. Default 1 hour. */
  ttl_ms?: number;
  now?: () => number;
  /** Called when a new request is queued (to notify an approver). Must not throw; failures are the callback's to handle. */
  on_request?: (rec: ApprovalRecord) => void;
  /** Called after the final decision (approve, deny, break-glass), so it can be written to the ledger. */
  on_decision?: (rec: ApprovalRecord, decision: "approved" | "denied") => void;
  /** Called when one approver of a quorum has approved but more are needed. */
  on_progress?: (rec: ApprovalRecord) => void;
  /** Called when an unanswered request escalates to other approvers. */
  on_escalate?: (rec: ApprovalRecord) => void;
  /** Used to let delegates approve on behalf of someone. */
  delegations?: Delegations;
}

const DECISION_LIMIT = 10;

export class Approvals {
  private readonly ttl: number;
  private readonly now: () => number;
  private readonly o: ApprovalsOptions;
  constructor(
    readonly store: ApprovalStore = new MemoryApprovalStore(),
    opts: ApprovalsOptions = {},
  ) {
    this.ttl = opts.ttl_ms ?? 3_600_000;
    this.now = opts.now ?? Date.now;
    this.o = opts;
  }

  private safely(fn: (() => void) | undefined): void {
    try {
      fn?.();
    } catch {
      /* notifications and ledger mirroring must never change an approval decision */
    }
  }

  /** Expire or escalate a request whose time is up. */
  private sweep(r: ApprovalRecord): ApprovalRecord {
    if ((r.status === "pending" || r.status === "approved") && this.now() >= r.expires_ms) {
      if (r.status === "pending" && r.on_timeout === "escalate" && !r.escalated) {
        const patch: Partial<ApprovalRecord> = {
          escalated: true,
          required_roles: r.escalate_to && r.escalate_to.length ? r.escalate_to : r.required_roles,
          expires_ms: this.now() + (r.ttl_ms ?? this.ttl),
          decision_count: (r.decision_count ?? 0) + 1,
        };
        if (this.store.transition(r.id, "pending", patch, r.decision_count ?? 0)) {
          const next = { ...r, ...patch };
          this.safely(() => this.o.on_escalate?.(next));
          return next;
        }
        return this.store.get(r.id) ?? r;
      }
      if (this.store.transition(r.id, r.status, { status: "expired" })) return { ...r, status: "expired" };
      return this.store.get(r.id) ?? r;
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

  private pendingMessage(rec: ApprovalRecord): string {
    const need = (rec.quorum ?? 1) > 1 ? ` (needs ${rec.quorum} approvers${rec.required_roles?.length ? ` from ${rec.required_roles.join(" or ")}` : ""})` : rec.required_roles?.length ? ` (needs an approver from ${rec.required_roles.join(" or ")})` : "";
    return `approval required: request ${rec.id} is pending an operator decision${need}; retry after it is approved`;
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
    const expired = mine.find((r) => r.status === "expired" && r.args_hash === (req.args_hash ?? null) && r.step === req.step && this.now() - r.expires_ms < 60_000);
    const pending = mine.find((r) => r.status === "pending");
    if (pending) return { approved: false, message: this.pendingMessage(pending) };
    if (expired && expired.on_timeout !== "escalate") {
      // Nobody answered in time and the rule says deny: say so once, then allow a fresh request.
      return { approved: false, message: `approval ${expired.id} expired unanswered and was denied; the call must be requested again` };
    }
    const ttl = req.timeout_ms ?? this.ttl;
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
      expires_ms: this.now() + ttl,
      decided_by: null,
      decided_ms: null,
      decision_note: null,
      requested_by: req.requested_by,
      required_roles: req.required_roles ?? [],
      quorum: req.quorum ?? 1,
      decision_count: 0,
      decisions: [],
      on_timeout: req.on_timeout ?? "deny",
      escalate_to: req.escalate_to ?? [],
      escalated: false,
      ttl_ms: ttl,
    };
    this.store.put(rec);
    this.safely(() => this.o.on_request?.(rec));
    return { approved: false, message: this.pendingMessage(rec) };
  }

  /**
   * Work out whether `by` may decide `r`, and on whose authority. Returns the basis ("role:operator", "group:finance",
   * "delegated by alice") or throws. With no `who` the caller is trusted (the CLI on the host that owns the data).
   */
  private authorize(r: ApprovalRecord, by: string, who: ApproverIdentity | undefined): { basis: string; on_behalf_of?: string } {
    if (!who) return { basis: "trusted caller" };
    if (r.requested_by && r.requested_by === by) throw new ApprovalError("you cannot decide a request made by your own run");
    const required = r.required_roles ?? [];
    const mine = new Set([...(who.roles ?? []), ...(who.groups ?? [])]);
    if (required.length === 0) return { basis: "approver" };
    const direct = required.find((x) => mine.has(x));
    if (direct) return { basis: `${(who.roles ?? []).includes(direct) ? "role" : "group"}:${direct}` };
    for (const d of this.o.delegations?.activeFor(by) ?? []) {
      const delegated = d.groups.length ? d.groups : required;
      const hit = required.find((x) => delegated.includes(x));
      if (hit) return { basis: `delegated by ${d.from} (${hit})`, on_behalf_of: d.from };
    }
    throw new ApprovalError(`this request needs an approver from: ${required.join(", ")}`);
  }

  private decideOn(id: string, decision: "approve" | "deny", by: string, note?: string, who?: ApproverIdentity): ApprovalRecord {
    const r = this.get(id);
    if (!r) throw new ApprovalError(`approval \`${id}\` not found`);
    if (r.status !== "pending") throw new ApprovalError(`approval \`${id}\` is ${r.status}, not pending`);
    const auth = this.authorize(r, by, who);
    const identity = auth.on_behalf_of ?? by;
    const prior = r.decisions ?? [];
    if (prior.some((d) => (d.on_behalf_of ?? d.by) === identity || d.by === by)) throw new ApprovalError("you have already decided this request");
    if (auth.on_behalf_of && prior.some((d) => d.by === auth.on_behalf_of)) throw new ApprovalError(`${auth.on_behalf_of} has already decided this request, so their delegate cannot add a second vote`);
    const entry = { by, ...(auth.on_behalf_of ? { on_behalf_of: auth.on_behalf_of } : {}), basis: auth.basis, decision, note: note ? redactSecrets(note) : null, ms: this.now() };
    const decisions = [...prior, entry].slice(-DECISION_LIMIT);
    const count = r.decision_count ?? 0;
    const quorum = r.quorum ?? 1;
    const approvedVotes = decisions.filter((d) => d.decision === "approve").length;
    let patch: Partial<ApprovalRecord>;
    if (decision === "deny") {
      patch = { status: "denied", decided_by: by, decided_ms: this.now(), decision_note: entry.note, decisions, decision_count: count + 1 };
    } else if (approvedVotes >= quorum) {
      patch = {
        status: "approved",
        decided_by: decisions.filter((d) => d.decision === "approve").map((d) => d.by).join(", "),
        decided_ms: this.now(),
        decision_note: entry.note,
        decisions,
        decision_count: count + 1,
      };
    } else {
      patch = { decisions, decision_count: count + 1 }; // one more vote, still pending
    }
    if (!this.store.transition(id, "pending", patch, count)) throw new ApprovalError(`approval \`${id}\` changed while you were deciding: reload it and try again`);
    const done = { ...r, ...patch };
    if (done.status === "approved" || done.status === "denied") this.safely(() => this.o.on_decision?.(done, done.status === "approved" ? "approved" : "denied"));
    else this.safely(() => this.o.on_progress?.(done));
    return done;
  }

  approve(id: string, by: string, note?: string, who?: ApproverIdentity): ApprovalRecord {
    return this.decideOn(id, "approve", by, note, who);
  }
  deny(id: string, by: string, note?: string, who?: ApproverIdentity): ApprovalRecord {
    return this.decideOn(id, "deny", by, note, who);
  }

  /**
   * Emergency override: an admin approves without the usual approvers or quorum. A reason and a pointer to the evidence
   * (ticket, incident) are mandatory, and the ledger records it as a break-glass approval.
   */
  breakGlass(id: string, by: string, info: { reason: string; evidence: string }, who?: ApproverIdentity): ApprovalRecord {
    if (who && !(who.roles ?? []).includes("admin")) throw new ApprovalError("break-glass needs the admin role");
    if (info.reason.trim().length < 10) throw new ApprovalError("break-glass needs a reason of at least 10 characters");
    if (!info.evidence.trim()) throw new ApprovalError("break-glass needs a reference to the evidence (ticket or incident)");
    const r = this.get(id);
    if (!r) throw new ApprovalError(`approval \`${id}\` not found`);
    if (r.status !== "pending") throw new ApprovalError(`approval \`${id}\` is ${r.status}, not pending`);
    const count = r.decision_count ?? 0;
    const bg = { by, reason: redactSecrets(info.reason), evidence: redactSecrets(info.evidence), ms: this.now() };
    const patch: Partial<ApprovalRecord> = {
      status: "approved",
      decided_by: by,
      decided_ms: bg.ms,
      decision_note: `BREAK-GLASS: ${bg.reason}`,
      break_glass: bg,
      decision_count: count + 1,
      decisions: [...(r.decisions ?? []), { by, basis: "break-glass", decision: "approve" as const, note: bg.reason, ms: bg.ms }].slice(-DECISION_LIMIT),
    };
    if (!this.store.transition(id, "pending", patch, count)) throw new ApprovalError(`approval \`${id}\` changed while you were deciding: reload it and try again`);
    const done = { ...r, ...patch };
    this.safely(() => this.o.on_decision?.(done, "approved"));
    return done;
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
