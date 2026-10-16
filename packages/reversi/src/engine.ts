/**
 * The run engine.
 *
 * A tool call goes through: manifest lookup, scope check, dependency check, approval, then a
 * write-ahead `intended` ledger record BEFORE the tool executes, then an outcome record after.
 * If journaling fails, the call does not run (fail closed). If the process dies mid-call, the
 * dangling `intended` record shows exactly which effects need reconciling.
 *
 * Rollback undoes steps with their declared compensations. Reverse chronological order is already
 * a valid undo order for dependencies, since a step can only depend on earlier steps. What matters
 * is what happens when an undo gets stuck: a step is never undone while a step that depends on it
 * is still standing. Stuck steps are reported, everything independent is still undone.
 */
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { canonicalize, hashPayload, sha256Hex } from "./canonical.js";
import type { ContentChecker } from "./content.js";
import { Ledger, type LedgerEvent } from "./ledger.js";
import { redactSecrets } from "./redact.js";
import { Registry, resolveRef } from "./manifest.js";
import type { Verification } from "./manifest.js";
import type { CaptureStore } from "./capture.js";
import type { KvStore } from "./kv.js";
import type { ApprovalRequirement, Policy, PolicyInput } from "./policy.js";
import { globAny } from "./glob.js";
import { SealedScope } from "./scope.js";
import {
  MemoryRunStore,
  RUN_ID_PATTERN,
  type Mode,
  type RunState,
  type RunStore,
  type StepState,
  type StepStatus,
} from "./store.js";

export class ReversiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReversiError";
  }
}

/** Thrown by {@link Run.wrap} when a call is blocked. The tool was not executed. */
export class BlockedError extends Error {
  constructor(
    readonly tool: string,
    readonly reasons: string[],
  ) {
    super(`call to \`${tool}\` blocked: ${reasons.join("; ")}`);
    this.name = "BlockedError";
  }
}

/** Throw from a tool executor when it is unknown whether the effect happened (timeout, dropped connection). */
export class EffectUncertainError extends Error {
  constructor(message = "outcome of the call is unknown") {
    super(message);
    this.name = "EffectUncertainError";
  }
}

export interface ApprovalRequest {
  run_id: string;
  step: number | null;
  tool: string;
  reason: string;
  kind: "call" | "compensation";
  /** Hash of the call's arguments, so an approval can be bound to them. */
  args_hash?: string;
  /** Why approval is needed: manifest, policy rule, content check. */
  triggers?: string[];
  /** Names of the arguments (never values). */
  arg_keys?: string[];
  /** The actor of the run, so the requester cannot approve their own request. */
  requested_by?: string;
  /** Roles or groups that may approve; empty means any approver. */
  required_roles?: string[];
  quorum?: number;
  timeout_ms?: number;
  on_timeout?: "deny" | "escalate";
  escalate_to?: string[];
}
/** `true`/`false`, or a decision with a message that is shown to the caller when not approved. */
export type ApprovalDecision = boolean | { approved: boolean; message?: string };
export type Approver = (req: ApprovalRequest) => ApprovalDecision | Promise<ApprovalDecision>;

export interface ReversiOptions {
  registry: Registry;
  ledger: Ledger;
  runs?: RunStore;
  approver?: Approver;
  now?: () => number;
  /** Extra restrictions on top of manifests and scopes. */
  policy?: Policy;
  content?: ContentChecker;
  /** dev, staging, prod... matched by policy rules. Default `default`. */
  environment?: string;
  /** If this file exists, every new call is blocked (rollback still works). */
  kill_switch_file?: string;
  /** Opt-in capture of redacted arguments and results, for replay, simulation and impact previews. */
  capture?: CaptureStore;
  /** Shared settings store: halts are kept here so every process using the same data store sees them. */
  kv?: KvStore;
}

/** What a halt applies to. An empty scope halts everything. */
export interface HaltScope {
  tool?: string;
  actor?: string;
  tenant?: string;
  environment?: string;
}
export interface Halt {
  id: string;
  reason: string;
  scope: HaltScope;
  by: string;
  ts_ms: number;
}

export interface StartRunOptions {
  run_id?: string;
  actor: string;
  scope: SealedScope;
  /** `enforce` blocks violations. `observe` journals them as `would_block` and lets the call run. */
  mode?: Mode;
  reason?: string;
  /** Customer or team the run belongs to. */
  tenant?: string;
}

export interface BeginInput {
  tool: string;
  args?: unknown;
  reason: string;
  /** Steps this call depends on beyond the manifest's `requires`. */
  depends_on?: number[];
  /** Violations found by the caller before asking (for example schema validation in the gateway). Treated like policy denials. */
  extra_violations?: string[];
  /** Notes for the ledger record of the intent. */
  extra_notes?: string[];
}

export type BeginResult =
  | { decision: "allow"; step: number }
  | { decision: "would_block"; step: number; reasons: string[] }
  | { decision: "block"; reasons: string[] };

export type Outcome =
  | {
      status: "succeeded";
      result?: unknown;
      /** Appended to the ledger detail. */
      notes?: string[];
      /** The result does not match what the tool promised: its `$result` references cannot be trusted for compensation. */
      invalid_result?: boolean;
    }
  | { status: "failed"; error?: string }
  | { status: "uncertain"; error?: string };

export type CallResult<T> =
  | { status: "executed"; step: number; result: T; observed_violations?: string[] }
  | { status: "blocked"; reasons: string[] };

export type PlanKind = "compensate" | "skip" | "unrecoverable" | "unresolved" | "unmanifested" | "defer";

export interface PlanAction {
  step: number;
  tool: string;
  kind: PlanKind;
  /** What the undo will not take back. */
  residue?: string[];
  compensation_kind?: "inverse" | "compensation";
  /** The undo is read back before it counts as complete. */
  verified?: boolean;
  compensation_tool?: string;
  args?: Record<string, unknown>;
  idempotency_key?: string;
  needs_approval?: boolean;
  blocked_by?: number[];
  note?: string;
}

export interface RollbackPlan {
  run_id: string;
  actions: PlanAction[];
  /** True if every standing step can be undone or needs no undo, assuming each compensation succeeds. */
  fully_reversible: boolean;
}

export interface CompensationCall {
  run_id: string;
  step: number;
  /** The compensation tool to run. */
  tool: string;
  original_tool: string;
  args: Record<string, unknown>;
  /** Stable across retries of the same step: pass it to the downstream API so retries deduplicate. */
  idempotency_key: string;
}
export type Compensator = (call: CompensationCall) => void | Promise<void>;

export type CompensationStart =
  | { decision: "go"; step: number; call: CompensationCall }
  | { decision: "defer"; step: number; blocked_by: number[] }
  | { decision: "awaiting_approval"; step: number }
  | { decision: "not_actionable"; step: number; kind: PlanKind; note?: string }
  | { decision: "nothing_to_do"; step: number; status: StepStatus };

export type CompensationOutcome = { status: "compensated" } | { status: "failed"; error?: string };

export interface RollbackReport {
  run_id: string;
  compensated: number[];
  skipped: number[];
  failed: Array<{ step: number; error: string }>;
  unrecoverable: number[];
  /** Compensations that ran but whose declared read-back could not be performed (no verifier) or was not possible. */
  unverified: number[];
  unresolved: number[];
  unmanifested: number[];
  deferred: Array<{ step: number; blocked_by: number[] }>;
  awaiting_approval: number[];
  /** True only if nothing was left undone or unexplained. */
  complete: boolean;
}

export function idempotencyKey(run_id: string, step: number, tool: string): string {
  return sha256Hex(canonicalize([run_id, step, tool]));
}

/** Several approval requirements on one call: any listed role may approve, the biggest quorum wins, the shortest timeout wins. */
export function mergeRequirements(reqs: ApprovalRequirement[]): Pick<ApprovalRequest, "required_roles" | "quorum" | "timeout_ms" | "on_timeout" | "escalate_to"> {
  if (reqs.length === 0) return {};
  const timeouts = reqs.map((r) => r.timeout_ms).filter((t): t is number => t !== undefined);
  return {
    required_roles: [...new Set(reqs.flatMap((r) => r.roles))],
    quorum: Math.max(...reqs.map((r) => r.quorum)),
    ...(timeouts.length ? { timeout_ms: Math.min(...timeouts) } : {}),
    on_timeout: reqs.some((r) => r.on_timeout === "deny" || r.on_timeout === undefined) ? "deny" : "escalate",
    escalate_to: [...new Set(reqs.flatMap((r) => r.escalate_to ?? []))],
  };
}

/** `{{args.a.b}}` placeholders rendered from the call arguments; undefined if any is missing or not a scalar. */
export function renderIdempotencyKey(template: string, args: unknown): string | undefined {
  let missing = false;
  const out = template.replace(/\{\{\s*(args(?:\.[A-Za-z0-9_-]+)+)\s*\}\}/g, (_m, path: string) => {
    const v = resolveRef(`$${path}`, "args", args);
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
    missing = true;
    return "";
  });
  return missing ? undefined : out;
}

const LIVE_STATUSES = new Set<StepStatus>(["intended", "succeeded", "uncertain", "compensating", "compensation_failed"]);

/** Compare a verification result with its `expect` (dotted path -> value). Returns a description of the first mismatch, or null. */
export function expectMismatch(actual: unknown, expect: Record<string, unknown>): string | null {
  for (const [path, want] of Object.entries(expect)) {
    let cur: unknown = actual;
    for (const seg of path.split(".")) {
      if (Array.isArray(cur) && /^\d+$/.test(seg)) cur = cur[Number(seg)];
      else if (typeof cur === "object" && cur !== null && Object.prototype.hasOwnProperty.call(cur, seg)) cur = (cur as Record<string, unknown>)[seg];
      else {
        cur = undefined;
        break;
      }
    }
    if (canonicalize(cur === undefined ? null : cur) !== canonicalize(want === undefined ? null : want) || (cur === undefined && want !== undefined)) {
      return `\`${path}\` is ${cur === undefined ? "missing" : JSON.stringify(cur)}, expected ${JSON.stringify(want)}`;
    }
  }
  return null;
}

function isArgObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const MANIFEST_TRIGGER = "manifest requires approval";
const ERROR_LIMIT = 300;
function messageOf(e: unknown): string {
  const m = redactSecrets(e instanceof Error ? e.message : String(e)); // error text is stored in run state and shown in the console
  return m.length > ERROR_LIMIT ? m.slice(0, ERROR_LIMIT) + "…" : m;
}

const SETTLED = new Set<StepStatus>(["failed", "compensated", "no_action"]);

function kindOf(s: StepState): Exclude<PlanKind, "defer"> {
  if (s.status === "intended" || s.status === "uncertain") return "unresolved";
  if (s.effect === null) return "unmanifested";
  if (s.effect === "read_only" || s.effect === "idempotent") return "skip";
  if (s.effect === "irreversible" || s.status === "unrecoverable" || s.handle_missing.length > 0) {
    return "unrecoverable";
  }
  return "compensate";
}

function isGoodDependent(d: StepState): boolean {
  return (
    SETTLED.has(d.status) ||
    (d.status === "succeeded" && (d.effect === "read_only" || d.effect === "idempotent"))
  );
}

function blockersOf(state: RunState, s: StepState): number[] {
  return state.steps.filter((d) => d.depends_on.includes(s.step) && !isGoodDependent(d)).map((d) => d.step);
}

function classify(state: RunState, s: StepState): PlanAction | null {
  if (SETTLED.has(s.status)) return null;
  const kind = kindOf(s);
  const base = { step: s.step, tool: s.tool };
  switch (kind) {
    case "compensate": {
      const blocked_by = blockersOf(state, s);
      if (blocked_by.length) return { ...base, kind: "defer", blocked_by };
      return {
        ...base,
        kind,
        compensation_tool: s.compensation_tool ?? undefined,
        args: s.handle ?? {},
        idempotency_key: idempotencyKey(state.run_id, s.step, s.tool),
        needs_approval: s.compensation_requires_approval,
        ...(s.residue?.length ? { residue: s.residue } : {}),
        ...(s.compensation_kind ? { compensation_kind: s.compensation_kind } : {}),
        ...(s.verification ? { verified: true } : {}),
      };
    }
    case "skip":
      return { ...base, kind };
    case "unrecoverable":
      return {
        ...base,
        kind,
        note:
          s.effect === "irreversible"
            ? "irreversible: cannot be undone, needs human follow-up"
            : s.handle_missing.length
              ? `compensation arguments unavailable: ${s.handle_missing.join(", ")}`
              : "marked unrecoverable",
      };
    case "unresolved":
      return { ...base, kind, note: "outcome unknown: reconcile with the downstream system" };
    case "unmanifested":
      return { ...base, kind, note: "no manifest was registered for this tool, so its effect is unknown" };
  }
}

export class Reversi {
  readonly registry: Registry;
  readonly ledger: Ledger;
  readonly runs: RunStore;
  readonly policy: Policy | undefined;
  readonly content: ContentChecker | undefined;
  readonly environment: string;
  private readonly approver: Approver | undefined;
  private readonly clock: () => number;
  private readonly killFile: string | undefined;
  private readonly memoryHalts = new Map<string, Halt>();
  private readonly kv: KvStore | undefined;
  readonly capture: CaptureStore | undefined;

  constructor(opts: ReversiOptions) {
    this.kv = opts.kv;
    this.capture = opts.capture;
    this.policy = opts.policy;
    this.content = opts.content;
    this.environment = opts.environment ?? "default";
    this.killFile = opts.kill_switch_file;
    this.registry = opts.registry;
    this.ledger = opts.ledger;
    this.runs = opts.runs ?? new MemoryRunStore();
    this.approver = opts.approver;
    this.clock = opts.now ?? Date.now;
  }

  startRun(opts: StartRunOptions): Run {
    const run_id = opts.run_id ?? `run_${randomUUID()}`;
    if (!RUN_ID_PATTERN.test(run_id)) throw new ReversiError(`invalid run id: ${JSON.stringify(run_id)}`);
    if (this.runs.get(run_id)) throw new ReversiError(`run \`${run_id}\` already exists`);
    const state: RunState = {
      run_id,
      actor: opts.actor,
      mode: opts.mode ?? "enforce",
      scope: {
        permissions: opts.scope.permissions(),
        seal: opts.scope.seal,
        parent_seal: opts.scope.parentSeal,
      },
      created_ms: this.clock(),
      ...(opts.tenant ? { tenant: opts.tenant } : {}),
      steps: [],
    };
    this.ledger.append({
      ts_ms: state.created_ms,
      run_id,
      actor: opts.actor,
      tool: "-",
      payload: { permissions: state.scope.permissions, seal: state.scope.seal, mode: state.mode },
      reason: opts.reason ?? "run started",
      event: "run_started",
      detail: `mode=${state.mode} scope_seal=${state.scope.seal}`,
    });
    this.runs.put(state);
    return new Run(this, run_id);
  }

  openRun(run_id: string): Run {
    if (!this.runs.get(run_id)) throw new ReversiError(`run \`${run_id}\` not found`);
    return new Run(this, run_id);
  }

  runIds(): string[] {
    return this.runs.list();
  }

  /**
   * Emergency stop: block new calls until {@link Reversi.resume}. With no scope it stops everything; a scope narrows it to
   * a tool (glob), actor, tenant or environment. Rollbacks are never affected. Halts live in the shared settings store when
   * there is one, so every process sees them.
   */
  halt(reason: string, scope: HaltScope = {}, by = "operator"): Halt {
    const h: Halt = { id: `halt_${randomUUID()}`, reason: reason || "halted by operator", scope, by, ts_ms: this.clock() };
    if (this.kv) this.kv.put("halts", h.id, h);
    else this.memoryHalts.set(h.id, h);
    return h;
  }

  /** Lift one halt by id, or all of them. Returns how many were lifted. */
  resume(id?: string): number {
    const all = this.halts().filter((h) => !id || h.id === id);
    for (const h of all) {
      if (this.kv) this.kv.delete("halts", h.id);
      else this.memoryHalts.delete(h.id);
    }
    return all.length;
  }

  halts(): Halt[] {
    return this.kv ? this.kv.list<Halt>("halts").map((e) => e.value) : [...this.memoryHalts.values()];
  }

  /** The reason new calls (matching `ctx`, if given) are blocked, or null. The kill-switch file halts everything. */
  halted(ctx?: { tool?: string; actor?: string; tenant?: string; environment?: string }): string | null {
    for (const h of this.halts()) {
      const s = h.scope;
      const applies =
        (s.tool === undefined || (ctx?.tool !== undefined && globAny(s.tool, ctx.tool))) &&
        (s.actor === undefined || (ctx?.actor !== undefined && globAny(s.actor, ctx.actor))) &&
        (s.tenant === undefined || (ctx?.tenant !== undefined && globAny(s.tenant, ctx.tenant))) &&
        (s.environment === undefined || (ctx?.environment !== undefined && globAny(s.environment, ctx.environment)));
      if (applies) {
        const scope = Object.entries(s).map(([k, v]) => `${k}=${v}`).join(", ");
        return scope ? `${h.reason} (scope: ${scope})` : h.reason;
      }
    }
    if (this.killFile && existsSync(this.killFile)) return `kill switch file ${this.killFile} exists`;
    return null;
  }

  /** @internal */
  get internals() {
    return { approver: this.approver, now: this.clock };
  }
}

export class Run {
  constructor(
    private readonly rv: Reversi,
    readonly run_id: string,
  ) {}

  private load(): RunState {
    const s = this.rv.runs.get(this.run_id);
    if (!s) throw new ReversiError(`run \`${this.run_id}\` not found`);
    return s;
  }

  private emit(
    event: LedgerEvent,
    step: number | null,
    tool: string,
    payload: unknown,
    reason: string,
    detail = "",
    actor?: string,
  ): void {
    this.rv.ledger.append({
      ts_ms: this.rv.internals.now(),
      run_id: this.run_id,
      step,
      actor: actor ?? this.load().actor,
      tool,
      payload,
      reason,
      event,
      detail,
    });
  }

  private nextStep(state: RunState): number {
    let max = state.steps.length - 1;
    for (const r of this.rv.ledger.forRun(this.run_id)) if (r.step !== null && r.step > max) max = r.step;
    return max + 1;
  }

  state(): RunState {
    return this.load();
  }

  /**
   * Authorize a call and journal its intent. Does not execute anything: the caller runs the tool
   * only on `allow` or `would_block`, then reports the outcome with {@link Run.complete}.
   */
  async begin(call: BeginInput): Promise<BeginResult> {
    const state = this.load();
    const manifest = this.rv.registry.get(call.tool);
    const violations: string[] = [];

    if (!manifest) violations.push(`no manifest registered for tool \`${call.tool}\``);

    let scope: SealedScope | null = null;
    try {
      scope = SealedScope.restore(state.scope.permissions, state.scope.seal, state.scope.parent_seal);
    } catch {
      violations.push("the run's scope was modified after it was sealed");
    }
    if (scope && manifest && !scope.has(manifest.permission)) {
      violations.push(`permission \`${manifest.permission}\` is not in the run's scope`);
    }

    const depends = new Set<number>();
    if (manifest) {
      for (const req of manifest.requires) {
        const dep = [...state.steps].reverse().find((s) => s.tool === req && s.status === "succeeded");
        if (dep) depends.add(dep.step);
        else violations.push(`requires \`${req}\` to have succeeded earlier in this run`);
      }
    }
    for (const d of call.depends_on ?? []) {
      if (state.steps.some((s) => s.step === d)) depends.add(d);
      else violations.push(`depends_on step ${d} does not exist`);
    }

    if (manifest?.status === "draft") violations.push(`the manifest for \`${call.tool}\` is a draft: publish it before it can be enforced`);
    if (call.extra_violations?.length) violations.push(...call.extra_violations);

    // Duplicate-call guard: the same rendered idempotency key must not run twice while the first still stands.
    let idemKey: string | undefined;
    if (manifest?.idempotency) {
      const rendered = renderIdempotencyKey(manifest.idempotency.key, call.args);
      if (rendered === undefined) {
        violations.push(`idempotency key \`${manifest.idempotency.key}\` needs arguments that are missing or not simple values`);
      } else {
        idemKey = `${call.tool}|${rendered}`;
        const scope = manifest.idempotency.scope;
        const runs = scope === "run" ? [state] : this.rv.runIds().map((id) => this.rv.runs.get(id)).filter((r): r is RunState => !!r && (scope === "global" || r.actor === state.actor));
        for (const r of runs) {
          const dup = r.steps.find((x) => x.idem_key === idemKey && LIVE_STATUSES.has(x.status));
          if (dup) {
            violations.push(`duplicate call: idempotency key matches step ${dup.step} of run ${r.run_id} (${dup.status})${dup.status === "intended" ? ", which is still in flight" : ""}`);
            break;
          }
        }
      }
    }

    // Arguments with no canonical form (Infinity, NaN, BigInt...) would all share one hash, which would let an
    // approval granted for one call cover another. Treat them as a violation and never match an approval.
    let argsHash: string;
    try {
      argsHash = sha256Hex(canonicalize(call.args === undefined ? null : call.args));
    } catch (e) {
      argsHash = `unhashable-${randomUUID()}`;
      violations.push(`arguments cannot be canonicalized: ${e instanceof Error ? e.message : "unsupported value"}`);
    }
    const triggers: string[] = [];
    const notes: string[] = [...(call.extra_notes ?? [])];
    if (manifest?.status === "deprecated") notes.push(`manifest deprecated${manifest.replaced_by ? `; use ${manifest.replaced_by}` : ""}`);
    const halted = this.rv.halted({ tool: call.tool, actor: state.actor, tenant: state.tenant, environment: this.rv.environment });
    if (halted) violations.push(`kill switch: ${halted}`);
    const policyInput: PolicyInput = {
      tool: call.tool,
      effect: manifest ? manifest.effect : null,
      permission: manifest ? manifest.permission : null,
      actor: state.actor,
      run_id: this.run_id,
      environment: this.rv.environment,
      args: call.args,
      tenant: state.tenant,
      data_class: manifest?.risk?.data_class,
      blast_radius: manifest?.risk?.blast_radius,
    };
    const requirements: ApprovalRequirement[] = [];
    let riskScore: number | undefined;
    if (this.rv.policy) {
      const d = this.rv.policy.evaluate(policyInput);
      violations.push(...d.deny);
      triggers.push(...d.approve);
      requirements.push(...d.requirements);
      notes.push(...d.warnings);
      if (d.risk) {
        riskScore = d.risk.score;
        notes.push(`risk ${d.risk.score}${d.risk.factors.length ? ` (${d.risk.factors.join(", ")})` : ""}`);
      }
    }
    if (manifest?.approval_rules) {
      const a = manifest.approval_rules;
      requirements.push({ roles: a.roles, quorum: a.quorum, timeout_ms: a.timeout_ms, on_timeout: a.on_timeout, escalate_to: a.escalate_to, source: `manifest \`${manifest.tool}\`` });
    }
    if (this.rv.content) {
      const succeeded = state.steps.filter((x) => x.status === "succeeded").map((x) => x.tool);
      const findings = [...this.rv.content.inspect(call.args), ...this.rv.content.cumulative(call.tool, succeeded)];
      for (const f of findings) {
        const text = `content check (${f.kind}): ${f.detail}`;
        if (f.action === "deny") violations.push(text);
        else if (f.action === "require_approval") triggers.push(text);
        else notes.push(text);
      }
    }
    if (manifest && manifest.approval === "always") triggers.push(MANIFEST_TRIGGER);

    const enforce = state.mode === "enforce";
    if (violations.length && enforce) {
      this.emit("blocked", null, call.tool, call.args, call.reason, violations.join("; "));
      this.captureCall(state, call, manifest?.audit?.redaction, null, "block", violations, riskScore, manifest?.version);
      return { decision: "block", reasons: violations };
    }
    const observed = [...violations];

    if (triggers.length) {
      const approver = this.rv.internals.approver;
      const decision = approver
        ? await approver({
            run_id: this.run_id,
            step: null,
            tool: call.tool,
            reason: call.reason,
            kind: "call",
            args_hash: argsHash,
            triggers,
            arg_keys: isArgObject(call.args) ? Object.keys(call.args).slice(0, 50) : [],
            requested_by: state.actor,
            ...mergeRequirements(requirements),
          })
        : false;
      const approved = typeof decision === "boolean" ? decision : decision.approved;
      if (approved) {
        this.emit("approved", null, call.tool, call.args, call.reason, `call approved; intent follows${triggers.length === 1 && triggers[0] === MANIFEST_TRIGGER ? "" : ` [${triggers.join("; ")}]`}`);
      } else {
        const msg =
          typeof decision === "object" && decision.message
            ? decision.message
            : approver
              ? "approval denied"
              : "approval required but no approver is configured";
        if (enforce) {
          this.emit("blocked", null, call.tool, call.args, call.reason, `${msg} [${triggers.join("; ")}]`);
          this.captureCall(state, call, manifest?.audit?.redaction, null, "block", [msg], riskScore, manifest?.version);
          return { decision: "block", reasons: [msg] };
        }
        observed.push(msg);
      }
    }
    this.rv.policy?.record(policyInput);

    // Everything from here to the save is synchronous, so concurrent calls cannot share a step number.
    const st = this.load();
    const step = this.nextStep(st);
    if (observed.length) {
      this.emit("would_block", step, call.tool, call.args, call.reason, observed.join("; "));
    }
    this.emit("intended", step, call.tool, call.args, call.reason, notes.join("; ")); // write-ahead: before the tool runs

    const partial: Record<string, unknown> = {};
    const missing: string[] = [];
    const argumentMap = manifest?.compensation?.argument_map ?? {};
    for (const [key, ref] of Object.entries(argumentMap)) {
      if (!ref.startsWith("$args.")) continue;
      const v = resolveRef(ref, "args", call.args);
      if (v === undefined) missing.push(key);
      else partial[key] = v;
    }
    st.steps.push({
      step,
      tool: call.tool,
      reason: call.reason,
      effect: manifest ? manifest.effect : null,
      status: "intended",
      depends_on: [...depends].sort((a, b) => a - b),
      compensation_tool: manifest?.compensation?.tool ?? null,
      compensation_requires_approval: manifest?.compensation?.requires_approval ?? false,
      argument_map: argumentMap,
      partial_handle: partial,
      handle: null,
      handle_missing: missing,
      error: null,
      ts_ms: this.rv.internals.now(),
      ...(manifest ? { manifest_version: manifest.version } : {}),
      ...(manifest?.compensation
        ? {
            compensation_kind: manifest.compensation.kind,
            residue: manifest.compensation.residue,
            ...(manifest.compensation.timeout_ms ? { compensation_timeout_ms: manifest.compensation.timeout_ms } : {}),
            ...(manifest.compensation.verification ? { verification: this.resolveVerification(manifest.compensation.verification, call.args, undefined, "call") } : {}),
          }
        : {}),
      ...(idemKey ? { idem_key: idemKey } : {}),
      ...(riskScore !== undefined ? { risk_score: riskScore } : {}),
    });
    this.rv.runs.put(st);
    this.captureCall(state, call, manifest?.audit?.redaction, step, observed.length ? "would_block" : "allow", observed, riskScore, manifest?.version);
    return observed.length ? { decision: "would_block", step, reasons: observed } : { decision: "allow", step };
  }

  /**
   * Resolve a verification's argument references. At call time only `$args.*` are known; when the call succeeds the
   * `$result.*` ones are filled in (`result` given). Anything that cannot be resolved is listed in `missing`, and the
   * verification is then reported as unverifiable instead of being skipped.
   */
  private resolveVerification(
    v: Verification,
    args: unknown,
    result: unknown,
    stage: "call" | "result",
    previous?: NonNullable<StepState["verification"]>,
  ): NonNullable<StepState["verification"]> {
    const resolved: Record<string, unknown> = { ...(previous?.args ?? {}) };
    const missing = new Set(previous?.missing ?? []);
    for (const [key, ref] of Object.entries(v.arguments)) {
      const fromArgs = ref.startsWith("$args.");
      if (fromArgs && stage === "call") {
        const val = resolveRef(ref, "args", args);
        if (val === undefined) missing.add(key);
        else resolved[key] = val;
      } else if (!fromArgs && stage === "result") {
        const val = result === undefined ? undefined : resolveRef(ref, "result", result);
        if (val === undefined) missing.add(key);
        else resolved[key] = val;
      }
    }
    return { tool: v.tool, refs: v.arguments, args: resolved, expect: v.expect, retries: v.retries, backoff_ms: v.backoff_ms, missing: [...missing] };
  }

  private captureCall(
    state: RunState,
    call: BeginInput,
    redact: string[] | undefined,
    step: number | null,
    decision: "allow" | "would_block" | "block",
    reasons: string[],
    risk: number | undefined,
    manifest_version: number | undefined,
  ): void {
    if (!this.rv.capture?.enabled) return;
    try {
      this.rv.capture.record({
        run_id: this.run_id,
        step,
        tool: call.tool,
        actor: state.actor,
        tenant: state.tenant,
        environment: this.rv.environment,
        args: call.args,
        decision,
        reasons,
        manifest_version,
        risk_score: risk,
        redact_paths: redact,
      });
    } catch {
      /* capture is a convenience: it must never stop a call */
    }
  }

  /** Record the outcome of a call that {@link Run.begin} allowed. */
  complete(step: number, outcome: Outcome): { step: number; status: StepStatus } {
    return this.applyOutcome(step, outcome, ["intended"]);
  }

  /**
   * Operator reconciliation: settle a step whose outcome was unknown (`intended` or `uncertain`)
   * after checking the downstream system. The ledger records who resolved it and why.
   */
  resolve(step: number, outcome: Outcome, by: { actor: string; note: string }): { step: number; status: StepStatus } {
    if (!by.note.trim()) throw new ReversiError("resolving a step needs a note saying how the outcome was established");
    return this.applyOutcome(step, outcome, ["intended", "uncertain"], by);
  }

  /** Ask `probe` about each unresolved step; settle those it can answer, leave the rest. */
  async reconcile(
    probe: (s: { step: number; tool: string; reason: string }) => Outcome | null | Promise<Outcome | null>,
    actor = "reconciler",
  ): Promise<{ resolved: number[]; still_unknown: number[] }> {
    const resolved: number[] = [];
    const still: number[] = [];
    for (const s of this.load().steps) {
      if (s.status !== "intended" && s.status !== "uncertain") continue;
      let o: Outcome | null = null;
      try {
        o = await probe({ step: s.step, tool: s.tool, reason: s.reason });
      } catch {
        o = null;
      }
      if (o && o.status !== "uncertain") {
        this.resolve(s.step, o, { actor, note: "established by automatic reconciliation probe" });
        resolved.push(s.step);
      } else still.push(s.step);
    }
    return { resolved, still_unknown: still };
  }

  /** Wrap a tool function so every call goes through this run. Throws {@link BlockedError} when blocked. */
  wrap<A, R>(tool: string, fn: (args: A) => R | Promise<R>, reason: string | ((args: A) => string)): (args: A) => Promise<R> {
    return async (args: A) => {
      const r = await this.call<R>({ tool, args, reason: typeof reason === "function" ? reason(args) : reason, execute: (a) => fn(a as A) });
      if (r.status === "blocked") throw new BlockedError(tool, r.reasons);
      return r.result;
    };
  }

  private applyOutcome(
    step: number,
    outcome: Outcome,
    allowed: StepStatus[],
    by?: { actor: string; note: string },
  ): { step: number; status: StepStatus } {
    const st = this.load();
    const s = st.steps.find((x) => x.step === step);
    if (!s) throw new ReversiError(`unknown step ${step}`);
    if (!allowed.includes(s.status)) {
      throw new ReversiError(`step ${step} is \`${s.status}\`, not awaiting an outcome`);
    }
    const who = by ? `resolved by ${by.actor}: ${by.note}` : "";
    if (outcome.status === "succeeded") {
      const handle: Record<string, unknown> = { ...s.partial_handle };
      const missing = [...s.handle_missing];
      for (const [key, ref] of Object.entries(s.argument_map)) {
        if (!ref.startsWith("$result.")) continue;
        const v = outcome.invalid_result ? undefined : resolveRef(ref, "result", outcome.result);
        if (v === undefined) missing.push(key);
        else handle[key] = v;
      }
      if (s.verification) {
        const sp = s.verification;
        s.verification = this.resolveVerification(
          { tool: sp.tool, arguments: sp.refs, expect: sp.expect, retries: sp.retries, backoff_ms: sp.backoff_ms },
          undefined,
          outcome.invalid_result ? undefined : outcome.result,
          "result",
          sp,
        );
      }
      s.result_hash = hashPayload(outcome.result);
      const flagged = this.rv.content?.inspect(outcome.result).filter((f) => f.kind === "injection" || f.kind === "encoded_payload") ?? [];
      const detail = [
        missing.length ? `compensation arguments unavailable: ${missing.join(", ")}` : "",
        outcome.invalid_result ? "result does not match the tool's declared output" : "",
        ...(outcome.notes ?? []),
        ...flagged.map((f) => `result content check (${f.kind}): ${f.detail}`),
        who,
      ].filter(Boolean);
      this.emit("succeeded", step, s.tool, outcome.result, s.reason, detail.join("; "), by?.actor);
      s.handle = handle;
      s.handle_missing = missing;
      s.status = "succeeded";
    } else {
      const error = outcome.error ? messageOf(outcome.error) : "";
      this.emit(outcome.status, step, s.tool, null, s.reason, [error, who].filter(Boolean).join("; "), by?.actor);
      s.status = outcome.status;
      s.error = error || null;
    }
    this.rv.runs.put(st);
    if (this.rv.capture?.enabled && (s.status === "succeeded" || s.status === "failed" || s.status === "uncertain")) {
      try {
        this.rv.capture.complete(this.run_id, step, s.status, outcome.status === "succeeded" ? outcome.result : undefined, this.rv.registry.get(s.tool)?.audit?.redaction);
      } catch {
        /* see above */
      }
    }
    return { step, status: s.status };
  }

  /** Authorize, execute and journal one tool call. Rethrows the executor's error after journaling it. */
  async call<T>(
    c: BeginInput & { execute: (args: unknown) => T | Promise<T> },
  ): Promise<CallResult<T>> {
    const b = await this.begin(c);
    if (b.decision === "block") return { status: "blocked", reasons: b.reasons };
    let result: T;
    try {
      result = await c.execute(c.args);
    } catch (e) {
      this.complete(
        b.step,
        e instanceof EffectUncertainError
          ? { status: "uncertain", error: messageOf(e) }
          : { status: "failed", error: messageOf(e) },
      );
      throw e;
    }
    this.complete(b.step, { status: "succeeded", result });
    return b.decision === "would_block"
      ? { status: "executed", step: b.step, result, observed_violations: b.reasons }
      : { status: "executed", step: b.step, result };
  }

  /** Steps whose outcome is unknown: journaled as intended but never completed, or reported uncertain. */
  unresolved(): number[] {
    const out = new Set<number>();
    for (const s of this.load().steps) if (s.status === "intended" || s.status === "uncertain") out.add(s.step);
    // Steps the ledger knows about but run state lost (a crash between journaling and saving).
    const intended = new Set<number>();
    const finished = new Set<number>();
    for (const r of this.rv.ledger.forRun(this.run_id)) {
      if (r.step === null) continue;
      if (r.event === "intended") intended.add(r.step);
      if (r.event === "succeeded" || r.event === "failed") finished.add(r.step);
    }
    for (const n of intended) if (!finished.has(n)) out.add(n);
    return [...out].sort((a, b) => a - b);
  }

  /** What a rollback would do, assuming every compensation succeeds. Executes nothing. */
  plan(): RollbackPlan {
    const sim = this.load();
    const actions: PlanAction[] = [];
    const ordered = [...sim.steps].sort((a, b) => b.step - a.step);
    for (const s of ordered) {
      const a = classify(sim, s);
      if (!a) continue;
      actions.push(a);
      if (a.kind === "compensate") s.status = "compensated";
      else if (a.kind === "skip") s.status = "no_action";
    }
    return {
      run_id: this.run_id,
      actions,
      fully_reversible: actions.every((a) => a.kind === "compensate" || a.kind === "skip"),
    };
  }

  /**
   * Begin undoing one step: checks dependencies and approval, then journals `compensating`
   * before returning the call to make. Use with {@link Run.completeCompensation} when the
   * compensation is executed by someone else (an SDK, a remote worker).
   */
  async beginCompensation(step_no: number, opts: { actor?: string } = {}): Promise<CompensationStart> {
    const actor = opts.actor ?? "operator";
    const st = this.load();
    const s = st.steps.find((x) => x.step === step_no);
    if (!s) throw new ReversiError(`unknown step ${step_no}`);
    const a = classify(st, s);
    if (!a) return { decision: "nothing_to_do", step: step_no, status: s.status };
    const reason = `rollback of run ${this.run_id}: undo step ${step_no} (${s.tool})`;

    switch (a.kind) {
      case "skip":
        s.status = "no_action";
        this.rv.runs.put(st);
        return { decision: "not_actionable", step: step_no, kind: "skip" };
      case "unrecoverable":
        if (s.status !== "unrecoverable") {
          this.emit("unrecoverable", step_no, s.tool, null, reason, a.note ?? "", actor);
          s.status = "unrecoverable";
          this.rv.runs.put(st);
        }
        return { decision: "not_actionable", step: step_no, kind: "unrecoverable", note: a.note };
      case "unresolved":
      case "unmanifested":
        return { decision: "not_actionable", step: step_no, kind: a.kind, note: a.note };
      case "defer":
        this.emit("deferred", step_no, s.tool, null, reason, `blocked by steps ${a.blocked_by?.join(", ")}`, actor);
        return { decision: "defer", step: step_no, blocked_by: a.blocked_by ?? [] };
      case "compensate":
        break;
    }

    const compTool = a.compensation_tool as string;
    if (a.needs_approval) {
      const approver = this.rv.internals.approver;
      const decision = approver
        ? await approver({
            run_id: this.run_id,
            step: step_no,
            tool: compTool,
            reason,
            kind: "compensation",
            args_hash: hashPayload(a.args ?? {}),
            triggers: ["manifest requires approval for this compensation"],
            arg_keys: Object.keys(a.args ?? {}).slice(0, 50),
          })
        : false;
      const ok = typeof decision === "boolean" ? decision : decision.approved;
      if (!ok) {
        this.emit(
          "blocked",
          step_no,
          compTool,
          a.args,
          reason,
          typeof decision === "object" && decision.message
            ? decision.message
            : approver
              ? "compensation approval denied"
              : "compensation needs approval but no approver is configured",
          actor,
        );
        return { decision: "awaiting_approval", step: step_no };
      }
      this.emit("approved", step_no, compTool, a.args, reason, "compensation approved", actor);
    }

    // Reload: the approval above may have taken a while.
    const st2 = this.load();
    const s2 = st2.steps.find((x) => x.step === step_no) as StepState;
    if (!["succeeded", "compensation_failed", "compensating"].includes(s2.status)) {
      return { decision: "nothing_to_do", step: step_no, status: s2.status };
    }
    const key = a.idempotency_key as string;
    this.emit("compensating", step_no, compTool, a.args, reason, `idempotency_key=${key}`, actor); // write-ahead
    s2.status = "compensating";
    this.rv.runs.put(st2);
    return {
      decision: "go",
      step: step_no,
      call: {
        run_id: this.run_id,
        step: step_no,
        tool: compTool,
        original_tool: s.tool,
        args: a.args ?? {},
        idempotency_key: key,
      },
    };
  }

  completeCompensation(step_no: number, outcome: CompensationOutcome, opts: { actor?: string } = {}): void {
    const st = this.load();
    const s = st.steps.find((x) => x.step === step_no);
    if (!s) throw new ReversiError(`unknown step ${step_no}`);
    if (s.status !== "compensating") {
      throw new ReversiError(`step ${step_no} is \`${s.status}\`, not mid-compensation`);
    }
    const actor = opts.actor ?? "operator";
    const reason = `rollback of run ${this.run_id}: undo step ${step_no} (${s.tool})`;
    const compTool = s.compensation_tool ?? s.tool;
    if (outcome.status === "compensated") {
      this.emit("compensated", step_no, compTool, s.handle, reason, "", actor);
      s.status = "compensated";
      s.error = null;
    } else {
      const error = outcome.error ? messageOf(outcome.error) : "compensation failed";
      this.emit("compensation_failed", step_no, compTool, s.handle, reason, error, actor);
      s.status = "compensation_failed";
      s.error = error;
    }
    this.rv.runs.put(st);
  }

  private async runVerification(
    step: number,
    v: NonNullable<StepState["verification"]>,
    verifier: ((tool: string, args: Record<string, unknown>) => unknown | Promise<unknown>) | undefined,
    actor: string | undefined,
    sleep: (ms: number) => Promise<void>,
    _base: number,
    _cap: number,
  ): Promise<"verified" | "failed" | "impossible" | "unverified"> {
    const reason = `rollback of run ${this.run_id}: verify the undo of step ${step}`;
    const who = actor ?? "operator";
    if (v.missing.length) {
      this.emit("verification_failed", step, v.tool, null, reason, `cannot verify: arguments unavailable (${v.missing.join(", ")})`, who);
      return "impossible";
    }
    if (!verifier) {
      this.emit("unverified", step, v.tool, v.args, reason, "no verifier is available to run the declared read-back", who);
      return "unverified";
    }
    let last = "";
    for (let attempt = 1; attempt <= v.retries; attempt++) {
      try {
        const got = await verifier(v.tool, v.args);
        const mismatch = expectMismatch(got, v.expect);
        if (!mismatch) {
          this.emit("verified", step, v.tool, v.args, reason, `${v.tool} matched the expected state${attempt > 1 ? ` on attempt ${attempt}` : ""}`, who);
          return "verified";
        }
        last = mismatch;
      } catch (e) {
        last = `verifier error: ${messageOf(e)}`;
      }
      if (attempt < v.retries) await sleep(v.backoff_ms * 2 ** (attempt - 1));
    }
    this.emit("verification_failed", step, v.tool, v.args, reason, `after ${v.retries} attempts: ${last}`, who);
    return "failed";
  }

  /**
   * Undo the run: newest step first, skipping nothing silently. A step is never undone while a step
   * depending on it is still standing. Failures do not stop independent steps. Safe to call again:
   * compensated steps are skipped, failed ones are retried with the same idempotency key.
   */
  async rollback(opts: {
    compensate: Compensator;
    actor?: string;
    /** Retry a failing compensation with exponential backoff and the same idempotency key. */
    retry?: { attempts?: number; base_ms?: number; max_ms?: number; sleep?: (ms: number) => Promise<void> };
    /** After a compensation reports success, confirm the undo is visible downstream. `false` or a throw counts as failure. */
    verify?: (call: CompensationCall) => boolean | Promise<boolean>;
    /**
     * Executes a manifest-declared verification: call `tool` with `args` and return what it returned (parsed). The engine
     * compares it with the declared `expect`, retrying with backoff. Without a verifier, a step that declares one is
     * reported as `unverified` and the rollback is not complete.
     */
    verifier?: (tool: string, args: Record<string, unknown>) => unknown | Promise<unknown>;
  }): Promise<RollbackReport> {
    const attempts = Math.max(1, opts.retry?.attempts ?? 1);
    const base = opts.retry?.base_ms ?? 200;
    const cap = opts.retry?.max_ms ?? 5000;
    const sleep = opts.retry?.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const report: RollbackReport = {
      run_id: this.run_id,
      compensated: [],
      skipped: [],
      failed: [],
      unrecoverable: [],
      unresolved: [],
      unmanifested: [],
      deferred: [],
      awaiting_approval: [],
      unverified: [],
      complete: false,
    };
    const order = this.load()
      .steps.map((s) => s.step)
      .sort((a, b) => b - a);
    for (const n of order) {
      const start = await this.beginCompensation(n, { actor: opts.actor });
      switch (start.decision) {
        case "go":
          {
            let error: string | null = null;
            for (let attempt = 1; attempt <= attempts; attempt++) {
              try {
                await opts.compensate(start.call);
                if (opts.verify && !(await opts.verify(start.call))) throw new Error("verification failed: the undo is not visible downstream");
                error = null;
                break;
              } catch (e) {
                error = messageOf(e);
                if (attempt < attempts) await sleep(Math.min(cap, base * 2 ** (attempt - 1)) * (0.5 + Math.random() / 2));
              }
            }
            let unverified = false;
            if (error === null) {
              const sv = this.load().steps.find((x) => x.step === n)?.verification;
              if (sv) {
                const outcome = await this.runVerification(n, sv, opts.verifier, opts.actor, sleep, base, cap);
                if (outcome === "failed") error = `verification failed: ${sv.tool} did not show the expected state after the undo`;
                else if (outcome === "impossible") error = `verification impossible: arguments unavailable (${sv.missing.join(", ")})`;
                else if (outcome === "unverified") unverified = true;
              }
            }
            if (error === null) {
              this.completeCompensation(n, { status: "compensated" }, { actor: opts.actor });
              report.compensated.push(n);
              if (unverified) report.unverified.push(n);
            } else {
              const msg = attempts > 1 ? `${error} (after ${attempts} attempts)` : error;
              this.completeCompensation(n, { status: "failed", error: msg }, { actor: opts.actor });
              report.failed.push({ step: n, error: msg });
            }
          }
          break;
        case "defer":
          report.deferred.push({ step: n, blocked_by: start.blocked_by });
          break;
        case "awaiting_approval":
          report.awaiting_approval.push(n);
          break;
        case "not_actionable":
          if (start.kind === "skip") report.skipped.push(n);
          else if (start.kind === "unrecoverable") report.unrecoverable.push(n);
          else if (start.kind === "unresolved") report.unresolved.push(n);
          else if (start.kind === "unmanifested") report.unmanifested.push(n);
          break;
        case "nothing_to_do":
          break;
      }
    }
    report.complete =
      report.failed.length === 0 &&
      report.unrecoverable.length === 0 &&
      report.unresolved.length === 0 &&
      report.unmanifested.length === 0 &&
      report.deferred.length === 0 &&
      report.awaiting_approval.length === 0 &&
      report.unverified.length === 0;
    return report;
  }
}
