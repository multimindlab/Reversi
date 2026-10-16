/**
 * Look before you leap, and look back: run calls through a throwaway engine (in-memory ledger and run state, the real
 * manifests and policy, nothing executed anywhere) to answer "what would this policy have done to last week's calls",
 * "what if this one argument had been different", "which of these plans is safest" and "what would approving this do".
 */
import { randomUUID } from "node:crypto";
import type { CaptureRecord } from "./capture.js";
import type { ContentChecker } from "./content.js";
import { Reversi, type RollbackPlan } from "./engine.js";
import { Ledger } from "./ledger.js";
import type { Registry, ToolManifest } from "./manifest.js";
import { Policy, type PolicyDoc } from "./policy.js";
import { SealedScope } from "./scope.js";

export interface SandboxContext {
  registry: Registry;
  policy?: PolicyDoc;
  content?: ContentChecker;
  environment?: string;
  /** Pretend the policy's clock is here (for time windows and freezes). */
  now?: () => number;
}

export type Verdict = "allow" | "needs_approval" | "block";

export interface SandboxCall {
  run?: string;
  tool: string;
  args?: unknown;
  actor?: string;
  tenant?: string;
  /** What the tool returned (used for compensation arguments). If omitted a result is synthesized from the manifest. */
  result?: unknown;
  /** The recorded outcome, when replaying. Default succeeded. */
  outcome?: "succeeded" | "failed" | "uncertain";
}

export interface SandboxStep {
  run: string;
  index: number;
  tool: string;
  verdict: Verdict;
  reasons: string[];
  risk?: number;
  /** The call ran in the sandbox (allowed or would be blocked in non-enforce modes). */
  executed: boolean;
  simulated_result: boolean;
}

const APPROVAL = "approval required";

/** A result containing every `$result.*` path the manifest's compensation and verification refer to. */
export function synthesizeResult(m: ToolManifest | undefined): unknown {
  const refs = [...Object.values(m?.compensation?.argument_map ?? {}), ...Object.values(m?.compensation?.verification?.arguments ?? {})].filter((r) => r.startsWith("$result."));
  const out: Record<string, unknown> = {};
  for (const r of refs) {
    const segs = r.split(".").slice(1);
    let cur = out;
    segs.forEach((seg, i) => {
      if (i === segs.length - 1) cur[seg] = `<simulated ${seg}>`;
      else cur = (cur[seg] ??= {}) as Record<string, unknown>;
    });
  }
  return out;
}

export class Sandbox {
  readonly reversi: Reversi;
  private runs = new Map<string, ReturnType<Reversi["startRun"]>>();
  private index = new Map<string, number>();
  private assume: boolean;
  constructor(
    private readonly ctx: SandboxContext,
    opts: { assume_approved?: boolean } = {},
  ) {
    this.assume = opts.assume_approved === true;
    const registry = ctx.registry;
    this.reversi = new Reversi({
      registry,
      ledger: new Ledger(),
      policy: ctx.policy ? new Policy(ctx.policy, ctx.now) : undefined,
      content: ctx.content,
      environment: ctx.environment,
      now: ctx.now,
      approver: () => (this.assume ? true : { approved: false, message: `${APPROVAL}: simulated` }),
    });
  }

  private runFor(id: string, actor: string, tenant: string | undefined) {
    let run = this.runs.get(id);
    if (!run) {
      const perms = [...new Set(this.ctx.registry.list().map((m) => m.permission))];
      run = this.reversi.startRun({ run_id: `sim_${randomUUID().slice(0, 8)}_${id}`.slice(0, 100).replace(/[^A-Za-z0-9._-]/g, "_"), actor, scope: SealedScope.seal(perms), tenant });
      this.runs.set(id, run);
    }
    return run;
  }

  async call(c: SandboxCall): Promise<SandboxStep> {
    const id = c.run ?? "plan";
    const run = this.runFor(id, c.actor ?? "simulation", c.tenant);
    const manifest = this.ctx.registry.get(c.tool);
    const i = this.index.get(id) ?? 0;
    this.index.set(id, i + 1);
    const b = await run.begin({ tool: c.tool, args: c.args, reason: "simulation" });
    if (b.decision === "block") {
      const approval = b.reasons.some((r) => r.startsWith(APPROVAL));
      return { run: id, index: i, tool: c.tool, verdict: approval ? "needs_approval" : "block", reasons: b.reasons, executed: false, simulated_result: false };
    }
    const simulated = c.result === undefined;
    const result = c.result ?? synthesizeResult(manifest);
    const outcome = c.outcome ?? "succeeded";
    run.complete(b.step, outcome === "succeeded" ? { status: "succeeded", result } : { status: outcome, error: "simulated" });
    const risk = run.state().steps.find((s) => s.step === b.step)?.risk_score;
    return { run: id, index: i, tool: c.tool, verdict: "allow", reasons: b.decision === "would_block" ? b.reasons : [], risk, executed: true, simulated_result: simulated };
  }

  /** Run a prerequisite as if it had already been approved and had succeeded, without changing how later calls are judged. */
  async seed(c: SandboxCall): Promise<SandboxStep> {
    const before = this.assume;
    this.assume = true;
    try {
      return await this.call(c);
    } finally {
      this.assume = before;
    }
  }

  plan(run = "plan"): RollbackPlan | undefined {
    return this.runs.get(run)?.plan();
  }
}

// ---- policy simulation against captured history ----

export interface Change {
  before: Verdict;
  after: Verdict;
  run: string;
  step: number | null;
  tool: string;
  reasons: string[];
}

export interface SimulationReport {
  calls: number;
  runs: number;
  unchanged: number;
  newly_blocked: Change[];
  newly_needs_approval: Change[];
  newly_allowed: Change[];
  /** Calls the history had blocked for a reason other than policy (scope, kill switch) and that still are. */
  notes: string[];
}

function historical(r: CaptureRecord): Verdict {
  if (r.decision !== "block") return "allow";
  return r.reasons.some((x) => x.startsWith(APPROVAL)) ? "needs_approval" : "block";
}

/** Replay captured calls through a candidate policy and say what would have been decided differently. */
export async function simulatePolicy(records: CaptureRecord[], ctx: SandboxContext): Promise<SimulationReport> {
  const sandbox = new Sandbox(ctx);
  const rep: SimulationReport = { calls: 0, runs: new Set(records.map((r) => r.run_id)).size, unchanged: 0, newly_blocked: [], newly_needs_approval: [], newly_allowed: [], notes: [] };
  for (const r of [...records].sort((a, b) => a.ts_ms - b.ts_ms)) {
    rep.calls++;
    const step = await sandbox.call({ run: r.run_id, tool: r.tool, args: r.args, actor: r.actor, tenant: r.tenant, result: r.result, outcome: r.outcome });
    const before = historical(r);
    const after = step.verdict;
    if (before === after) {
      rep.unchanged++;
      continue;
    }
    const change: Change = { before, after, run: r.run_id, step: r.step, tool: r.tool, reasons: step.reasons };
    if (after === "block") rep.newly_blocked.push(change);
    else if (after === "needs_approval") rep.newly_needs_approval.push(change);
    else rep.newly_allowed.push(change);
  }
  const redacted = records.some((r) => JSON.stringify(r.args).includes("[REDACTED]") || JSON.stringify(r.args).includes("[PII:"));
  if (redacted) rep.notes.push("some captured arguments were redacted, so rules that look inside those values may behave differently than they did live");
  return rep;
}

// ---- replay one run with a change ----

export interface ArgChange {
  /** Step number, or omit to apply to every call of `tool`. */
  step?: number;
  tool?: string;
  /** `$args.amount` or `amount`. */
  path: string;
  value: unknown;
}

function applyChange(args: unknown, path: string, value: unknown): unknown {
  const clone = JSON.parse(JSON.stringify(args ?? {})) as Record<string, unknown>;
  const segs = path.replace(/^\$args\./, "").split(".");
  let cur = clone as Record<string, unknown>;
  segs.forEach((seg, i) => {
    if (i === segs.length - 1) cur[seg] = value;
    else {
      if (typeof cur[seg] !== "object" || cur[seg] === null) cur[seg] = {};
      cur = cur[seg] as Record<string, unknown>;
    }
  });
  return clone;
}

export interface ReplayReport {
  baseline: SandboxStep[];
  variant: SandboxStep[];
  differences: Array<{ index: number; tool: string; before: Verdict; after: Verdict; reasons: string[] }>;
  baseline_plan?: RollbackPlan;
  variant_plan?: RollbackPlan;
}

/** Replay one captured run twice, as recorded and with the changes, in the sandbox. Nothing touches production. */
export async function replayRun(records: CaptureRecord[], ctx: SandboxContext, changes: ArgChange[]): Promise<ReplayReport> {
  const calls = [...records].sort((a, b) => a.ts_ms - b.ts_ms);
  const go = async (mutate: boolean) => {
    const sb = new Sandbox(ctx, { assume_approved: true });
    const steps: SandboxStep[] = [];
    for (const [i, r] of calls.entries()) {
      let args = r.args;
      if (mutate) for (const c of changes) if ((c.step === undefined || c.step === (r.step ?? i)) && (c.tool === undefined || c.tool === r.tool)) args = applyChange(args, c.path, c.value);
      steps.push(await sb.call({ run: "replay", tool: r.tool, args, actor: r.actor, tenant: r.tenant, result: r.result, outcome: r.outcome }));
    }
    return { steps, plan: sb.plan("replay") };
  };
  // Judge decisions without assuming approval (so "needs approval" shows), then compute the plans on the approved path.
  const judge = async (mutate: boolean) => {
    const sb = new Sandbox(ctx);
    const steps: SandboxStep[] = [];
    for (const [i, r] of calls.entries()) {
      let args = r.args;
      if (mutate) for (const c of changes) if ((c.step === undefined || c.step === (r.step ?? i)) && (c.tool === undefined || c.tool === r.tool)) args = applyChange(args, c.path, c.value);
      steps.push(await sb.call({ run: "replay", tool: r.tool, args, actor: r.actor, tenant: r.tenant, result: r.result, outcome: r.outcome }));
    }
    return steps;
  };
  const [bj, vj, bp, vp] = await Promise.all([judge(false), judge(true), go(false), go(true)]);
  return {
    baseline: bj,
    variant: vj,
    differences: vj.flatMap((v, i) => (v.verdict !== bj[i]?.verdict ? [{ index: i, tool: v.tool, before: (bj[i] as SandboxStep).verdict, after: v.verdict, reasons: v.reasons }] : [])),
    baseline_plan: bp.plan,
    variant_plan: vp.plan,
  };
}

// ---- speculative execution: compare alternative plans ----

export interface PlanInput {
  name: string;
  calls: Array<{ tool: string; args?: unknown; result?: unknown }>;
}

export interface PlanReport {
  name: string;
  steps: SandboxStep[];
  /** Index of the first call that would be refused, if any. */
  blocked_at?: number;
  approvals_needed: number;
  max_risk: number;
  total_risk: number;
  irreversible: string[];
  residue: string[];
  fully_reversible: boolean;
  rollback: RollbackPlan | undefined;
  /** Lower is safer. Blocked plans rank last. */
  rank: number;
  notes: string[];
}

export interface SpeculationReport {
  plans: PlanReport[];
  /** Name of the safest plan that can run to the end, if any. */
  recommended?: string;
}

export async function speculate(plans: PlanInput[], ctx: SandboxContext, o: { actor?: string; tenant?: string } = {}): Promise<SpeculationReport> {
  const reports: PlanReport[] = [];
  for (const p of plans) {
    const sb = new Sandbox(ctx, { assume_approved: true });
    const judge = new Sandbox(ctx);
    const steps: SandboxStep[] = [];
    let blocked_at: number | undefined;
    for (const [i, c] of p.calls.entries()) {
      // What would be decided if nobody had approved yet?
      const asked = await judge.call({ run: "p", tool: c.tool, args: c.args, actor: o.actor, tenant: o.tenant, result: c.result });
      const step = await sb.call({ run: "p", tool: c.tool, args: c.args, actor: o.actor, tenant: o.tenant, result: c.result });
      steps.push(asked.verdict === "needs_approval" ? { ...step, verdict: "needs_approval", reasons: asked.reasons } : step);
      if (step.verdict === "block") {
        blocked_at = i;
        break;
      }
    }
    const rollback = sb.plan("p");
    const executed = steps.filter((s) => s.executed);
    const manifests = executed.map((s) => ctx.registry.get(s.tool));
    const irreversible = executed.filter((_, i) => manifests[i]?.effect === "irreversible").map((s) => s.tool);
    const residue = [...new Set((rollback?.actions ?? []).flatMap((a) => a.residue ?? []))];
    const approvals = steps.filter((s) => s.verdict === "needs_approval").length;
    const risks = executed.map((s) => s.risk ?? 0);
    const max_risk = risks.length ? Math.max(...risks) : 0;
    const notes: string[] = [];
    if (steps.some((s) => s.simulated_result)) notes.push("some results were synthesized from the manifests, so the rollback outlook assumes compensation arguments are available");
    if (!ctx.policy) notes.push("no policy loaded: decisions come from manifests and scope only");
    reports.push({
      name: p.name,
      steps,
      ...(blocked_at !== undefined ? { blocked_at } : {}),
      approvals_needed: approvals,
      max_risk,
      total_risk: risks.reduce((a, b) => a + b, 0),
      irreversible,
      residue,
      fully_reversible: rollback?.fully_reversible ?? true,
      rollback,
      rank: (blocked_at !== undefined ? 10_000 : 0) + approvals * 10 + max_risk + irreversible.length * 50 + (rollback?.fully_reversible === false ? 25 : 0),
      notes,
    });
  }
  reports.sort((a, b) => a.rank - b.rank);
  return { plans: reports, recommended: reports.find((r) => r.blocked_at === undefined)?.name };
}

// ---- impact preview ----

export interface ImpactPreview {
  tool: string;
  known: boolean;
  status?: string;
  effect: string | null;
  owner?: string;
  risk?: { data_class?: string; blast_radius?: string };
  verdict: Verdict;
  reasons: string[];
  risk_score?: { score: number; factors: string[] };
  approval?: { roles: string[]; quorum: number; timeout_ms?: number; on_timeout?: string };
  compensation?: { tool: string; kind: string; residue: string[]; verified: boolean; needs_approval: boolean };
  requires: string[];
  rollback_outlook: string[];
  warnings: string[];
}

/** What would approving this call do, and what could be undone afterwards? */
export async function previewImpact(ctx: SandboxContext, call: { tool: string; args?: unknown; actor?: string; tenant?: string }): Promise<ImpactPreview> {
  const m = ctx.registry.get(call.tool);
  if (!m) {
    return { tool: call.tool, known: false, effect: null, verdict: "block", reasons: ["no manifest is registered for this tool"], requires: [], rollback_outlook: ["unknown: without a manifest Reversi cannot say whether this can be undone"], warnings: ["unclassified tool"] };
  }
  const sb = new Sandbox(ctx);
  // Satisfy `requires` so the verdict and outlook are about this call, not about missing prerequisites.
  for (const r of m.requires) await sb.seed({ run: "preview", tool: r, actor: call.actor, tenant: call.tenant });
  const judged = await sb.call({ run: "preview", tool: call.tool, args: call.args, actor: call.actor, tenant: call.tenant });
  const sb2 = new Sandbox(ctx, { assume_approved: true });
  for (const r of m.requires) await sb2.call({ run: "preview", tool: r, actor: call.actor, tenant: call.tenant });
  await sb2.call({ run: "preview", tool: call.tool, args: call.args, actor: call.actor, tenant: call.tenant });
  const plan = sb2.plan("preview");
  const mine = plan?.actions.find((a) => a.tool === call.tool);
  const outlook: string[] = [];
  if (!mine) outlook.push("nothing to undo");
  else if (mine.kind === "compensate") {
    outlook.push(`undo by calling ${mine.compensation_tool}${mine.needs_approval ? " (needs approval)" : ""}`);
    if (mine.residue?.length) outlook.push(`but ${mine.residue.join("; ")}`);
    if (mine.verified) outlook.push("the undo is read back and verified");
  } else if (mine.kind === "skip") outlook.push("no undo needed: this does not change anything that needs undoing");
  else outlook.push(mine.note ?? "cannot be undone");
  const warnings: string[] = [];
  if (m.effect === "irreversible") warnings.push("irreversible: once approved, this cannot be taken back");
  if (m.status === "draft") warnings.push("the manifest is a draft");
  if (m.status === "deprecated") warnings.push(`the manifest is deprecated${m.replaced_by ? `; use ${m.replaced_by}` : ""}`);
  if (m.compensation && !m.compensation.verification) warnings.push("the undo is not verified: nothing reads back that it worked");
  const policy = ctx.policy ? new Policy(ctx.policy, ctx.now) : undefined;
  const score = policy?.score({ tool: m.tool, effect: m.effect, permission: m.permission, actor: call.actor ?? "agent", run_id: "preview", environment: ctx.environment ?? "default", args: call.args, tenant: call.tenant, data_class: m.risk?.data_class, blast_radius: m.risk?.blast_radius });
  return {
    tool: m.tool,
    known: true,
    status: m.status,
    effect: m.effect,
    owner: m.owner,
    risk: m.risk,
    verdict: judged.verdict,
    reasons: judged.reasons,
    ...(score ? { risk_score: score } : {}),
    ...(m.approval_rules ? { approval: { roles: m.approval_rules.roles, quorum: m.approval_rules.quorum, timeout_ms: m.approval_rules.timeout_ms, on_timeout: m.approval_rules.on_timeout } } : {}),
    ...(m.compensation ? { compensation: { tool: m.compensation.tool, kind: m.compensation.kind, residue: m.compensation.residue, verified: !!m.compensation.verification, needs_approval: m.compensation.requires_approval } } : {}),
    requires: m.requires,
    rollback_outlook: outlook,
    warnings,
  };
}
