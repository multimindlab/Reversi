/** Capture, policy simulation against history, replay with a change, speculative plans, and impact previews. */
import { existsSync, readFileSync, statSync } from "node:fs";
import type { Command } from "commander";
import {
  PolicyVersions,
  loadPolicyFile,
  parsePolicy,
  previewImpact,
  replayRun,
  simulatePolicy,
  speculate,
  type ArgChange,
  type PlanInput,
  type PolicyDoc,
} from "@multimindlab/reversi";
import { Fail, type Ctx, type EngineFlags } from "../context.js";
import { sinceMs } from "./inspect.js";

function loadPolicyDoc(ctx: Ctx, path: string | undefined, o: EngineFlags): PolicyDoc | undefined {
  const p = path ?? o.policy ?? ctx.project(o)?.policy;
  if (!p) return undefined;
  if (!existsSync(p)) throw new Fail(`policy not found: ${p}`);
  if (statSync(p).isDirectory()) {
    const pv = new PolicyVersions(p);
    const a = pv.activeVersion();
    return a === null ? undefined : pv.doc(a);
  }
  return loadPolicyFile(p).doc;
}

function parseChange(spec: string): ArgChange {
  // [step.]path=json   e.g. 1.amount=9000   or   tool:pay.charge.amount=9000   or   amount=9000
  const eq = spec.indexOf("=");
  if (eq < 1) throw new Fail(`--set wants path=value, like 1.amount=9000 or tool:pay.charge/amount=9000 (got "${spec}")`);
  let lhs = spec.slice(0, eq);
  const raw = spec.slice(eq + 1);
  let value: unknown = raw;
  try {
    value = JSON.parse(raw);
  } catch {
    /* a plain string */
  }
  const change: ArgChange = { path: "", value };
  const t = /^tool:([^/]+)\/(.+)$/.exec(lhs);
  if (t) {
    change.tool = t[1];
    lhs = t[2] as string;
  } else {
    const s = /^(\d+)\.(.+)$/.exec(lhs);
    if (s) {
      change.step = Number(s[1]);
      lhs = s[2] as string;
    }
  }
  change.path = lhs;
  return change;
}

export function registerSimulationCommands(program: Command, ctx: Ctx): void {
  const { io } = ctx;

  const capture = program.command("capture").description("redacted call arguments, kept for a limited time when you turn capture on");
  ctx.dataOpts(capture.command("list").description("captured calls").option("--run <id>").option("--tool <name>").option("--since <when>").option("--json")).action((o: EngineFlags & { run?: string; tool?: string; since?: string; json?: boolean }) =>
    ctx.withEngine(o, (e) => {
      if (!e.capture) return io.out("capture is off. Turn it on with `capture: { enabled: true }` in reversi.config.yaml, or REVERSI_CAPTURE=1");
      const rows = e.capture.list({ run_id: o.run, tool: o.tool, since_ms: sinceMs(o.since) });
      if (o.json) return io.out(JSON.stringify(rows, null, 2));
      for (const r of rows) io.out(`${new Date(r.ts_ms).toISOString().slice(0, 19)}Z  ${r.run_id}${r.step !== null ? `#${r.step}` : ""}  ${r.tool.padEnd(26)} ${r.decision.padEnd(11)} ${r.outcome ?? ""}  args=${JSON.stringify(r.args).slice(0, 80)}`);
      if (!rows.length) io.out("nothing captured");
    }),
  );
  ctx.dataOpts(capture.command("purge").description("delete expired captures, or everything for a run").option("--run <id>")).action((o: EngineFlags & { run?: string }) =>
    ctx.withEngine(o, (e) => {
      if (!e.capture) return io.out("capture is off");
      io.out(`removed ${e.capture.purge({ run_id: o.run })} captured calls`);
    }, { capture: { enabled: true } }),
  );

  ctx
    .dataOpts(program.command("simulate").description("replay captured calls through a different policy and report what would have been decided differently").option("--policy <file>", "the candidate policy (file or folder)").option("--since <when>", "only calls since then (default 7d)").option("--run <id>").option("--json"))
    .action((o: EngineFlags & { since?: string; run?: string; json?: boolean }) =>
      ctx.withEngine(o, async (e) => {
        if (!e.capture) throw new Fail("simulation needs captured calls: turn capture on first (it keeps redacted arguments for a limited time)");
        const policy = loadPolicyDoc(ctx, o.policy, {}) ?? undefined;
        if (!policy) throw new Fail("pass --policy <file> with the policy to try");
        const records = e.capture.list({ run_id: o.run, since_ms: o.run ? undefined : sinceMs(o.since ?? "7d") });
        if (!records.length) throw new Fail("no captured calls in that period");
        const rep = await simulatePolicy(records, { registry: e.registry, policy, environment: e.reversi.environment });
        if (o.json) return io.out(JSON.stringify(rep, null, 2));
        io.out(`${rep.calls} captured calls in ${rep.runs} runs: ${rep.unchanged} unchanged`);
        const show = (title: string, list: typeof rep.newly_blocked) => {
          if (!list.length) return;
          io.out(`\n${title} (${list.length})`);
          for (const c of list.slice(0, 50)) io.out(`  ${c.run}${c.step !== null ? `#${c.step}` : ""}  ${c.tool}  ${c.before} -> ${c.after}  ${c.reasons[0] ?? ""}`);
        };
        show("newly blocked", rep.newly_blocked);
        show("newly needing approval", rep.newly_needs_approval);
        show("newly allowed", rep.newly_allowed);
        for (const n of rep.notes) io.out(`note: ${n}`);
        if (rep.newly_blocked.length) ctx.code = 2;
      }),
    );

  ctx
    .dataOpts(
      program
        .command("replay <run_id>")
        .description("replay one captured run in a sandbox, once as recorded and once with changes, and compare")
        .option("--set <change>", "change an argument: 1.amount=9000, tool:pay.charge/amount=9000, amount=9000 (repeatable)", (v: string, prev: string[] = []) => [...prev, v])
        .option("--policy <file>", "also try a different policy")
        .option("--json"),
    )
    .action((id: string, o: EngineFlags & { set?: string[]; json?: boolean }) =>
      ctx.withEngine(o, async (e) => {
        if (!e.capture) throw new Fail("replay needs captured calls: turn capture on first");
        const records = e.capture.list({ run_id: id });
        if (!records.length) throw new Fail(`nothing captured for run ${id} (captures expire; capture must have been on)`);
        const policy = loadPolicyDoc(ctx, o.policy, {}) ?? undefined;
        const rep = await replayRun(records, { registry: e.registry, policy, environment: e.reversi.environment }, (o.set ?? []).map(parseChange));
        if (o.json) return io.out(JSON.stringify(rep, null, 2));
        io.out(`run ${id}: ${records.length} captured calls`);
        for (const [i, v] of rep.variant.entries()) {
          const b = rep.baseline[i];
          io.out(`  ${i}  ${v.tool.padEnd(28)} as recorded: ${b?.verdict}   with your changes: ${v.verdict}${v.verdict !== "allow" ? `  (${v.reasons[0] ?? ""})` : ""}`);
        }
        io.out(rep.differences.length ? `${rep.differences.length} decision${rep.differences.length === 1 ? "" : "s"} would change` : "no decision would change");
        io.out(`rollback as recorded: ${rep.baseline_plan?.fully_reversible ? "fully reversible" : "not fully reversible"}; with changes: ${rep.variant_plan?.fully_reversible ? "fully reversible" : "not fully reversible"}`);
      }),
    );

  ctx
    .dataOpts(program.command("speculate <plans>").description("compare alternative plans without running them: decisions, approvals, risk, residue and rollback for each").option("--policy <file>").option("--actor <name>").option("--json"))
    .action((file: string, o: EngineFlags & { actor?: string; json?: boolean }) =>
      ctx.withEngine(o, async (e) => {
        const doc = ctx.readDoc(file) as { plans?: PlanInput[] } | PlanInput[];
        const plans = Array.isArray(doc) ? doc : doc.plans;
        if (!plans?.length) throw new Fail(`${file}: expected a list of plans, each with a name and a list of calls`);
        const policy = loadPolicyDoc(ctx, o.policy, {}) ?? undefined;
        const rep = await speculate(plans, { registry: e.registry, policy, environment: e.reversi.environment }, { actor: o.actor });
        if (o.json) return io.out(JSON.stringify(rep, null, 2));
        for (const p of rep.plans) {
          io.out(`${p.name}${p.name === rep.recommended ? "   <- recommended" : ""}`);
          io.out(`  ${p.blocked_at !== undefined ? `blocked at call ${p.blocked_at}: ${p.steps[p.blocked_at]?.reasons[0]}` : "can run to the end"}; approvals needed: ${p.approvals_needed}; highest risk: ${p.max_risk}; ${p.fully_reversible ? "fully reversible" : "NOT fully reversible"}`);
          if (p.irreversible.length) io.out(`  irreversible: ${p.irreversible.join(", ")}`);
          if (p.residue.length) io.out(`  leaves behind: ${p.residue.join("; ")}`);
          for (const n of p.notes) io.out(`  note: ${n}`);
        }
        if (!rep.recommended) io.out("no plan can run to the end");
      }),
    );

  ctx
    .dataOpts(program.command("impact <tool>").description("what approving a call to this tool would do and what could be undone").option("--args <json>", "the call's arguments").option("--policy <file>").option("--actor <name>").option("--json"))
    .action((tool: string, o: EngineFlags & { args?: string; actor?: string; json?: boolean }) =>
      ctx.withEngine(o, async (e) => {
        let args: unknown;
        if (o.args) {
          try {
            args = JSON.parse(o.args);
          } catch {
            throw new Fail("--args must be JSON");
          }
        }
        const policy = loadPolicyDoc(ctx, o.policy, {}) ?? undefined;
        const p = await previewImpact({ registry: e.registry, policy, environment: e.reversi.environment }, { tool, args, actor: o.actor });
        if (o.json) return io.out(JSON.stringify(p, null, 2));
        io.out(`${p.tool}: ${p.known ? p.effect : "no manifest"}${p.status && p.status !== "approved" ? ` (${p.status})` : ""}`);
        io.out(`decision now: ${p.verdict}${p.reasons.length ? `  (${p.reasons[0]})` : ""}`);
        if (p.risk_score) io.out(`risk ${p.risk_score.score}: ${p.risk_score.factors.join(", ") || "no factors"}`);
        if (p.risk) io.out(`data class ${p.risk.data_class ?? "?"}, blast radius ${p.risk.blast_radius ?? "?"}${p.owner ? `, owner ${p.owner}` : ""}`);
        if (p.requires.length) io.out(`needs first: ${p.requires.join(", ")}`);
        if (p.approval) io.out(`approvers: ${p.approval.roles.join(" or ") || "any"}, ${p.approval.quorum} needed`);
        for (const l of p.rollback_outlook) io.out(`rollback: ${l}`);
        for (const w of p.warnings) io.out(`warning: ${w}`);
      }),
    );

  void readFileSync;
  void parsePolicy;
}
