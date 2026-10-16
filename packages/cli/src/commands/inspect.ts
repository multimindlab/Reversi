/** Looking at what happened: runs, actions, ledger search, and the periodic report. */
import { writeFileSync } from "node:fs";
import type { Command } from "commander";
import {
  buildPeriodReport,
  parseDuration,
  renderPeriodHtml,
  renderPeriodMarkdown,
  searchRecords,
  searchRuns,
  type EngineHandle,
  type LedgerEvent,
  type RunStatus,
} from "@multimindlab/reversi";
import { Fail, type Ctx, type EngineFlags } from "../context.js";

/** "7d", "12h", "30m", an ISO date, or epoch ms -> a point in time. Durations count back from now. */
export function sinceMs(v: string | undefined, now = Date.now()): number | undefined {
  if (v === undefined) return undefined;
  const d = parseDuration(v);
  if (d !== undefined && /^\d+(\.\d+)?\s*(ms|s|m|h|d)$/.test(v.trim())) return now - d;
  const t = Date.parse(v);
  if (Number.isFinite(t)) return t;
  if (/^\d{10,}$/.test(v)) return Number(v);
  throw new Fail(`cannot read "${v}" as a time: use a duration like 7d, a date like 2026-10-01, or epoch milliseconds`);
}

const when = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 19) + "Z";

export function registerInspectCommands(program: Command, ctx: Ctx): void {
  const { io } = ctx;

  const runs = program.command("runs").description("list runs, or show one");
  ctx
    .dataOpts(
      runs
        .command("list", { isDefault: true })
        .description("list runs, newest last")
        .option("--actor <name>")
        .option("--tenant <name>")
        .option("--tool <name>")
        .option("--status <status>", "needs_attention | rolled_back | complete | blocked_only | empty")
        .option("--mode <mode>", "enforce | observe | advise")
        .option("--since <when>", "7d, 2026-10-01, ...")
        .option("--until <when>")
        .option("--text <text>", "part of the run id")
        .option("--limit <n>", "how many", "100")
        .option("--json", "machine-readable"),
    )
    .action((o: EngineFlags & Record<string, string | undefined> & { json?: boolean }) =>
      ctx.withEngine(o, (e) => {
        const r = searchRuns(e.reversi, { actor: o.actor, tenant: o.tenant, tool: o.tool, status: o.status as RunStatus | undefined, mode: o.mode, since_ms: sinceMs(o.since), until_ms: sinceMs(o.until), text: o.text, limit: Number(o.limit) });
        if (o.json) return io.out(JSON.stringify(r, null, 2));
        for (const s of r.runs) io.out(`${s.run_id}  actor=${s.actor}  mode=${s.mode}  steps=${s.steps}  ${s.status}${s.tenant ? `  tenant=${s.tenant}` : ""}${s.unresolved.length ? `  UNRESOLVED=${s.unresolved.join(",")}` : ""}`);
        if (r.next) io.out(`(more: --text or narrower filters; the next page starts after ${r.next})`);
      }),
    );

  ctx
    .dataOpts(runs.command("show <run_id>").description("one run: steps, rollback outlook, approvals and the event trail").option("--json"))
    .action((id: string, o: EngineFlags & { json?: boolean }) =>
      ctx.withEngine(o, (e) => {
        const run = e.reversi.openRun(id);
        const st = run.state();
        const plan = run.plan();
        const recs = e.reversi.ledger.forRun(id);
        const approvals = e.approvals.list({ run_id: id });
        if (o.json) return io.out(JSON.stringify({ state: st, plan, approvals, records: recs }, null, 2));
        io.out(`run ${id}  actor=${st.actor}  mode=${st.mode}${st.tenant ? `  tenant=${st.tenant}` : ""}  started ${when(st.created_ms)}`);
        io.out(`scope: ${st.scope.permissions.join(" ")}`);
        io.out("");
        io.out("steps");
        for (const s of st.steps) io.out(`  ${String(s.step).padStart(3)}  ${s.tool.padEnd(28)} ${(s.effect ?? "no manifest").padEnd(12)} ${s.status}${s.risk_score !== undefined ? `  risk ${s.risk_score}` : ""}${s.error ? `  error: ${s.error}` : ""}`);
        if (st.steps.length === 0) io.out("  (none)");
        io.out("");
        io.out(plan.fully_reversible ? "rollback: fully reversible (assuming each compensation succeeds)" : "rollback: NOT fully reversible");
        for (const a of plan.actions) io.out(`  step ${a.step}  ${a.tool}  ${a.kind}${a.compensation_tool ? ` -> ${a.compensation_tool}` : ""}${a.residue?.length ? `  (residue: ${a.residue.join("; ")})` : ""}${a.note ? `  ${a.note}` : ""}`);
        if (approvals.length) {
          io.out("");
          io.out("approvals");
          for (const a of approvals) io.out(`  ${a.id}  ${a.status}  ${a.kind} ${a.tool}  ${a.decided_by ? `by ${a.decided_by}` : "waiting"}${a.quorum && a.quorum > 1 ? `  (${(a.decisions ?? []).filter((d) => d.decision === "approve").length}/${a.quorum})` : ""}`);
        }
        io.out("");
        io.out("events");
        for (const r of recs) io.out(`  ${String(r.seq).padStart(5)}  ${when(r.ts_ms)}  ${r.event.padEnd(19)} ${r.tool}  by ${r.actor}${r.detail ? `  | ${r.detail.slice(0, 100)}` : ""}`);
      }),
    );

  const actions = program.command("actions").description("individual tool calls across runs");
  ctx
    .dataOpts(
      actions
        .command("list", { isDefault: true })
        .description("steps across runs")
        .option("--run <id>")
        .option("--tool <name>")
        .option("--actor <name>")
        .option("--status <status>", "succeeded | failed | uncertain | intended | compensated | ...")
        .option("--since <when>")
        .option("--limit <n>", "how many", "200")
        .option("--json"),
    )
    .action((o: EngineFlags & Record<string, string | undefined> & { json?: boolean }) =>
      ctx.withEngine(o, (e) => {
        const since = sinceMs(o.since);
        const rows: Array<{ run: string; step: number; tool: string; actor: string; effect: string | null; status: string; ts_ms: number; risk?: number }> = [];
        for (const id of o.run ? [o.run] : e.reversi.runIds().sort()) {
          const st = e.reversi.openRun(id).state();
          if (o.actor && st.actor !== o.actor) continue;
          for (const s of st.steps) if ((!o.tool || s.tool === o.tool) && (!o.status || s.status === o.status) && (!since || s.ts_ms >= since)) rows.push({ run: id, step: s.step, tool: s.tool, actor: st.actor, effect: s.effect, status: s.status, ts_ms: s.ts_ms, risk: s.risk_score });
        }
        const out = rows.sort((a, b) => a.ts_ms - b.ts_ms).slice(-Number(o.limit));
        if (o.json) return io.out(JSON.stringify(out, null, 2));
        for (const r of out) io.out(`${when(r.ts_ms)}  ${r.run}#${r.step}  ${r.tool.padEnd(28)} ${(r.effect ?? "no manifest").padEnd(12)} ${r.status.padEnd(18)} ${r.actor}${r.risk !== undefined ? `  risk ${r.risk}` : ""}`);
        if (out.length === 0) io.out("no matching actions");
      }),
    );
  ctx
    .dataOpts(actions.command("show <run_id> <step>").description("one call: its state, its ledger records and, if capture is on, its redacted arguments").option("--json"))
    .action((id: string, step: string, o: EngineFlags & { json?: boolean }) =>
      ctx.withEngine(o, (e) => {
        const n = Number(step);
        const st = e.reversi.openRun(id).state();
        const s = st.steps.find((x) => x.step === n);
        if (!s) throw new Fail(`run ${id} has no step ${step}`);
        const recs = e.reversi.ledger.forRun(id).filter((r) => r.step === n);
        const cap = e.capture?.get(id, n);
        const approvals = e.approvals.list({ run_id: id }).filter((a) => a.tool === s.tool || a.tool === s.compensation_tool);
        if (o.json) return io.out(JSON.stringify({ step: s, records: recs, captured: cap, approvals }, null, 2));
        io.out(`${id} step ${n}: ${s.tool}  [${s.effect ?? "no manifest"}]  ${s.status}${s.error ? `  error: ${s.error}` : ""}`);
        io.out(`why: ${s.reason}`);
        if (s.manifest_version) io.out(`manifest v${s.manifest_version}${s.risk_score !== undefined ? `, risk ${s.risk_score}` : ""}`);
        if (s.compensation_tool) io.out(`undo: ${s.compensation_tool} (${s.compensation_kind ?? "compensation"})${s.residue?.length ? `; leaves: ${s.residue.join("; ")}` : ""}${s.verification ? `; verified by reading ${s.verification.tool}` : ""}`);
        if (s.handle) io.out(`undo arguments: ${JSON.stringify(s.handle)}`);
        if (s.result_hash) io.out(`result hash: ${s.result_hash}`);
        io.out(cap ? `captured arguments (redacted): ${JSON.stringify(cap.args)}` : "arguments are not stored (only their hash is in the ledger); turn on capture to keep redacted copies");
        for (const r of recs) io.out(`  ${String(r.seq).padStart(5)}  ${when(r.ts_ms)}  ${r.event.padEnd(19)} by ${r.actor}${r.detail ? `  | ${r.detail}` : ""}`);
        for (const a of approvals) io.out(`  approval ${a.id}: ${a.status}${a.decided_by ? ` by ${a.decided_by}` : ""}`);
      }),
    );

  ctx
    .storeOpts(
      program
        .command("search")
        .description("search ledger records")
        .option("-m, --manifests <path>", "(only needed to label tools)")
        .option("--run <id>")
        .option("--actor <name>")
        .option("--tool <name>")
        .option("--event <event>", "one event name, or several separated by commas")
        .option("--text <text>", "words in the reason or detail")
        .option("--since <when>")
        .option("--until <when>")
        .option("--limit <n>", "how many", "200")
        .option("--json"),
    )
    .action((o: EngineFlags & Record<string, string | undefined> & { json?: boolean }) =>
      ctx.withEngine({ ...o, manifests: o.manifests ?? ctx.project(o)?.manifests ?? process.env.REVERSI_MANIFESTS }, (e) => {
        const r = searchRecords(e.reversi, { run_id: o.run, actor: o.actor, tool: o.tool, event: o.event ? (o.event.split(",") as LedgerEvent[]) : undefined, text: o.text, since_ms: sinceMs(o.since), until_ms: sinceMs(o.until), limit: Number(o.limit) });
        if (o.json) return io.out(JSON.stringify(r.records, null, 2));
        for (const x of r.records) io.out(`${String(x.seq).padStart(6)}  ${when(x.ts_ms)}  ${x.run_id}${x.step !== null ? `#${x.step}` : ""}  ${x.event.padEnd(19)} ${x.tool}  ${x.actor}${x.detail ? `  | ${x.detail.slice(0, 90)}` : ""}`);
        if (r.records.length === 0) io.out("no matching records");
      }),
    );

  // the periodic report is `reversi report` with no run id
  void ((e: EngineHandle) => e);
}

export async function periodReportCommand(ctx: Ctx, o: EngineFlags & { since?: string; format?: string; out?: string }): Promise<void> {
  await ctx.withEngine(o, (e) => {
    const from = sinceMs(o.since ?? "7d") as number;
    const rep = buildPeriodReport(e.reversi, e.approvals, from);
    const fmt = o.format ?? (o.out?.endsWith(".html") ? "html" : o.out?.endsWith(".json") ? "json" : "md");
    const text = fmt === "json" ? JSON.stringify(rep, null, 2) : fmt === "html" ? renderPeriodHtml(rep) : renderPeriodMarkdown(rep);
    if (o.out) {
      writeFileSync(o.out, text);
      ctx.io.out(`wrote ${o.out}`);
    } else ctx.io.out(text.replace(/\n$/, ""));
  });
}
