/** Retention, legal holds, anchoring, delegation, break-glass and scoped halts. */
import { readFileSync, writeFileSync } from "node:fs";
import type { Command } from "commander";
import {
  Ledger,
  anchorLedger,
  applyRetention,
  planRetention,
  readAnchors,
  verifyAnchor,
  type HoldScope,
  type RetentionConfig,
  type SigningKey,
} from "@multimindlab/reversi";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { Fail, type Ctx, type EngineFlags } from "../context.js";

function key(path: string | undefined): SigningKey | undefined {
  if (!path) return undefined;
  const private_pem = readFileSync(path, "utf8");
  return { private_pem, public_pem: createPublicKey(createPrivateKey(private_pem)).export({ type: "spki", format: "pem" }).toString() };
}

export function registerGovernanceCommands(program: Command, ctx: Ctx): void {
  const { io } = ctx;

  // ---- retention ----
  const retention = program.command("retention").description("delete run data past its retention period (the ledger itself is never deleted)");
  const retentionConfig = async (e: Awaited<ReturnType<Ctx["engine"]>>, days?: string): Promise<RetentionConfig> => {
    if (days) return { default_days: Number(days), rules: [] };
    const { loadPolicyFile } = await import("@multimindlab/reversi");
    const p = e.config.policy;
    const doc = p ? (await import("node:fs")).statSync(p).isFile() ? loadPolicyFile(p).doc : undefined : undefined;
    if (!doc?.retention) throw new Fail("no retention settings: add a `retention:` section to the policy file, or pass --days");
    return doc.retention;
  };
  ctx.dataOpts(retention.command("plan").description("which runs are due for deletion, and which are held").option("--days <n>", "use this retention instead of the policy's")).action((o: EngineFlags & { days?: string }) =>
    ctx.withEngine(o, async (e) => {
      const cfg = await retentionConfig(e, o.days);
      const plan = planRetention(e.reversi, cfg, e.holds);
      for (const p of plan) io.out(`${p.run_id}  ${p.age_days}d old  keep ${p.retention_days}d  ${p.held ? `HELD (${p.held.reason})` : p.due ? (p.needs_export ? "due; needs an evidence bundle first" : "due") : "keep"}`);
      if (!plan.length) io.out("no runs");
    }),
  );
  ctx
    .dataOpts(retention.command("apply").description("delete run state, approvals and captures for runs past retention").option("--days <n>").option("--dry-run").option("--archive-dir <dir>", "write a signed evidence bundle for each run before deleting it").option("--key <file>", "signing key for the bundles"))
    .action((o: EngineFlags & { days?: string; dryRun?: boolean; archiveDir?: string; key?: string }) =>
      ctx.withEngine(o, async (e) => {
        const cfg = await retentionConfig(e, o.days);
        const r = applyRetention(e.reversi, cfg, { holds: e.holds, approvals: e.approvals, capture: e.capture, dry_run: o.dryRun, archive_dir: o.archiveDir, key: key(o.key) ?? e.signing_key, actor: "cli" });
        io.out(`${o.dryRun ? "would delete" : "deleted"}: ${r.purged.join(", ") || "nothing"}`);
        for (const x of r.exported) io.out(`archived ${x.run_id} -> ${x.file}`);
        for (const s of r.skipped) io.out(`kept ${s.run_id}: ${s.reason}`);
      }),
    );

  // ---- legal hold ----
  const hold = program.command("hold").description("legal holds: stop retention from deleting runs");
  ctx.dataOpts(hold.command("add").description("hold runs matching a scope").option("--run <id>").option("--tenant <name>").option("--actor <name>").option("--tool <name>").requiredOption("--reason <text>", "the case or matter").option("--by <name>", "who", "cli")).action((o: EngineFlags & HoldScope & { reason: string; by: string; run?: string }) =>
    ctx.withEngine(o, (e) => {
      const h = e.holds.add({ run_id: o.run, tenant: o.tenant, actor: o.actor, tool: o.tool }, o.reason, o.by);
      io.out(`${h.id}  holding ${Object.entries(h.scope).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(", ")}`);
    }),
  );
  ctx.dataOpts(hold.command("list").description("active holds").option("--all", "include released ones")).action((o: EngineFlags & { all?: boolean }) =>
    ctx.withEngine(o, (e) => {
      for (const h of e.holds.list({ all: o.all })) io.out(`${h.id}  ${Object.entries(h.scope).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(", ")}  ${h.reason}  by ${h.by}${h.released_ms ? "  RELEASED" : ""}`);
    }),
  );
  ctx.dataOpts(hold.command("release <id>")).action((id: string, o: EngineFlags) =>
    ctx.withEngine(o, (e) => {
      if (!e.holds.release(id)) throw new Fail(`no active hold ${id}`);
      io.out(`released ${id}`);
    }),
  );

  // ---- anchors ----
  const anchor = program.command("anchor").description("publish the ledger head somewhere you control, and prove later that history is unchanged");
  ctx
    .dataOpts(anchor.command("publish").description("write the current head to the sinks in the config (or --file / --webhook)").option("--file <path>", "append to this file").option("--webhook <url>").option("--secret <s>", "sign the webhook body with this secret").option("--key <file>", "sign the anchor"))
    .action((o: EngineFlags & { file?: string; webhook?: string; secret?: string; key?: string }) =>
      ctx.withEngine(o, async (e) => {
        const sinks = [...(o.file ? [{ type: "file" as const, path: o.file }] : []), ...(o.webhook ? [{ type: "webhook" as const, url: o.webhook, secret: o.secret }] : []), ...(!o.file && !o.webhook ? (e.config.anchor?.sinks ?? []) : [])];
        if (!sinks.length) throw new Fail("no anchor sinks: pass --file or --webhook, or add `anchor:` to reversi.config.yaml");
        const r = await anchorLedger(e.reversi.ledger, sinks, { key: key(o.key) ?? e.signing_key, egress: e.egress });
        io.out(`anchored ${r.anchor.records} records, head ${r.anchor.head.slice(0, 16)}…${r.anchor.signature ? " (signed)" : ""}`);
        for (const d of r.delivered) io.out(`  delivered to ${d}`);
        for (const x of r.errors) io.err(`  FAILED ${x}`);
        if (r.errors.length) ctx.code = 1;
      }),
    );
  ctx
    .dataOpts(anchor.command("verify <file>").description("check every anchor in a file against the ledger").option("--pub <pem>", "trusted public key the anchors must be signed by"))
    .action((file: string, o: EngineFlags & { pub?: string }) =>
      ctx.withEngine(o, (e) => {
        const ledger: Ledger = e.reversi.ledger;
        const anchors = readAnchors(file);
        if (!anchors.length) throw new Fail(`no anchors in ${file}`);
        let bad = 0;
        for (const a of anchors) {
          const r = verifyAnchor(ledger, a, o.pub ? readFileSync(o.pub, "utf8") : undefined);
          io.out(`${new Date(a.ts_ms).toISOString().slice(0, 19)}Z  ${a.records} records  ${r.ok ? `ok${r.signed ? " (signature trusted)" : ""}` : `FAIL: ${r.error}`}`);
          if (!r.ok) bad++;
        }
        if (bad) ctx.code = 1;
      }),
    );

  // ---- delegation ----
  const delegate = program.command("delegate").description("hand your approval authority to someone for a while");
  ctx.dataOpts(delegate.command("add").requiredOption("--from <name>").requiredOption("--to <name>").requiredOption("--hours <n>").requiredOption("--reason <text>").option("--group <name>", "only this group (repeatable)", (v: string, p: string[] = []) => [...p, v])).action((o: EngineFlags & { from: string; to: string; hours: string; reason: string; group?: string[] }) =>
    ctx.withEngine(o, (e) => {
      const d = e.delegations.grant({ from: o.from, to: o.to, until_ms: Date.now() + Number(o.hours) * 3_600_000, reason: o.reason, groups: o.group });
      io.out(`${d.id}  ${d.from} -> ${d.to} until ${new Date(d.until_ms).toISOString().slice(0, 16)}Z`);
    }),
  );
  ctx.dataOpts(delegate.command("list")).action((o: EngineFlags) => ctx.withEngine(o, (e) => {
    for (const d of e.delegations.list()) io.out(`${d.id}  ${d.from} -> ${d.to}  until ${new Date(d.until_ms).toISOString().slice(0, 16)}Z  ${d.revoked ? "REVOKED" : d.until_ms < Date.now() ? "expired" : "active"}  ${d.reason}`);
  }));
  ctx.dataOpts(delegate.command("revoke <id>")).action((id: string, o: EngineFlags) => ctx.withEngine(o, (e) => {
    if (!e.delegations.revoke(id)) throw new Fail(`no delegation ${id}`);
    io.out(`revoked ${id}`);
  }));

  // ---- break-glass ----
  ctx
    .dataOpts(program.command("break-glass <approval_id>").description("emergency override of a pending approval: needs a real reason and a reference to the evidence, and is recorded as such").requiredOption("--reason <text>", "at least 10 characters").requiredOption("--evidence <ref>", "ticket or incident").option("--by <name>", "who", "cli"))
    .action((id: string, o: EngineFlags & { reason: string; evidence: string; by: string }) =>
      ctx.withEngine(o, (e) => {
        const r = e.approvals.breakGlass(id, o.by, { reason: o.reason, evidence: o.evidence }, { roles: ["admin"], groups: [] });
        io.out(`${r.id} approved by break-glass (${o.by}); evidence ${o.evidence}`);
      }),
    );

  // ---- halts ----
  const halt = program.command("halt").description("scoped kill switches (shared by every process using the same data store)");
  ctx
    .dataOpts(halt.command("add <reason>").description("block new calls, everywhere or narrowed by tool, actor, tenant or environment").option("--tool <glob>").option("--actor <glob>").option("--tenant <glob>").option("--environment <glob>").option("--by <name>", "who", "cli"))
    .action((reason: string, o: EngineFlags & { tool?: string; actor?: string; tenant?: string; environment?: string; by: string }) =>
      ctx.withEngine(o, (e) => {
        const h = e.reversi.halt(reason, { tool: o.tool, actor: o.actor, tenant: o.tenant, environment: o.environment } as never, o.by);
        io.out(`${h.id}  ${reason}${Object.keys(h.scope).length ? `  (${JSON.stringify(h.scope)})` : "  (everything)"}`);
      }),
    );
  ctx.dataOpts(halt.command("list")).action((o: EngineFlags) => ctx.withEngine(o, (e) => {
    for (const h of e.reversi.halts()) io.out(`${h.id}  ${h.reason}  scope=${JSON.stringify(h.scope)}  by ${h.by}`);
    if (!e.reversi.halts().length) io.out("no halts");
  }));
  ctx.dataOpts(halt.command("lift [id]").description("lift one halt, or all of them")).action((id: string | undefined, o: EngineFlags) => ctx.withEngine(o, (e) => {
    io.out(`lifted ${e.reversi.resume(id)}`);
  }));

  void writeFileSync;
}
