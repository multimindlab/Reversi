/**
 * Retention and legal hold.
 *
 * The ledger is append-only and holds only hashes, reasons and details, so it is never purged. What retention removes
 * is the working data around a run: its run state, its approval requests and its captured (redacted) arguments. A legal
 * hold stops that for the runs it covers, and a manifest can require an evidence bundle to be archived first.
 */
import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Approvals } from "./approvals.js";
import type { CaptureStore } from "./capture.js";
import type { Reversi } from "./engine.js";
import { createBundle, type SigningKey } from "./evidence.js";
import { globAny } from "./glob.js";
import type { KvStore } from "./kv.js";
import type { RunState } from "./store.js";

export interface HoldScope {
  run_id?: string;
  tenant?: string;
  actor?: string;
  tool?: string;
}
export interface Hold {
  id: string;
  scope: HoldScope;
  reason: string;
  by: string;
  ts_ms: number;
  released_ms?: number;
}

const NS = "holds";

export class LegalHolds {
  constructor(
    private readonly kv: KvStore,
    private readonly now: () => number = Date.now,
  ) {}

  add(scope: HoldScope, reason: string, by: string): Hold {
    if (!Object.values(scope).some(Boolean)) throw new Error("a legal hold needs a scope: a run, tenant, actor or tool");
    if (reason.trim().length < 5) throw new Error("a legal hold needs a reason (case or matter reference)");
    const h: Hold = { id: `hold_${randomUUID()}`, scope, reason, by, ts_ms: this.now() };
    this.kv.put(NS, h.id, h);
    return h;
  }

  release(id: string): boolean {
    const e = this.kv.get<Hold>(NS, id);
    if (!e || e.value.released_ms) return false;
    this.kv.put(NS, id, { ...e.value, released_ms: this.now() });
    return true;
  }

  list(opts: { all?: boolean } = {}): Hold[] {
    return this.kv.list<Hold>(NS).map((e) => e.value).filter((h) => opts.all || !h.released_ms);
  }

  /** The hold that covers this run, if any. */
  coverOf(run: RunState): Hold | undefined {
    return this.list().find((h) => {
      const s = h.scope;
      return (!s.run_id || s.run_id === run.run_id) && (!s.tenant || s.tenant === run.tenant) && (!s.actor || s.actor === run.actor) && (!s.tool || run.steps.some((x) => x.tool === s.tool));
    });
  }
}

export interface RetentionConfig {
  default_days: number;
  rules: Array<{ match: { tool?: string; tenant?: string; environment?: string; data_class?: string }; days: number }>;
}

export function parseRetention(raw: unknown, errors: string[]): RetentionConfig | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    errors.push("`retention` must be an object");
    return undefined;
  }
  const r = raw as Record<string, unknown>;
  for (const k of Object.keys(r)) if (!["default_days", "rules"].includes(k)) errors.push(`retention: unknown field \`${k}\``);
  if (typeof r.default_days !== "number" || !Number.isInteger(r.default_days) || r.default_days < 1) errors.push("retention.default_days must be a positive integer");
  const rules = Array.isArray(r.rules) ? r.rules : r.rules === undefined ? [] : (errors.push("retention.rules must be a list"), []);
  rules.forEach((x: unknown, i: number) => {
    const o = x as { match?: Record<string, unknown>; days?: unknown };
    if (!o || typeof o.match !== "object" || o.match === null) errors.push(`retention.rules[${i}]: match is required`);
    else for (const k of Object.keys(o.match)) if (!["tool", "tenant", "environment", "data_class"].includes(k)) errors.push(`retention.rules[${i}]: unknown match field \`${k}\``);
    if (!Number.isInteger(o?.days) || (o.days as number) < 1) errors.push(`retention.rules[${i}]: days must be a positive integer`);
  });
  return { default_days: r.default_days as number, rules: rules as RetentionConfig["rules"] };
}

/** How long to keep a run: the longest of its default, the matching rules and each tool's manifest `audit.retention_days`. */
export function retentionDays(state: RunState, rv: Reversi, cfg: RetentionConfig): number {
  let days = cfg.default_days;
  for (const s of state.steps) {
    const m = rv.registry.get(s.tool);
    days = Math.max(days, m?.audit?.retention_days ?? 0);
    for (const r of cfg.rules) {
      const x = r.match;
      if ((!x.tool || globAny(x.tool, s.tool)) && (!x.tenant || x.tenant === state.tenant) && (!x.environment || x.environment === rv.environment) && (!x.data_class || x.data_class === m?.risk?.data_class)) days = Math.max(days, r.days);
    }
  }
  return days;
}

export interface RetentionItem {
  run_id: string;
  age_days: number;
  retention_days: number;
  held?: Hold;
  due: boolean;
  needs_export: boolean;
}

export function planRetention(rv: Reversi, cfg: RetentionConfig, holds: LegalHolds | undefined, now = Date.now()): RetentionItem[] {
  return rv.runIds().flatMap((id) => {
    const st = rv.openRun(id).state();
    const age = (now - st.created_ms) / 86_400_000;
    const days = retentionDays(st, rv, cfg);
    return [
      {
        run_id: id,
        age_days: Math.floor(age),
        retention_days: days,
        held: holds?.coverOf(st),
        due: age >= days,
        needs_export: st.steps.some((s) => rv.registry.get(s.tool)?.audit?.evidence_export === "required"),
      },
    ];
  });
}

export interface RetentionReport {
  dry_run: boolean;
  purged: string[];
  skipped: Array<{ run_id: string; reason: string }>;
  exported: Array<{ run_id: string; file: string }>;
}

export function applyRetention(
  rv: Reversi,
  cfg: RetentionConfig,
  o: { holds?: LegalHolds; approvals?: Approvals; capture?: CaptureStore; dry_run?: boolean; archive_dir?: string; key?: SigningKey; now?: number; actor?: string },
): RetentionReport {
  const now = o.now ?? Date.now();
  const rep: RetentionReport = { dry_run: o.dry_run === true, purged: [], skipped: [], exported: [] };
  for (const item of planRetention(rv, cfg, o.holds, now)) {
    if (!item.due) continue;
    if (item.held) {
      rep.skipped.push({ run_id: item.run_id, reason: `legal hold ${item.held.id}: ${item.held.reason}` });
      continue;
    }
    const needExport = item.needs_export || (o.archive_dir !== undefined && o.key !== undefined);
    if (item.needs_export && (!o.archive_dir || !o.key)) {
      rep.skipped.push({ run_id: item.run_id, reason: "a manifest requires an evidence bundle before deletion; give an archive directory and a signing key" });
      continue;
    }
    let file: string | undefined;
    if (needExport && o.archive_dir && o.key && !o.dry_run) {
      mkdirSync(o.archive_dir, { recursive: true });
      const bundle = createBundle({ records: rv.ledger.forRun(item.run_id), ledger_head: rv.ledger.head(), run_id: item.run_id, key: o.key, now });
      file = join(o.archive_dir, `${item.run_id}.json`);
      writeFileSync(file, JSON.stringify(bundle, null, 2));
      rep.exported.push({ run_id: item.run_id, file });
    }
    if (!o.dry_run) {
      rv.runs.delete(item.run_id);
      for (const a of o.approvals?.list({ run_id: item.run_id }) ?? []) o.approvals?.store.delete(a.id);
      o.capture?.purge({ run_id: item.run_id });
      rv.ledger.append({
        ts_ms: now,
        run_id: item.run_id,
        actor: o.actor ?? "retention",
        tool: "-",
        reason: `retention: older than ${item.retention_days} days`,
        event: "purged",
        detail: `run state, approvals and captured data deleted${file ? `; evidence bundle archived at ${file}` : ""}`,
      });
    }
    rep.purged.push(item.run_id);
  }
  return rep;
}
