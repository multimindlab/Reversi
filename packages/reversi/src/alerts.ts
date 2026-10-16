/**
 * Alerts: conditions worth a human's attention, computed from the ledger, approvals and health. `evaluateAlerts` is pure
 * (the console shows its result live); the {@link AlertManager} sends each alert once, reminds while it persists, and
 * resolves it when the condition clears, sharing its state through the KV store so several processes do not repeat it.
 */
import type { Approvals } from "./approvals.js";
import type { Notifier, Severity } from "./channels.js";
import type { Reversi } from "./engine.js";
import type { KvStore } from "./kv.js";

export interface Alert {
  id: string;
  kind: string;
  severity: Severity;
  title: string;
  detail: string;
  ts_ms: number;
  run_id?: string;
}

export interface AlertOptions {
  now?: number;
  /** How far back event-based alerts look. Default 15 minutes. */
  window_ms?: number;
  /** Blocked calls in the window that count as a spike. Default 10. */
  denial_spike?: number;
  /** A step whose outcome has been unknown this long is flagged. Default 1 hour. */
  unresolved_ms?: number;
  /** Upstream health (the gateway supplies it). */
  health?: Array<{ name: string; ok: boolean }>;
}

export function evaluateAlerts(rv: Reversi, approvals: Approvals | undefined, o: AlertOptions = {}): Alert[] {
  const now = o.now ?? Date.now();
  const since = now - (o.window_ms ?? 900_000);
  const out = new Map<string, Alert>();
  const add = (a: Alert) => {
    if (!out.has(a.id)) out.set(a.id, a);
  };

  let denials = 0;
  for (const r of rv.ledger.records()) {
    if (r.ts_ms < since) continue;
    if (r.event === "blocked") denials++;
    if (r.event === "verification_failed") add({ id: `verify:${r.run_id}:${r.step}`, kind: "verification_failed", severity: "critical", title: `Undo not verified: ${r.tool}`, detail: r.detail, ts_ms: r.ts_ms, run_id: r.run_id });
    if (r.event === "unverified") add({ id: `unverified:${r.run_id}:${r.step}`, kind: "rollback_unverified", severity: "warning", title: `Undo could not be verified: ${r.tool}`, detail: r.detail, ts_ms: r.ts_ms, run_id: r.run_id });
    if (r.event === "succeeded" && rv.registry.get(r.tool)?.effect === "irreversible") add({ id: `irreversible:${r.run_id}:${r.step}`, kind: "irreversible_executed", severity: "warning", title: `Irreversible action executed: ${r.tool}`, detail: `${r.actor} in run ${r.run_id}`, ts_ms: r.ts_ms, run_id: r.run_id });
    if ((r.event === "blocked" || r.event === "would_block") && /no manifest registered/.test(r.detail) && !rv.registry.has(r.tool)) add({ id: `unclassified:${r.tool}`, kind: "unclassified_mutation", severity: "warning", title: `Unclassified tool called: ${r.tool}`, detail: `${r.actor} (${r.event})`, ts_ms: r.ts_ms, run_id: r.run_id });
    const budget = /budget `([^`]+)` at (\d+)%/.exec(r.detail);
    if (budget) add({ id: `budget:${budget[1]}`, kind: "budget_threshold", severity: Number(budget[2]) >= 100 ? "critical" : "warning", title: `Budget ${budget[1]} at ${budget[2]}%`, detail: r.detail, ts_ms: r.ts_ms, run_id: r.run_id });
    if (r.event === "approved" && r.detail.startsWith("BREAK-GLASS")) add({ id: `breakglass:${r.seq}`, kind: "break_glass", severity: "critical", title: `Break-glass approval for ${r.tool}`, detail: `${r.actor}: ${r.reason}`, ts_ms: r.ts_ms, run_id: r.run_id });
  }
  if (denials >= (o.denial_spike ?? 10)) add({ id: "denial-spike", kind: "policy_denial_spike", severity: "warning", title: `${denials} calls blocked in the last ${Math.round((o.window_ms ?? 900_000) / 60_000)} minutes`, detail: "An agent may be looping or probing. Check the blocked reasons in the ledger.", ts_ms: now });

  for (const id of rv.runIds()) {
    const st = rv.openRun(id).state();
    for (const s of st.steps) {
      if (s.status === "compensation_failed") add({ id: `comp:${id}:${s.step}`, kind: "compensation_failed", severity: "critical", title: `Rollback failed: ${s.tool} in ${id}`, detail: s.error ?? "", ts_ms: s.ts_ms, run_id: id });
      if ((s.status === "intended" || s.status === "uncertain") && now - s.ts_ms > (o.unresolved_ms ?? 3_600_000)) add({ id: `stuck:${id}:${s.step}`, kind: "unresolved_outcome", severity: "warning", title: `Outcome still unknown: ${s.tool} in ${id}`, detail: `step ${s.step} has been ${s.status} for over ${Math.round((now - s.ts_ms) / 60_000)} minutes; check the downstream system and resolve it`, ts_ms: s.ts_ms, run_id: id });
    }
  }

  for (const a of approvals?.list() ?? []) {
    if ((a.status === "expired" || a.escalated) && a.requested_ms >= since - (a.ttl_ms ?? 0)) add({ id: `approval-timeout:${a.id}`, kind: "approval_timeout", severity: "warning", title: `Approval ${a.status === "expired" ? "expired unanswered" : "escalated"}: ${a.tool}`, detail: `run ${a.run_id}, requested by ${a.requested_by ?? "unknown"}`, ts_ms: a.expires_ms, run_id: a.run_id });
  }
  for (const h of o.health ?? []) if (!h.ok) add({ id: `upstream:${h.name}`, kind: "upstream_unhealthy", severity: "critical", title: `Upstream ${h.name} is not answering`, detail: "The gateway cannot reach it; calls to its tools will fail.", ts_ms: now });
  for (const h of rv.halts()) add({ id: `halt:${h.id}`, kind: "halted", severity: "warning", title: "New calls are blocked", detail: `${h.reason}${Object.keys(h.scope).length ? ` (scope: ${Object.entries(h.scope).map(([k, v]) => `${k}=${v}`).join(", ")})` : ""}`, ts_ms: h.ts_ms });
  return [...out.values()].sort((a, b) => (a.severity === b.severity ? b.ts_ms - a.ts_ms : a.severity === "critical" ? -1 : b.severity === "critical" ? 1 : 0));
}

interface AlertState {
  active: boolean;
  first_ms: number;
  last_notified_ms: number;
  title: string;
}

const NS = "alert-state";

export class AlertManager {
  constructor(
    private readonly rv: Reversi,
    private readonly approvals: Approvals | undefined,
    private readonly kv: KvStore,
    private readonly notifier: Notifier,
    private readonly o: AlertOptions & { remind_ms?: number; console_url?: string; health?: () => Promise<Array<{ name: string; ok: boolean }>> } = {},
  ) {}

  private timer: NodeJS.Timeout | undefined;

  start(intervalMs = 60_000): void {
    this.stop();
    this.timer = setInterval(() => void this.tick().catch(() => {}), intervalMs);
    this.timer.unref();
  }
  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /** Evaluate once: notify new alerts (and reminders), resolve cleared ones. Returns what was sent. */
  async tick(now = Date.now()): Promise<{ fired: string[]; resolved: string[] }> {
    const health = this.o.health ? await this.o.health().catch(() => undefined) : this.o.health;
    const alerts = evaluateAlerts(this.rv, this.approvals, { ...this.o, now, health: Array.isArray(health) ? health : undefined });
    const remind = this.o.remind_ms ?? 3_600_000;
    const fired: string[] = [];
    const resolved: string[] = [];
    const live = new Set(alerts.map((a) => a.id));
    for (const a of alerts) {
      const cur = this.kv.get<AlertState>(NS, a.id);
      let send = false;
      if (!cur) send = this.kv.cas(NS, a.id, { active: true, first_ms: now, last_notified_ms: now, title: a.title }, 0);
      else if (!cur.value.active) send = this.kv.cas(NS, a.id, { active: true, first_ms: now, last_notified_ms: now, title: a.title }, cur.version);
      else if (now - cur.value.last_notified_ms >= remind) send = this.kv.cas(NS, a.id, { ...cur.value, last_notified_ms: now }, cur.version);
      if (send) {
        fired.push(a.id);
        await this.notifier.notify({ event: "alert", severity: a.severity, title: a.title, text: a.detail, dedup_key: a.id, data: { kind: a.kind, run_id: a.run_id }, link: this.o.console_url ? `${this.o.console_url.replace(/\/$/, "")}/console/alerts` : undefined });
      }
    }
    for (const e of this.kv.list<AlertState>(NS)) {
      if (e.value.active && !live.has(e.key) && this.kv.cas(NS, e.key, { ...e.value, active: false }, e.version)) {
        resolved.push(e.key);
        await this.notifier.notify({ event: "alert", severity: "info", title: `Resolved: ${e.value.title}`, text: "The condition has cleared.", dedup_key: e.key, resolve: true });
      }
    }
    return { fired, resolved };
  }
}
