/**
 * OpenTelemetry trace export (OTLP over HTTP/JSON, no SDK). Each tool call becomes a span from its journaled intent to
 * its outcome, each compensation a span from `compensating` to its result, and blocked calls become short error spans.
 * Spans carry names and ids, never arguments or results. Point `endpoint` at a collector (`http://collector:4318`).
 */
import { createHash } from "node:crypto";
import type { Reversi } from "./engine.js";
import { guardedFetch, type EgressConfig } from "./egress.js";
import type { LedgerRecord } from "./ledger.js";

type AttrValue = { stringValue: string } | { intValue: string } | { boolValue: boolean };
interface Span {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  kind: number;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: Array<{ key: string; value: AttrValue }>;
  status: { code: number; message?: string };
}

const hex = (s: string, bytes: number) => createHash("sha256").update(s).digest("hex").slice(0, bytes * 2);
const nano = (ms: number) => String(BigInt(ms) * 1_000_000n);
const attr = (key: string, v: string | number | boolean | null | undefined): { key: string; value: AttrValue } | null =>
  v === null || v === undefined ? null : { key, value: typeof v === "boolean" ? { boolValue: v } : typeof v === "number" ? { intValue: String(Math.trunc(v)) } : { stringValue: String(v).slice(0, 500) } };

export interface OtelOptions {
  /** Base URL of an OTLP/HTTP collector; spans go to `<endpoint>/v1/traces`. */
  endpoint: string;
  headers?: Record<string, string>;
  service_name?: string;
  service_version?: string;
  environment?: string;
  egress?: EgressConfig;
  fetch?: typeof fetch;
  /** Send when this many spans are waiting (default 50) or every `interval_ms` (default 5000). */
  batch?: number;
  interval_ms?: number;
  onError?: (e: Error) => void;
}

export class OtelExporter {
  private readonly pending: Span[] = [];
  private readonly open = new Map<string, LedgerRecord>();
  private timer: NodeJS.Timeout | undefined;
  private unsubscribe: (() => void) | undefined;
  private readonly f: typeof fetch;
  constructor(
    private readonly o: OtelOptions,
    private readonly rv?: Reversi,
  ) {
    this.f = guardedFetch(o.egress, o.fetch);
  }

  /** Start listening to the engine's ledger and flush on a timer. */
  start(): void {
    if (this.rv) this.unsubscribe = this.rv.ledger.onAppend((r) => this.record(r));
    this.timer = setInterval(() => void this.flush(), this.o.interval_ms ?? 5000);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    this.unsubscribe?.();
    if (this.timer) clearInterval(this.timer);
    await this.flush();
  }

  private span(start: LedgerRecord, end: LedgerRecord, name: string, ok: boolean): Span {
    const effect = this.rv?.registry.get(start.tool)?.effect;
    return {
      traceId: hex(start.run_id, 16),
      spanId: hex(`${start.run_id}/${start.step}/${name}/${start.seq}`, 8),
      name: `${name} ${start.tool}`,
      kind: 1,
      startTimeUnixNano: nano(start.ts_ms),
      endTimeUnixNano: nano(Math.max(end.ts_ms, start.ts_ms)),
      attributes: [
        attr("reversi.run_id", start.run_id),
        attr("reversi.step", start.step),
        attr("reversi.tool", start.tool),
        attr("reversi.actor", start.actor),
        attr("reversi.effect", effect),
        attr("reversi.event", end.event),
        attr("reversi.reason", start.reason),
        attr("reversi.detail", end.detail),
        attr("reversi.seq.start", start.seq),
        attr("reversi.seq.end", end.seq),
      ].filter((a): a is { key: string; value: AttrValue } => a !== null),
      status: ok ? { code: 1 } : { code: 2, message: end.detail.slice(0, 200) || end.event },
    };
  }

  /** Feed a ledger record. Exposed for tests and for replaying history. */
  record(r: LedgerRecord): void {
    const key = `${r.run_id}/${r.step}`;
    switch (r.event) {
      case "intended":
      case "compensating":
        this.open.set(`${key}/${r.event}`, r);
        return;
      case "succeeded":
      case "failed":
      case "uncertain": {
        const s = this.open.get(`${key}/intended`);
        if (s) this.push(this.span(s, r, "reversi.call", r.event === "succeeded"));
        this.open.delete(`${key}/intended`);
        return;
      }
      case "compensated":
      case "compensation_failed": {
        const s = this.open.get(`${key}/compensating`);
        if (s) this.push(this.span(s, r, "reversi.compensate", r.event === "compensated"));
        this.open.delete(`${key}/compensating`);
        return;
      }
      case "blocked":
      case "would_block":
        this.push(this.span(r, r, "reversi.call.blocked", r.event === "would_block"));
        return;
      default:
        return;
    }
  }

  private push(s: Span) {
    this.pending.push(s);
    if (this.pending.length >= (this.o.batch ?? 50)) void this.flush();
  }

  async flush(): Promise<void> {
    if (this.pending.length === 0) return;
    const spans = this.pending.splice(0);
    const body = {
      resourceSpans: [
        {
          resource: { attributes: [attr("service.name", this.o.service_name ?? "reversi"), attr("service.version", this.o.service_version), attr("deployment.environment", this.o.environment ?? this.rv?.environment)].filter((a): a is { key: string; value: AttrValue } => a !== null) },
          scopeSpans: [{ scope: { name: "reversi" }, spans }],
        },
      ],
    };
    try {
      const res = await this.f(`${this.o.endpoint.replace(/\/$/, "")}/v1/traces`, { method: "POST", headers: { "content-type": "application/json", ...(this.o.headers ?? {}) }, body: JSON.stringify(body), signal: AbortSignal.timeout(10_000) });
      if (!res.ok) throw new Error(`collector answered ${res.status}`);
    } catch (e) {
      (this.o.onError ?? ((err) => console.error(`trace export failed: ${err.message}`)))(e instanceof Error ? e : new Error(String(e)));
    }
  }
}
