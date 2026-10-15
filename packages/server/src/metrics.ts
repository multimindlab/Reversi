/** Prometheus text exposition, plus the in-process request counters behind it. */
import type { Approvals, Ledger } from "@multimindlab/reversi";

const esc = (v: string) => v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
const labels = (l: Record<string, string>) => {
  const e = Object.entries(l);
  return e.length ? `{${e.map(([k, v]) => `${k}="${esc(v)}"`).join(",")}}` : "";
};

export class Metrics {
  private readonly requests = new Map<string, number>();
  private readonly durations = new Map<string, { sum: number; count: number }>();
  private readonly events = new Map<string, number>();
  private seen = 0;
  readonly started = Date.now();

  request(method: string, route: string, status: number, ms: number): void {
    const key = JSON.stringify({ method, route, status: String(status) });
    this.requests.set(key, (this.requests.get(key) ?? 0) + 1);
    const dk = JSON.stringify({ method, route });
    const d = this.durations.get(dk) ?? { sum: 0, count: 0 };
    d.sum += ms / 1000;
    d.count += 1;
    this.durations.set(dk, d);
  }

  /** Count ledger events incrementally, so a scrape is O(new records). */
  private ledgerEvents(ledger: Ledger): void {
    const recs = ledger.records();
    for (; this.seen < recs.length; this.seen++) {
      const e = (recs[this.seen] as { event: string }).event;
      this.events.set(e, (this.events.get(e) ?? 0) + 1);
    }
  }

  render(deps: { ledger: Ledger; approvals: Approvals; halted: string | null; runs: number }): string {
    this.ledgerEvents(deps.ledger);
    const out: string[] = [];
    const metric = (name: string, help: string, type: string, lines: string[]) => {
      out.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`, ...lines);
    };
    metric(
      "reversi_http_requests_total",
      "HTTP requests by route and status.",
      "counter",
      [...this.requests].map(([k, v]) => `reversi_http_requests_total${labels(JSON.parse(k))} ${v}`),
    );
    metric(
      "reversi_http_request_duration_seconds",
      "Time spent handling HTTP requests.",
      "summary",
      [...this.durations].flatMap(([k, v]) => {
        const l = labels(JSON.parse(k));
        return [`reversi_http_request_duration_seconds_sum${l} ${v.sum}`, `reversi_http_request_duration_seconds_count${l} ${v.count}`];
      }),
    );
    metric(
      "reversi_ledger_events_total",
      "Ledger records by event: calls (intended), failures, compensations, blocks.",
      "counter",
      [...this.events].sort().map(([e, n]) => `reversi_ledger_events_total${labels({ event: e })} ${n}`),
    );
    metric("reversi_ledger_records", "Records in the ledger.", "gauge", [`reversi_ledger_records ${deps.ledger.records().length}`]);
    metric("reversi_runs", "Runs known to the store.", "gauge", [`reversi_runs ${deps.runs}`]);

    const all = deps.approvals.list();
    const count = (s: string) => all.filter((a) => a.status === s).length;
    metric(
      "reversi_approvals",
      "Approvals by status.",
      "gauge",
      ["pending", "approved", "denied", "consumed", "expired"].map((s) => `reversi_approvals${labels({ status: s })} ${count(s)}`),
    );
    const decided = all.filter((a) => a.decided_ms !== null);
    metric("reversi_approval_latency_seconds", "Time from request to operator decision.", "summary", [
      `reversi_approval_latency_seconds_sum ${decided.reduce((n, a) => n + ((a.decided_ms as number) - a.requested_ms) / 1000, 0)}`,
      `reversi_approval_latency_seconds_count ${decided.length}`,
    ]);
    metric("reversi_halted", "1 while the kill switch blocks new calls.", "gauge", [`reversi_halted ${deps.halted ? 1 : 0}`]);
    metric("reversi_uptime_seconds", "Seconds since the server started.", "gauge", [`reversi_uptime_seconds ${(Date.now() - this.started) / 1000}`]);
    return out.join("\n") + "\n";
  }
}
