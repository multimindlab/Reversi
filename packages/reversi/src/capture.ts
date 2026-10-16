/**
 * Opt-in capture of redacted call arguments and results, kept for a limited time.
 *
 * The ledger never stores arguments (only hashes). Replay, policy simulation against history and impact previews need
 * them, so capture is a separate, explicit choice: off by default, redacted on the way in (credentials, optional
 * personal data, and the paths a manifest lists under `audit.redaction`), and deleted when it expires.
 */
import { randomBytes } from "node:crypto";
import { kvUpdate, type KvStore } from "./kv.js";
import { maskPii } from "./pii.js";
import { redactSecrets } from "./redact.js";

export interface CaptureConfig {
  enabled: boolean;
  /** How long a record is kept. Default 7 days. */
  ttl_ms: number;
  /** Also mask emails, phone numbers, card numbers, SSNs and IBANs. Default true. */
  redact_pii: boolean;
  /** Largest captured value in characters; bigger ones are cut. Default 20,000. */
  max_chars: number;
}

export const DEFAULT_CAPTURE: CaptureConfig = { enabled: false, ttl_ms: 7 * 86_400_000, redact_pii: true, max_chars: 20_000 };

export interface CaptureRecord {
  run_id: string;
  /** Null for a call that was blocked before it became a step. */
  step: number | null;
  tool: string;
  actor: string;
  tenant?: string;
  environment: string;
  args: unknown;
  result?: unknown;
  /** What the engine decided at the time. */
  decision: "allow" | "would_block" | "block";
  reasons: string[];
  outcome?: "succeeded" | "failed" | "uncertain";
  manifest_version?: number;
  risk_score?: number;
  ts_ms: number;
  expires_ms: number;
}

const NS = "capture";
const MASK = "[REDACTED]";

/** Replace the value at `$args.a.b` inside `root` (which is the args or result object itself). */
function setPath(root: unknown, path: string, value: unknown): void {
  const segs = path.split(".").slice(1);
  let cur = root as Record<string, unknown> | unknown[];
  for (let i = 0; i < segs.length; i++) {
    const k = segs[i] as string;
    const next = (cur as Record<string, unknown>)[k];
    if (i === segs.length - 1) {
      if (typeof cur === "object" && cur !== null && k in cur) (cur as Record<string, unknown>)[k] = value;
      return;
    }
    if (typeof next !== "object" || next === null) return;
    cur = next as Record<string, unknown>;
  }
}

/** A redacted deep copy: credentials and (optionally) personal data masked, listed paths replaced, long values cut. */
export function redactForCapture(value: unknown, opts: { redact_pii: boolean; max_chars: number; paths?: string[]; root?: "args" | "result" }): unknown {
  const clean = (v: unknown, depth: number): unknown => {
    if (depth > 12) return "[too deep]";
    if (typeof v === "string") {
      let s = redactSecrets(v);
      if (opts.redact_pii) s = maskPii(s);
      return s.length > opts.max_chars ? `${s.slice(0, opts.max_chars)}…[cut]` : s;
    }
    if (Array.isArray(v)) return v.slice(0, 200).map((x) => clean(x, depth + 1));
    if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).slice(0, 200).map(([k, x]) => [k, clean(x, depth + 1)]));
    if (typeof v === "number" && !Number.isFinite(v)) return String(v);
    return v;
  };
  const out = clean(value, 0);
  for (const p of opts.paths ?? []) if (p.startsWith(`$${opts.root ?? "args"}.`)) setPath(out, p, MASK);
  return out;
}

export class CaptureStore {
  readonly config: CaptureConfig;
  constructor(
    private readonly kv: KvStore,
    config: Partial<CaptureConfig> = {},
    private readonly now: () => number = Date.now,
  ) {
    this.config = { ...DEFAULT_CAPTURE, ...config };
  }

  get enabled(): boolean {
    return this.config.enabled;
  }

  private key(run: string, step: number | null): string {
    return `${run}/${step === null ? `blocked-${this.now()}-${randomBytes(3).toString("hex")}` : String(step).padStart(6, "0")}`;
  }

  /** Redact and store a call. Returns the key, so the outcome can be added later. */
  record(rec: Omit<CaptureRecord, "args" | "result" | "ts_ms" | "expires_ms"> & { args: unknown; result?: unknown; redact_paths?: string[] }): string | null {
    if (!this.config.enabled) return null;
    const { redact_paths, ...rest } = rec;
    const o = { redact_pii: this.config.redact_pii, max_chars: this.config.max_chars, paths: redact_paths };
    const stored: CaptureRecord = {
      ...rest,
      args: redactForCapture(rec.args, { ...o, root: "args" }),
      ...(rec.result !== undefined ? { result: redactForCapture(rec.result, { ...o, root: "result" }) } : {}),
      ts_ms: this.now(),
      expires_ms: this.now() + this.config.ttl_ms,
    };
    const key = this.key(rec.run_id, rec.step);
    this.kv.put(NS, key, stored);
    return key;
  }

  /** Add what happened to a captured call. */
  complete(run: string, step: number, outcome: "succeeded" | "failed" | "uncertain", result: unknown, redact_paths?: string[]): void {
    if (!this.config.enabled) return;
    const o = { redact_pii: this.config.redact_pii, max_chars: this.config.max_chars, paths: redact_paths, root: "result" as const };
    kvUpdate<CaptureRecord | undefined>(this.kv, NS, `${run}/${String(step).padStart(6, "0")}`, (cur) =>
      cur ? { ...cur, outcome, ...(result !== undefined ? { result: redactForCapture(result, o) } : {}) } : cur,
    );
  }

  private live(r: CaptureRecord): boolean {
    return r.expires_ms > this.now();
  }

  list(filter: { run_id?: string; tool?: string; since_ms?: number } = {}): CaptureRecord[] {
    return this.kv
      .list<CaptureRecord>(NS, filter.run_id ? `${filter.run_id}/` : "")
      .map((e) => e.value)
      .filter((r) => r && this.live(r) && (!filter.tool || r.tool === filter.tool) && (!filter.since_ms || r.ts_ms >= filter.since_ms))
      .sort((a, b) => a.ts_ms - b.ts_ms || (a.step ?? 0) - (b.step ?? 0));
  }

  get(run: string, step: number): CaptureRecord | undefined {
    const r = this.kv.get<CaptureRecord>(NS, `${run}/${String(step).padStart(6, "0")}`)?.value;
    return r && this.live(r) ? r : undefined;
  }

  /** Delete expired records (and, with `run_id`, everything captured for that run). Returns how many were removed. */
  purge(opts: { run_id?: string } = {}): number {
    let n = 0;
    for (const e of this.kv.list<CaptureRecord>(NS, opts.run_id ? `${opts.run_id}/` : "")) {
      if (opts.run_id || !this.live(e.value)) if (this.kv.delete(NS, e.key)) n++;
    }
    return n;
  }
}
