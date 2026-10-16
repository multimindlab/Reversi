/**
 * Risk scoring: a transparent 0..100 number from the tool's effect class, data class, blast radius, environment,
 * the call's amount and the actor. Every factor is listed, so a reviewer can see why a call scored what it did.
 */
import { resolveRef } from "./manifest.js";

export interface RiskConfig {
  weights?: {
    effect?: Record<string, number>;
    blast_radius?: Record<string, number>;
    data_class?: Record<string, number>;
    environment?: Record<string, number>;
    /** Points for a tool with no manifest. */
    unclassified?: number;
  };
  /** Points added when a numeric argument is over a band. The highest matching band applies. */
  amount?: { path: string; bands: Array<{ over: number; points: number }> };
  /** Extra points for specific actors (a new or untrusted agent). */
  actors?: Record<string, number>;
  /** At or above `approve` a call needs approval; at or above `deny` it is refused. */
  thresholds?: { approve?: number; deny?: number };
}

export const DEFAULT_WEIGHTS = {
  effect: { read_only: 0, idempotent: 5, reversible: 15, compensable: 30, irreversible: 60 },
  blast_radius: { low: 0, medium: 10, high: 20, critical: 35 },
  data_class: { public: 0, internal: 5, pii: 15, financial: 20, phi: 25, secret: 25 },
  environment: { prod: 10, production: 10 },
  unclassified: 40,
} as const;

export interface RiskInput {
  effect: string | null;
  blast_radius?: string;
  data_class?: string;
  environment: string;
  actor: string;
  args: unknown;
}

export interface RiskResult {
  score: number;
  factors: string[];
}

export function scoreRisk(cfg: RiskConfig | undefined, i: RiskInput): RiskResult {
  const w = { ...DEFAULT_WEIGHTS, ...(cfg?.weights ?? {}) } as Record<string, Record<string, number> | number>;
  const factors: string[] = [];
  let score = 0;
  const add = (points: number | undefined, label: string) => {
    if (!points) return;
    score += points;
    factors.push(`${label} ${points > 0 ? "+" : ""}${points}`);
  };
  if (i.effect === null) add(w.unclassified as number, "no manifest");
  else add((w.effect as Record<string, number>)[i.effect], `effect ${i.effect}`);
  if (i.blast_radius) add((w.blast_radius as Record<string, number>)[i.blast_radius], `blast radius ${i.blast_radius}`);
  if (i.data_class) add((w.data_class as Record<string, number>)[i.data_class], `data class ${i.data_class}`);
  add((w.environment as Record<string, number>)[i.environment], `environment ${i.environment}`);
  if (cfg?.amount) {
    const v = resolveRef(cfg.amount.path, "args", i.args);
    const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
    if (Number.isFinite(n)) {
      const band = [...cfg.amount.bands].sort((a, b) => b.over - a.over).find((b) => n > b.over);
      if (band) add(band.points, `amount over ${band.over}`);
    }
  }
  add(cfg?.actors?.[i.actor], `actor ${i.actor}`);
  return { score: Math.max(0, Math.min(100, score)), factors };
}

export function parseRisk(raw: unknown, errors: string[]): RiskConfig | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    errors.push("`risk` must be an object");
    return undefined;
  }
  const r = raw as Record<string, unknown>;
  for (const k of Object.keys(r)) if (!["weights", "amount", "actors", "thresholds"].includes(k)) errors.push(`risk: unknown field \`${k}\``);
  const numMap = (v: unknown, where: string) => {
    if (v === undefined) return;
    if (typeof v !== "object" || v === null || Object.values(v).some((x) => typeof x !== "number" || !Number.isFinite(x))) errors.push(`${where} must map names to numbers`);
  };
  if (r.weights !== undefined) {
    const w = r.weights as Record<string, unknown>;
    if (typeof w !== "object" || w === null) errors.push("risk.weights must be an object");
    else {
      for (const k of Object.keys(w)) {
        if (!["effect", "blast_radius", "data_class", "environment", "unclassified"].includes(k)) errors.push(`risk.weights: unknown field \`${k}\``);
        else if (k === "unclassified") {
          if (typeof w[k] !== "number") errors.push("risk.weights.unclassified must be a number");
        } else numMap(w[k], `risk.weights.${k}`);
      }
    }
  }
  numMap(r.actors, "risk.actors");
  if (r.amount !== undefined) {
    const a = r.amount as Record<string, unknown>;
    if (typeof a?.path !== "string" || !/^\$args(\.[A-Za-z0-9_-]+)+$/.test(a.path)) errors.push("risk.amount.path must look like `$args.amount`");
    if (!Array.isArray(a?.bands) || a.bands.some((b: unknown) => typeof (b as { over?: unknown }).over !== "number" || typeof (b as { points?: unknown }).points !== "number")) errors.push("risk.amount.bands must be a list of { over, points }");
  }
  if (r.thresholds !== undefined) {
    const t = r.thresholds as Record<string, unknown>;
    for (const k of Object.keys(t ?? {})) {
      if (!["approve", "deny"].includes(k)) errors.push(`risk.thresholds: unknown field \`${k}\``);
      else if (typeof t[k] !== "number" || (t[k] as number) < 0 || (t[k] as number) > 100) errors.push(`risk.thresholds.${k} must be 0..100`);
    }
    if (typeof t?.approve === "number" && typeof t?.deny === "number" && t.approve > t.deny) errors.push("risk.thresholds.approve must not be above deny");
  }
  return r as RiskConfig;
}
