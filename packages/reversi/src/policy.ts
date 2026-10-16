/**
 * Policy as code: rules over tool, effect, permission, actor, environment and call arguments, plus
 * rate/budget limits. Deny beats require_approval beats allow. A policy only ever adds restrictions
 * on top of the manifest and the run's scope; it cannot grant a permission the scope lacks.
 */
import { globAny } from "./glob.js";
import type { CheckAction, ContentConfig } from "./content.js";
import { WindowCounters } from "./counters.js";
import type { KvStore } from "./kv.js";
import { EFFECTS, parseDuration, resolveRef, type Effect } from "./manifest.js";
import { parseRisk, scoreRisk, type RiskConfig, type RiskResult } from "./risk.js";
import { frozenAt, inWindow, parseFreeze, parseWindow, type Freeze, type Window } from "./schedule.js";

export type PolicyAction = "allow" | "deny" | "require_approval";
const OPS = ["eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "matches", "exists", "contains"] as const;
export type Op = (typeof OPS)[number];

export interface Condition {
  /** `$args.path.to.value` */
  path: string;
  op: Op;
  value?: unknown;
}

export interface Match {
  tool?: string | string[];
  effect?: Effect | Effect[];
  permission?: string | string[];
  actor?: string | string[];
  environment?: string | string[];
  tenant?: string | string[];
  data_class?: string | string[];
  blast_radius?: string | string[];
}

/** Who must approve, how many, and what happens when nobody answers. Several requirements on one call are merged. */
export interface ApprovalRequirement {
  /** Reversi roles or group names. An approver must hold at least one. Empty: any approver. */
  roles: string[];
  quorum: number;
  timeout_ms?: number;
  on_timeout?: "deny" | "escalate";
  escalate_to?: string[];
  source: string;
}

export interface PolicyRule {
  id: string;
  description?: string;
  match: Match;
  when?: Condition[];
  /** Only applies inside (or, with `outside`, outside) this time window. */
  window?: Window;
  action: PolicyAction;
  reason?: string;
  /** For `require_approval`: who may approve, and how many of them. */
  approvers?: string[];
  quorum?: number;
  approval_timeout?: string | number;
  on_timeout?: "deny" | "escalate";
  escalate_to?: string[];
}

export interface Budget {
  id: string;
  match: Match;
  metric: "calls" | "sum";
  /** For `sum`: `$args.amount`. */
  path?: string;
  max: number;
  window_seconds: number;
  per: "run" | "actor" | "tenant" | "global";
  action: "deny" | "require_approval";
  /** Warn (in the ledger) from this share of the budget. Default 0.8. */
  warn_at: number;
}

export interface Limit {
  id: string;
  match: Match;
  max_calls: number;
  window_seconds: number;
  per: "run" | "actor" | "tenant" | "global";
}

export interface PolicyTestCase {
  name: string;
  input: Partial<PolicyInput>;
  expect: PolicyAction;
  /** Optional: a rule id that must have fired. */
  rule?: string;
}

export interface PolicyDoc {
  version: 1;
  /** `deny` turns the rules into an allowlist: a call must match an `allow` rule. */
  default: "allow" | "deny";
  rules: PolicyRule[];
  limits: Limit[];
  budgets: Budget[];
  /** Change freezes: no non-read call in these periods. */
  freezes: Freeze[];
  risk?: RiskConfig;
  tests: PolicyTestCase[];
  /** Content-check settings, if the file has a `content:` section. */
  content?: Partial<ContentConfig>;
}

export interface PolicyInput {
  tool: string;
  effect: Effect | null;
  permission: string | null;
  actor: string;
  run_id: string;
  environment: string;
  args: unknown;
  tenant?: string;
  data_class?: string;
  blast_radius?: string;
}

export interface PolicyDecision {
  action: PolicyAction;
  deny: string[];
  approve: string[];
  fired: string[];
  /** Who must approve what needs approval, from rules that name approvers or a quorum. */
  requirements: ApprovalRequirement[];
  risk?: RiskResult;
  /** Things worth a note in the ledger that do not block: budget nearly spent. */
  warnings: string[];
}

export class PolicyError extends Error {
  constructor(public readonly errors: string[]) {
    super(errors.join("; "));
    this.name = "PolicyError";
  }
}

const isRec = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const strOrList = (x: unknown) => typeof x === "string" || (Array.isArray(x) && x.every((s) => typeof s === "string"));

function validateMatch(m: unknown, where: string, errors: string[]): Match {
  if (m === undefined) return {};
  if (!isRec(m)) {
    errors.push(`${where}: match must be an object`);
    return {};
  }
  for (const k of Object.keys(m)) {
    if (!["tool", "effect", "permission", "actor", "environment", "tenant", "data_class", "blast_radius"].includes(k)) errors.push(`${where}: unknown match field \`${k}\``);
    else if (!strOrList(m[k])) errors.push(`${where}: match.${k} must be a string or list of strings`);
  }
  const eff = m.effect === undefined ? [] : Array.isArray(m.effect) ? m.effect : [m.effect];
  for (const e of eff) if (!EFFECTS.includes(e as Effect)) errors.push(`${where}: unknown effect \`${String(e)}\``);
  return m as Match;
}

function validateCondition(c: unknown, where: string, errors: string[]): void {
  if (!isRec(c)) return void errors.push(`${where}: condition must be an object`);
  if (typeof c.path !== "string" || !/^\$args(\.[A-Za-z0-9_-]+)+$/.test(c.path)) {
    errors.push(`${where}: condition path must look like \`$args.amount\``);
  }
  if (!OPS.includes(c.op as Op)) errors.push(`${where}: condition op must be one of ${OPS.join(", ")}`);
  if (c.op === "matches") {
    try {
      new RegExp(String(c.value));
    } catch {
      errors.push(`${where}: invalid regular expression`);
    }
  }
  if ((c.op === "in" || c.op === "not_in") && !Array.isArray(c.value)) errors.push(`${where}: ${String(c.op)} needs a list value`);
  if (c.op !== "exists" && c.value === undefined) errors.push(`${where}: condition needs a value`);
}

const CHECK_ACTIONS: CheckAction[] = ["flag", "require_approval", "deny"];

function parseContent(raw: unknown, errors: string[]): Partial<ContentConfig> | undefined {
  if (raw === undefined) return undefined;
  if (!isRec(raw)) {
    errors.push("`content` must be an object");
    return undefined;
  }
  const out: Partial<ContentConfig> = {};
  for (const k of Object.keys(raw)) {
    if (!["secrets", "encoded_payloads", "injection", "pii", "cumulative", "max_string_bytes"].includes(k)) errors.push(`content: unknown field \`${k}\``);
  }
  for (const k of ["secrets", "encoded_payloads", "injection", "pii"] as const) {
    if (raw[k] === undefined) continue;
    if (!CHECK_ACTIONS.includes(raw[k] as CheckAction)) errors.push(`content.${k} must be ${CHECK_ACTIONS.join(", ")}`);
    else out[k] = raw[k] as CheckAction;
  }
  if (raw.max_string_bytes !== undefined) {
    if (!Number.isInteger(raw.max_string_bytes) || (raw.max_string_bytes as number) < 1) errors.push("content.max_string_bytes must be a positive integer");
    else out.max_string_bytes = raw.max_string_bytes as number;
  }
  if (raw.cumulative !== undefined) {
    if (!Array.isArray(raw.cumulative)) errors.push("content.cumulative must be a list");
    else {
      out.cumulative = [];
      raw.cumulative.forEach((c: unknown, i: number) => {
        const w = `content.cumulative[${i}]`;
        if (!isRec(c) || typeof c.id !== "string" || !c.id) return void errors.push(`${w}: id is required`);
        if (!Array.isArray(c.sources) || !c.sources.length || !c.sources.every((x) => typeof x === "string")) errors.push(`${w}: sources must be a non-empty list of tool globs`);
        if (!Array.isArray(c.egress) || !c.egress.length || !c.egress.every((x) => typeof x === "string")) errors.push(`${w}: egress must be a non-empty list of tool globs`);
        if (!CHECK_ACTIONS.includes(c.action as CheckAction)) errors.push(`${w}: action must be ${CHECK_ACTIONS.join(", ")}`);
        out.cumulative?.push(c as unknown as ContentConfig["cumulative"][number]);
      });
    }
  }
  return out;
}

export function parsePolicy(raw: unknown): PolicyDoc {
  const errors: string[] = [];
  if (!isRec(raw)) throw new PolicyError(["policy must be an object"]);
  for (const k of Object.keys(raw)) if (!["version", "default", "rules", "limits", "budgets", "freezes", "risk", "tests", "content"].includes(k)) errors.push(`unknown field \`${k}\``);
  if (raw.version !== undefined && raw.version !== 1) errors.push("`version` must be 1");
  const def = raw.default ?? "allow";
  if (def !== "allow" && def !== "deny") errors.push("`default` must be allow or deny");
  const rules: PolicyRule[] = [];
  const ids = new Set<string>();
  for (const [i, r] of (Array.isArray(raw.rules) ? raw.rules : raw.rules === undefined ? [] : (errors.push("`rules` must be a list"), [])).entries()) {
    const where = `rules[${i}]`;
    if (!isRec(r)) {
      errors.push(`${where}: must be an object`);
      continue;
    }
    for (const k of Object.keys(r)) if (!["id", "description", "match", "when", "window", "action", "reason", "approvers", "quorum", "approval_timeout", "on_timeout", "escalate_to"].includes(k)) errors.push(`${where}: unknown field \`${k}\``);
    if (typeof r.id !== "string" || !r.id) errors.push(`${where}: id is required`);
    else if (ids.has(r.id)) errors.push(`${where}: duplicate id \`${r.id}\``);
    else ids.add(r.id);
    if (!["allow", "deny", "require_approval"].includes(r.action as string)) errors.push(`${where}: action must be allow, deny or require_approval`);
    const match = validateMatch(r.match, where, errors);
    const when = r.when === undefined ? [] : Array.isArray(r.when) ? r.when : (errors.push(`${where}: when must be a list`), []);
    when.forEach((c, j) => validateCondition(c, `${where}.when[${j}]`, errors));
    const window = parseWindow(r.window, where, errors);
    if (r.approvers !== undefined && (!Array.isArray(r.approvers) || r.approvers.some((a) => typeof a !== "string" || !a))) errors.push(`${where}: approvers must be a list of role or group names`);
    if (r.quorum !== undefined && (!Number.isInteger(r.quorum) || (r.quorum as number) < 1 || (r.quorum as number) > 10)) errors.push(`${where}: quorum must be 1..10`);
    if (r.approval_timeout !== undefined && parseDuration(r.approval_timeout) === undefined) errors.push(`${where}: approval_timeout must be a duration like 15m`);
    if (r.on_timeout !== undefined && r.on_timeout !== "deny" && r.on_timeout !== "escalate") errors.push(`${where}: on_timeout must be deny or escalate`);
    if ((r.approvers !== undefined || r.quorum !== undefined || r.approval_timeout !== undefined) && r.action !== "require_approval") errors.push(`${where}: approvers, quorum and approval_timeout only apply to require_approval rules`);
    rules.push({ ...(r as unknown as PolicyRule), match, when: when as Condition[], ...(window ? { window } : {}) });
  }
  const limits: Limit[] = [];
  for (const [i, l] of (Array.isArray(raw.limits) ? raw.limits : raw.limits === undefined ? [] : (errors.push("`limits` must be a list"), [])).entries()) {
    const where = `limits[${i}]`;
    if (!isRec(l)) {
      errors.push(`${where}: must be an object`);
      continue;
    }
    if (typeof l.id !== "string" || !l.id) errors.push(`${where}: id is required`);
    if (!Number.isInteger(l.max_calls) || (l.max_calls as number) < 0) errors.push(`${where}: max_calls must be a non-negative integer`);
    if (typeof l.window_seconds !== "number" || !(l.window_seconds > 0)) errors.push(`${where}: window_seconds must be positive`);
    if (l.per !== undefined && !["run", "actor", "tenant", "global"].includes(l.per as string)) errors.push(`${where}: per must be run, actor, tenant or global`);
    limits.push({ ...(l as unknown as Limit), per: (l.per as Limit["per"]) ?? "run", match: validateMatch(l.match, where, errors) });
  }
  const budgets: Budget[] = [];
  for (const [i, b] of (Array.isArray(raw.budgets) ? raw.budgets : raw.budgets === undefined ? [] : (errors.push("`budgets` must be a list"), [])).entries()) {
    const where = `budgets[${i}]`;
    if (!isRec(b)) {
      errors.push(`${where}: must be an object`);
      continue;
    }
    for (const k of Object.keys(b)) if (!["id", "match", "metric", "path", "max", "window_seconds", "per", "action", "warn_at"].includes(k)) errors.push(`${where}: unknown field \`${k}\``);
    if (typeof b.id !== "string" || !b.id) errors.push(`${where}: id is required`);
    if (b.metric !== "calls" && b.metric !== "sum") errors.push(`${where}: metric must be calls or sum`);
    if (b.metric === "sum" && (typeof b.path !== "string" || !/^\$args(\.[A-Za-z0-9_-]+)+$/.test(b.path))) errors.push(`${where}: a sum budget needs path like $args.amount`);
    if (typeof b.max !== "number" || !(b.max >= 0)) errors.push(`${where}: max must be a non-negative number`);
    if (typeof b.window_seconds !== "number" || !(b.window_seconds > 0)) errors.push(`${where}: window_seconds must be positive`);
    if (b.per !== undefined && !["run", "actor", "tenant", "global"].includes(b.per as string)) errors.push(`${where}: per must be run, actor, tenant or global`);
    if (b.action !== undefined && b.action !== "deny" && b.action !== "require_approval") errors.push(`${where}: action must be deny or require_approval`);
    if (b.warn_at !== undefined && (typeof b.warn_at !== "number" || b.warn_at <= 0 || b.warn_at > 1)) errors.push(`${where}: warn_at must be above 0 and at most 1`);
    budgets.push({ ...(b as unknown as Budget), per: (b.per as Budget["per"]) ?? "run", action: (b.action as Budget["action"]) ?? "deny", warn_at: (b.warn_at as number) ?? 0.8, match: validateMatch(b.match, where, errors) });
  }
  const freezes: Freeze[] = [];
  if (raw.freezes !== undefined && !Array.isArray(raw.freezes)) errors.push("`freezes` must be a list");
  else for (const [i, f] of ((raw.freezes as unknown[] | undefined) ?? []).entries()) {
    const fr = parseFreeze(f, `freezes[${i}]`, errors);
    if (fr) freezes.push(fr);
  }
  const risk = parseRisk(raw.risk, errors);
  const tests = raw.tests === undefined ? [] : Array.isArray(raw.tests) ? (raw.tests as PolicyTestCase[]) : (errors.push("`tests` must be a list"), []);
  const content = parseContent(raw.content, errors);
  if (errors.length) throw new PolicyError(errors);
  return { version: 1, default: def as "allow" | "deny", rules, limits, budgets, freezes, ...(risk ? { risk } : {}), tests, ...(content ? { content } : {}) };
}

function matches(m: Match, i: PolicyInput): boolean {
  return (
    globAny(m.tool, i.tool) &&
    (m.effect === undefined || (i.effect !== null && (Array.isArray(m.effect) ? m.effect : [m.effect]).includes(i.effect))) &&
    (m.permission === undefined || (i.permission !== null && globAny(m.permission, i.permission))) &&
    globAny(m.actor, i.actor) &&
    globAny(m.environment, i.environment) &&
    (m.tenant === undefined || (i.tenant !== undefined && globAny(m.tenant, i.tenant))) &&
    (m.data_class === undefined || (i.data_class !== undefined && globAny(m.data_class, i.data_class))) &&
    (m.blast_radius === undefined || (i.blast_radius !== undefined && globAny(m.blast_radius, i.blast_radius)))
  );
}

/** Numbers, and numeric strings: an upstream that coerces "5000" must not slip under `gt 1000`. */
function numeric(v: unknown): number | undefined {
  if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

/**
 * Does the condition hold? For `deny` and `require_approval` rules (`failClosed`), a value that is present but
 * of the wrong type for the operator counts as matching: a restriction must not be dodged by sending the wrong type.
 */
function holds(c: Condition, args: unknown, failClosed = false): boolean {
  const v = resolveRef(c.path, "args", args);
  if (failClosed && v !== undefined && v !== null) {
    if (["gt", "gte", "lt", "lte"].includes(c.op) && numeric(v) === undefined) return true;
    if (c.op === "matches" && typeof v !== "string") return true;
  }
  const n = numeric(v);
  switch (c.op) {
    case "exists":
      return v !== undefined;
    case "eq":
      return JSON.stringify(v) === JSON.stringify(c.value);
    case "ne":
      return JSON.stringify(v) !== JSON.stringify(c.value);
    case "gt":
      return n !== undefined && n > (c.value as number);
    case "gte":
      return n !== undefined && n >= (c.value as number);
    case "lt":
      return n !== undefined && n < (c.value as number);
    case "lte":
      return n !== undefined && n <= (c.value as number);
    case "in":
      return (c.value as unknown[]).some((x) => JSON.stringify(x) === JSON.stringify(v));
    case "not_in":
      return v !== undefined && !(c.value as unknown[]).some((x) => JSON.stringify(x) === JSON.stringify(v));
    case "matches":
      return typeof v === "string" && new RegExp(String(c.value)).test(v);
    case "contains":
      return typeof v === "string" ? v.includes(String(c.value)) : Array.isArray(v) && v.some((x) => JSON.stringify(x) === JSON.stringify(c.value));
  }
}

export class Policy {
  private readonly counters: WindowCounters;
  constructor(
    readonly doc: PolicyDoc,
    private readonly clock: () => number = Date.now,
    /** Share counters (rate limits, budgets) between processes by passing the data store's KV. */
    kv?: KvStore,
  ) {
    this.counters = new WindowCounters(kv, clock);
  }

  static from(raw: unknown, clock?: () => number, kv?: KvStore): Policy {
    return new Policy(parsePolicy(raw), clock, kv);
  }

  /** The amount a call adds to a budget: 1 for `calls`, the numeric argument for `sum`. */
  private amountOf(b: Budget, input: PolicyInput): number {
    if (b.metric === "calls") return 1;
    const n = numeric(resolveRef(b.path as string, "args", input.args));
    return n ?? 0;
  }

  private scopeKey(id: string, per: "run" | "actor" | "tenant" | "global", i: PolicyInput): string {
    return JSON.stringify([id, per === "run" ? i.run_id : per === "actor" ? i.actor : per === "tenant" ? (i.tenant ?? "") : ""]);
  }

  /** Risk score for a call, using this policy's weights (or the defaults when it has none). */
  score(input: PolicyInput): RiskResult {
    return scoreRisk(this.doc.risk, { effect: input.effect, blast_radius: input.blast_radius, data_class: input.data_class, environment: input.environment, actor: input.actor, args: input.args });
  }

  evaluate(input: PolicyInput): PolicyDecision {
    const deny: string[] = [];
    const approve: string[] = [];
    const fired: string[] = [];
    const warnings: string[] = [];
    const requirements: ApprovalRequirement[] = [];
    const now = this.clock();
    let allowed = false;
    for (const r of this.doc.rules) {
      if (!matches(r.match, input) || !(r.when ?? []).every((c) => holds(c, input.args, r.action !== "allow"))) continue;
      if (r.window && !inWindow(r.window, now)) continue;
      fired.push(r.id);
      const why = `policy \`${r.id}\`${r.reason ? `: ${r.reason}` : ""}`;
      if (r.action === "deny") deny.push(why);
      else if (r.action === "require_approval") {
        approve.push(why);
        if (r.approvers || r.quorum || r.approval_timeout) {
          requirements.push({
            roles: r.approvers ?? [],
            quorum: r.quorum ?? 1,
            ...(r.approval_timeout !== undefined ? { timeout_ms: parseDuration(r.approval_timeout) } : {}),
            ...(r.on_timeout ? { on_timeout: r.on_timeout } : {}),
            ...(r.escalate_to ? { escalate_to: r.escalate_to } : {}),
            source: `policy \`${r.id}\``,
          });
        }
      } else allowed = true;
    }
    if (this.doc.default === "deny" && !allowed && deny.length === 0) deny.push("policy: no allow rule matches this call (default deny)");

    for (const f of this.doc.freezes) {
      if (!frozenAt(f, now)) continue;
      const m = f.match;
      const applies = m
        ? globAny(m.tool, input.tool) && (m.effect === undefined || (input.effect !== null && (Array.isArray(m.effect) ? m.effect : [m.effect]).includes(input.effect))) && globAny(m.environment, input.environment)
        : input.effect !== "read_only";
      if (applies) {
        deny.push(`freeze \`${f.id}\`: ${f.reason} (until ${f.to})`);
        fired.push(f.id);
      }
    }

    for (const l of this.doc.limits) {
      if (!matches(l.match, input)) continue;
      const { count } = this.counters.total(`limit:${this.scopeKey(l.id, l.per, input)}`, l.window_seconds * 1000);
      if (count >= l.max_calls) {
        deny.push(`limit \`${l.id}\`: ${l.max_calls} calls per ${l.window_seconds}s exceeded`);
        fired.push(l.id);
      }
    }

    for (const b of this.doc.budgets) {
      if (!matches(b.match, input)) continue;
      const { count, sum } = this.counters.total(`budget:${this.scopeKey(b.id, b.per, input)}`, b.window_seconds * 1000);
      const used = b.metric === "calls" ? count : sum;
      const after = used + this.amountOf(b, input);
      if (after > b.max) {
        (b.action === "deny" ? deny : approve).push(`budget \`${b.id}\`: ${used} of ${b.max} used in ${b.window_seconds}s, this call would make it ${after}`);
        fired.push(b.id);
      } else if (b.max > 0 && after >= b.max * b.warn_at) {
        warnings.push(`budget \`${b.id}\` at ${Math.round((after / b.max) * 100)}% (${after} of ${b.max})`);
      }
    }

    let risk: RiskResult | undefined;
    if (this.doc.risk) {
      risk = this.score(input);
      const t = this.doc.risk.thresholds;
      if (t?.deny !== undefined && risk.score >= t.deny) deny.push(`risk score ${risk.score} is at or above the deny threshold ${t.deny} (${risk.factors.join(", ")})`);
      else if (t?.approve !== undefined && risk.score >= t.approve) approve.push(`risk score ${risk.score} is at or above the approval threshold ${t.approve} (${risk.factors.join(", ")})`);
    }
    return { action: deny.length ? "deny" : approve.length ? "require_approval" : "allow", deny, approve, fired, requirements, ...(risk ? { risk } : {}), warnings };
  }

  /** Count a call that was actually allowed to start, for the limits and budgets. */
  record(input: PolicyInput): void {
    for (const l of this.doc.limits) {
      if (matches(l.match, input)) this.counters.add(`limit:${this.scopeKey(l.id, l.per, input)}`, 1, l.window_seconds * 1000);
    }
    for (const b of this.doc.budgets) {
      if (matches(b.match, input)) this.counters.add(`budget:${this.scopeKey(b.id, b.per, input)}`, this.amountOf(b, input), b.window_seconds * 1000);
    }
  }
}

export interface PolicyTestResult {
  name: string;
  ok: boolean;
  got: PolicyAction;
  expected: PolicyAction;
  message?: string;
}

/** Run a policy's test cases (inline `tests:` plus any extra). Limits are evaluated fresh per case. */
export function runPolicyTests(policy: PolicyDoc, extra: PolicyTestCase[] = []): PolicyTestResult[] {
  return [...policy.tests, ...extra].map((t) => {
    const p = new Policy(policy);
    const d = p.evaluate({
      tool: "",
      effect: null,
      permission: null,
      actor: "agent",
      run_id: "test-run",
      environment: "dev",
      args: {},
      ...t.input,
    });
    const ok = d.action === t.expect && (t.rule === undefined || d.fired.includes(t.rule));
    return {
      name: t.name,
      ok,
      got: d.action,
      expected: t.expect,
      message: ok ? undefined : t.rule && !d.fired.includes(t.rule) ? `rule \`${t.rule}\` did not fire (fired: ${d.fired.join(", ") || "none"})` : undefined,
    };
  });
}

/** Combine policy documents: rules and limits concatenated (ids must stay unique), default deny wins. */
export function mergePolicyDocs(...docs: Array<PolicyDoc | undefined>): PolicyDoc | undefined {
  const present = docs.filter((d): d is PolicyDoc => d !== undefined);
  if (present.length === 0) return undefined;
  const merged: PolicyDoc = {
    version: 1,
    default: present.some((d) => d.default === "deny") ? "deny" : "allow",
    rules: present.flatMap((d) => d.rules),
    limits: present.flatMap((d) => d.limits),
    budgets: present.flatMap((d) => d.budgets),
    freezes: present.flatMap((d) => d.freezes),
    risk: present.find((d) => d.risk)?.risk,
    tests: present.flatMap((d) => d.tests),
    content: present.find((d) => d.content)?.content,
  };
  const ids = merged.rules.map((r) => r.id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup) throw new PolicyError([`duplicate rule id \`${dup}\` when combining policies`]);
  return merged;
}
