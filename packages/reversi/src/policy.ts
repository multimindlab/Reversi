/**
 * Policy as code: rules over tool, effect, permission, actor, environment and call arguments, plus
 * rate/budget limits. Deny beats require_approval beats allow. A policy only ever adds restrictions
 * on top of the manifest and the run's scope; it cannot grant a permission the scope lacks.
 */
import { globAny } from "./glob.js";
import { EFFECTS, resolveRef, type Effect } from "./manifest.js";

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
}

export interface PolicyRule {
  id: string;
  description?: string;
  match: Match;
  when?: Condition[];
  action: PolicyAction;
  reason?: string;
}

export interface Limit {
  id: string;
  match: Match;
  max_calls: number;
  window_seconds: number;
  per: "run" | "actor" | "global";
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
  tests: PolicyTestCase[];
}

export interface PolicyInput {
  tool: string;
  effect: Effect | null;
  permission: string | null;
  actor: string;
  run_id: string;
  environment: string;
  args: unknown;
}

export interface PolicyDecision {
  action: PolicyAction;
  deny: string[];
  approve: string[];
  fired: string[];
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
    if (!["tool", "effect", "permission", "actor", "environment"].includes(k)) errors.push(`${where}: unknown match field \`${k}\``);
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

export function parsePolicy(raw: unknown): PolicyDoc {
  const errors: string[] = [];
  if (!isRec(raw)) throw new PolicyError(["policy must be an object"]);
  for (const k of Object.keys(raw)) if (!["version", "default", "rules", "limits", "tests"].includes(k)) errors.push(`unknown field \`${k}\``);
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
    for (const k of Object.keys(r)) if (!["id", "description", "match", "when", "action", "reason"].includes(k)) errors.push(`${where}: unknown field \`${k}\``);
    if (typeof r.id !== "string" || !r.id) errors.push(`${where}: id is required`);
    else if (ids.has(r.id)) errors.push(`${where}: duplicate id \`${r.id}\``);
    else ids.add(r.id);
    if (!["allow", "deny", "require_approval"].includes(r.action as string)) errors.push(`${where}: action must be allow, deny or require_approval`);
    const match = validateMatch(r.match, where, errors);
    const when = r.when === undefined ? [] : Array.isArray(r.when) ? r.when : (errors.push(`${where}: when must be a list`), []);
    when.forEach((c, j) => validateCondition(c, `${where}.when[${j}]`, errors));
    rules.push({ ...(r as unknown as PolicyRule), match, when: when as Condition[] });
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
    if (l.per !== undefined && !["run", "actor", "global"].includes(l.per as string)) errors.push(`${where}: per must be run, actor or global`);
    limits.push({ ...(l as unknown as Limit), per: (l.per as Limit["per"]) ?? "run", match: validateMatch(l.match, where, errors) });
  }
  const tests = raw.tests === undefined ? [] : Array.isArray(raw.tests) ? (raw.tests as PolicyTestCase[]) : (errors.push("`tests` must be a list"), []);
  if (errors.length) throw new PolicyError(errors);
  return { version: 1, default: def as "allow" | "deny", rules, limits, tests };
}

function matches(m: Match, i: PolicyInput): boolean {
  return (
    globAny(m.tool, i.tool) &&
    (m.effect === undefined || (i.effect !== null && (Array.isArray(m.effect) ? m.effect : [m.effect]).includes(i.effect))) &&
    (m.permission === undefined || (i.permission !== null && globAny(m.permission, i.permission))) &&
    globAny(m.actor, i.actor) &&
    globAny(m.environment, i.environment)
  );
}

function holds(c: Condition, args: unknown): boolean {
  const v = resolveRef(c.path, "args", args);
  switch (c.op) {
    case "exists":
      return v !== undefined;
    case "eq":
      return JSON.stringify(v) === JSON.stringify(c.value);
    case "ne":
      return JSON.stringify(v) !== JSON.stringify(c.value);
    case "gt":
      return typeof v === "number" && v > (c.value as number);
    case "gte":
      return typeof v === "number" && v >= (c.value as number);
    case "lt":
      return typeof v === "number" && v < (c.value as number);
    case "lte":
      return typeof v === "number" && v <= (c.value as number);
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
  /** Call timestamps per limit bucket, for sliding-window limits. */
  private readonly calls = new Map<string, number[]>();
  constructor(
    readonly doc: PolicyDoc,
    private readonly clock: () => number = Date.now,
  ) {}

  static from(raw: unknown, clock?: () => number): Policy {
    return new Policy(parsePolicy(raw), clock);
  }

  evaluate(input: PolicyInput): PolicyDecision {
    const deny: string[] = [];
    const approve: string[] = [];
    const fired: string[] = [];
    let allowed = false;
    for (const r of this.doc.rules) {
      if (!matches(r.match, input) || !(r.when ?? []).every((c) => holds(c, input.args))) continue;
      fired.push(r.id);
      const why = `policy \`${r.id}\`${r.reason ? `: ${r.reason}` : ""}`;
      if (r.action === "deny") deny.push(why);
      else if (r.action === "require_approval") approve.push(why);
      else allowed = true;
    }
    if (this.doc.default === "deny" && !allowed && deny.length === 0) deny.push("policy: no allow rule matches this call (default deny)");
    for (const l of this.doc.limits) {
      if (!matches(l.match, input)) continue;
      const key = this.bucket(l, input);
      const horizon = this.clock() - l.window_seconds * 1000;
      const recent = (this.calls.get(key) ?? []).filter((t) => t > horizon);
      if (recent.length >= l.max_calls) {
        deny.push(`limit \`${l.id}\`: ${l.max_calls} calls per ${l.window_seconds}s exceeded`);
        fired.push(l.id);
      }
    }
    return { action: deny.length ? "deny" : approve.length ? "require_approval" : "allow", deny, approve, fired };
  }

  /** Count a call that was actually allowed to start, for the limits. */
  record(input: PolicyInput): void {
    const now = this.clock();
    for (const l of this.doc.limits) {
      if (!matches(l.match, input)) continue;
      const key = this.bucket(l, input);
      const horizon = now - l.window_seconds * 1000;
      const list = (this.calls.get(key) ?? []).filter((t) => t > horizon);
      list.push(now);
      this.calls.set(key, list);
    }
  }

  private bucket(l: Limit, i: PolicyInput): string {
    return JSON.stringify([l.id, l.per === "run" ? i.run_id : l.per === "actor" ? i.actor : ""]);
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
