/**
 * The tool manifest: how reversible a tool is, what undoes it, which permission it needs.
 * A tool without a manifest is an incomplete tool, the way a function that allocates without
 * a matching free is incomplete.
 */

export const EFFECTS = ["read_only", "idempotent", "reversible", "compensable", "irreversible"] as const;
export type Effect = (typeof EFFECTS)[number];

export type ManifestStatus = "draft" | "approved" | "deprecated";
export const BLAST_RADII = ["low", "medium", "high", "critical"] as const;
export type BlastRadius = (typeof BLAST_RADII)[number];

/** Read back upstream state after a compensation and require an expected condition before calling the undo complete. */
export interface Verification {
  /** A read-only tool that returns the state to check. */
  tool: string;
  /** Arguments for it, as references (`$args.x`, `$result.y`) resolved when the original call succeeded. */
  arguments: Record<string, string>;
  /** Dotted path in the verification result -> expected value (deep equal). */
  expect: Record<string, unknown>;
  /** Attempts, with `backoff_ms` between them (doubling), because undo is often eventually consistent. */
  retries: number;
  backoff_ms: number;
}

export interface Compensation {
  /** Name of the tool that undoes this one. */
  tool: string;
  /** `inverse` restores the exact prior state. `compensation` (default) makes amends and may leave residue. */
  kind: "inverse" | "compensation";
  /** What the undo cannot take back, in plain words (an emailed notification, a line on a statement). */
  residue: string[];
  verification?: Verification;
  timeout_ms?: number;
  /**
   * How to build the compensation's arguments. Keys are the compensation tool's argument names;
   * values are references: `$args.path.to.value` (the original call) or `$result.path.to.value`.
   */
  argument_map: Record<string, string>;
  /** A human must approve running this compensation. */
  requires_approval: boolean;
}

export interface ToolManifest {
  tool: string;
  description?: string;
  effect: Effect;
  permission: string;
  /** `always` makes a human approve each call. Forced to `always` for irreversible tools. */
  approval: "never" | "always";
  compensation?: Compensation;
  /** Tools that must have succeeded earlier in the same run. Also creates rollback ordering edges. */
  requires: string[];
  /** Manifest version (a registry increments it on every publish). */
  version: number;
  /** `draft` manifests are not enforceable: calls are blocked. `deprecated` ones still run and still roll back. */
  status: ManifestStatus;
  replaced_by?: string;
  owner?: string;
  oncall?: string;
  risk?: { data_class?: string; blast_radius?: BlastRadius; environment?: string };
  timeout_ms?: number;
  /** Retry transient failures of the forward call (only honoured for read_only and idempotent tools). */
  retry?: { attempts: number; base_ms: number; max_ms: number };
  /** Calls with the same rendered key are duplicates. `{{args.order_id}}` templates over the call arguments. */
  idempotency?: { key: string; scope: "run" | "actor" | "global" };
  audit?: { retention_days?: number; evidence_export?: "required" | "optional"; redaction?: string[] };
  /** Who may approve, how many must, and what happens when nobody answers in time. */
  approval_rules?: { roles: string[]; quorum: number; timeout_ms?: number; on_timeout: "deny" | "escalate"; escalate_to?: string[] };
  /** Hash of the upstream tool's inputSchema when this manifest was written; lets the gateway notice drift. */
  schema_hash?: string;
}

export class ManifestError extends Error {
  constructor(public readonly errors: string[]) {
    super(errors.join("; "));
    this.name = "ManifestError";
  }
}

const TOOL_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,127}$/;
const PERMISSION = /^\S{1,128}$/;
export const REF_PATTERN = /^\$(args|result)(\.[A-Za-z0-9_-]+)+$/;

const TOP_KEYS = new Set([
  "tool",
  "description",
  "effect",
  "permission",
  "approval",
  "compensation",
  "requires",
  "version",
  "status",
  "replaced_by",
  "owner",
  "oncall",
  "risk",
  "timeout_ms",
  "retry",
  "idempotency",
  "audit",
  "schema_hash",
]);
const COMP_KEYS = new Set(["tool", "argument_map", "requires_approval", "kind", "residue", "verification", "timeout_ms"]);
const VERIFY_KEYS = new Set(["tool", "arguments", "expect", "retries", "backoff_ms"]);

/** "15m", "30s", "2h", "500ms", "1d" or a number of milliseconds. */
export function parseDuration(v: unknown): number | undefined {
  if (typeof v === "number") return Number.isFinite(v) && v > 0 ? Math.floor(v) : undefined;
  if (typeof v !== "string") return undefined;
  const m = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)$/.exec(v.trim());
  if (!m) return undefined;
  const mult = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "ms"];
  return Math.floor(Number(m[1]) * mult);
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

export type ValidateResult = { ok: true; manifest: ToolManifest } | { ok: false; errors: string[] };

/** Validate one manifest and fill in defaults. Does not check references to other tools. */
export function validateManifest(input: unknown): ValidateResult {
  const errors: string[] = [];
  if (!isRecord(input)) return { ok: false, errors: ["manifest must be an object"] };
  // A normalized manifest (as stored and returned by this library) carries `approval_rules`; read it back as the author's `approval` object.
  const raw = isRecord(input.approval_rules) && typeof input.approval === "string" ? authorForm(input as unknown as ToolManifest) : input;

  const label = typeof raw.tool === "string" && raw.tool ? `\`${raw.tool}\`` : "manifest";
  const err = (m: string) => errors.push(`${label}: ${m}`);

  for (const k of Object.keys(raw)) if (!TOP_KEYS.has(k)) err(`unknown field \`${k}\``);

  if (typeof raw.tool !== "string" || !TOOL_NAME.test(raw.tool)) {
    err("`tool` must be a name of letters, digits and _ . : / - (max 128 characters)");
  }
  if (typeof raw.permission !== "string" || !PERMISSION.test(raw.permission)) {
    err("`permission` must be a non-empty string without whitespace");
  }
  if (raw.description !== undefined && typeof raw.description !== "string") {
    err("`description` must be a string");
  }
  const effect = raw.effect as Effect;
  if (!EFFECTS.includes(effect)) err(`\`effect\` must be one of ${EFFECTS.join(", ")}`);

  let approval: "never" | "always" = "never";
  let approval_rules: ToolManifest["approval_rules"];
  if (raw.approval !== undefined) {
    if (raw.approval === "never" || raw.approval === "always") approval = raw.approval;
    else if (isRecord(raw.approval)) {
      const a = raw.approval;
      for (const k of Object.keys(a)) if (!["required", "roles", "quorum", "timeout", "on_timeout", "escalate_to"].includes(k)) err(`unknown approval field \`${k}\``);
      if (a.required !== undefined && typeof a.required !== "boolean") err("`approval.required` must be a boolean");
      approval = a.required === false ? "never" : "always";
      const roles = a.roles === undefined ? [] : a.roles;
      if (!Array.isArray(roles) || roles.some((r) => typeof r !== "string" || !r)) err("`approval.roles` must be a list of role or group names");
      const quorum = a.quorum === undefined ? 1 : a.quorum;
      if (!Number.isInteger(quorum) || (quorum as number) < 1 || (quorum as number) > 10) err("`approval.quorum` must be an integer from 1 to 10");
      let timeout_ms: number | undefined;
      if (a.timeout !== undefined) {
        timeout_ms = parseDuration(a.timeout);
        if (timeout_ms === undefined) err("`approval.timeout` must be a duration like 15m, 30s or 2h");
      }
      if (a.on_timeout !== undefined && a.on_timeout !== "deny" && a.on_timeout !== "escalate") err("`approval.on_timeout` must be deny or escalate");
      if (Array.isArray(roles) && Array.isArray(roles) && (quorum as number) > 1 && roles.length === 0) err("a quorum needs `approval.roles` to draw approvers from");
      approval_rules = {
        roles: Array.isArray(roles) ? (roles as string[]) : [],
        quorum: Number.isInteger(quorum) ? (quorum as number) : 1,
        timeout_ms,
        on_timeout: a.on_timeout === "escalate" ? "escalate" : "deny",
        escalate_to: Array.isArray(a.escalate_to) ? (a.escalate_to as string[]) : undefined,
      };
    } else err("`approval` must be `never`, `always` or an object with roles, quorum and timeout");
  }
  if (effect === "irreversible") {
    if (raw.approval === "never") err("irreversible tools must require approval");
    approval = "always";
  }

  let requires: string[] = [];
  if (raw.requires !== undefined) {
    const normalized = Array.isArray(raw.requires)
      ? raw.requires.map((r) => (typeof r === "string" ? r : isRecord(r) && typeof r.tool === "string" && (r.status === undefined || r.status === "succeeded") ? r.tool : ""))
      : [];
    if (!Array.isArray(raw.requires) || normalized.some((r) => !r)) {
      err("`requires` must be a list of tool names (or { tool, status: succeeded })");
    } else {
      requires = normalized;
      if (new Set(requires).size !== requires.length) err("`requires` contains duplicates");
      if (requires.includes(raw.tool as string)) err("a tool cannot require itself");
    }
  }

  let compensation: Compensation | undefined;
  if (raw.compensation !== undefined) {
    const c = raw.compensation;
    if (!isRecord(c)) {
      err("`compensation` must be an object");
    } else {
      for (const k of Object.keys(c)) if (!COMP_KEYS.has(k)) err(`unknown compensation field \`${k}\``);
      if (typeof c.tool !== "string" || !TOOL_NAME.test(c.tool)) {
        err("`compensation.tool` must be a tool name");
      } else if (c.tool === raw.tool) {
        err("a tool cannot compensate itself");
      }
      const argument_map: Record<string, string> = {};
      if (c.argument_map !== undefined) {
        if (!isRecord(c.argument_map)) {
          err("`compensation.argument_map` must be an object");
        } else {
          for (const [k, v] of Object.entries(c.argument_map)) {
            if (typeof v !== "string" || !REF_PATTERN.test(v)) {
              err(`argument_map.${k} must be a reference like \`$args.id\` or \`$result.charge_id\``);
            } else {
              argument_map[k] = v;
            }
          }
        }
      }
      if (c.requires_approval !== undefined && typeof c.requires_approval !== "boolean") {
        err("`compensation.requires_approval` must be a boolean");
      }
      if (c.kind !== undefined && c.kind !== "inverse" && c.kind !== "compensation") err("`compensation.kind` must be inverse or compensation");
      let residue: string[] = [];
      if (c.residue !== undefined) {
        if (!Array.isArray(c.residue) || c.residue.some((r) => typeof r !== "string" || !r)) err("`compensation.residue` must be a list of strings");
        else residue = c.residue as string[];
      }
      if (c.kind === "inverse" && residue.length) err("an `inverse` compensation restores exact state, so it cannot declare residue; use kind: compensation");
      let comp_timeout: number | undefined;
      if (c.timeout_ms !== undefined) {
        comp_timeout = parseDuration(c.timeout_ms);
        if (comp_timeout === undefined) err("`compensation.timeout_ms` must be a positive number or a duration");
      }
      let verification: Verification | undefined;
      if (c.verification !== undefined) {
        const v = c.verification;
        if (!isRecord(v)) err("`compensation.verification` must be an object");
        else {
          for (const k of Object.keys(v)) if (!VERIFY_KEYS.has(k)) err(`unknown verification field \`${k}\``);
          if (typeof v.tool !== "string" || !TOOL_NAME.test(v.tool)) err("`verification.tool` must be a tool name");
          const vargs: Record<string, string> = {};
          if (v.arguments !== undefined) {
            if (!isRecord(v.arguments)) err("`verification.arguments` must be an object");
            else
              for (const [k, ref] of Object.entries(v.arguments)) {
                if (typeof ref !== "string" || !REF_PATTERN.test(ref)) err(`verification.arguments.${k} must be a reference like \`$result.id\``);
                else vargs[k] = ref;
              }
          }
          if (!isRecord(v.expect) || Object.keys(v.expect).length === 0) err("`verification.expect` must name at least one path and its expected value");
          const retries = v.retries === undefined ? 3 : v.retries;
          if (!Number.isInteger(retries) || (retries as number) < 1 || (retries as number) > 10) err("`verification.retries` must be 1..10");
          const backoff = v.backoff_ms === undefined ? 1000 : parseDuration(v.backoff_ms);
          if (backoff === undefined) err("`verification.backoff_ms` must be a positive number or a duration like 2s");
          if (typeof v.tool === "string" && isRecord(v.expect) && Number.isInteger(retries) && backoff !== undefined) {
            verification = { tool: v.tool, arguments: vargs, expect: v.expect, retries: retries as number, backoff_ms: backoff };
          }
        }
      }
      if (typeof c.tool === "string") {
        compensation = {
          tool: c.tool,
          argument_map,
          requires_approval: c.requires_approval === true,
          kind: c.kind === "inverse" ? "inverse" : "compensation",
          residue,
          ...(verification ? { verification } : {}),
          ...(comp_timeout !== undefined ? { timeout_ms: comp_timeout } : {}),
        };
      }
    }
  }

  if (effect === "reversible" || effect === "compensable") {
    if (raw.compensation === undefined) err(`${effect} tools must declare a compensation`);
  } else if (EFFECTS.includes(effect) && raw.compensation !== undefined) {
    err(`${effect} tools must not declare a compensation`);
  }

  // ---- metadata, risk, timeouts, retry, idempotency, audit ----
  const version = raw.version === undefined ? 1 : raw.version;
  if (!Number.isInteger(version) || (version as number) < 1) err("`version` must be a positive integer");
  const status = raw.status === undefined ? "approved" : raw.status;
  if (status !== "draft" && status !== "approved" && status !== "deprecated") err("`status` must be draft, approved or deprecated");
  for (const k of ["replaced_by", "owner", "oncall", "schema_hash"] as const) {
    if (raw[k] !== undefined && (typeof raw[k] !== "string" || !raw[k])) err(`\`${k}\` must be a non-empty string`);
  }
  let risk: ToolManifest["risk"];
  if (raw.risk !== undefined) {
    const r = raw.risk;
    if (!isRecord(r)) err("`risk` must be an object");
    else {
      for (const k of Object.keys(r)) if (!["data_class", "blast_radius", "environment"].includes(k)) err(`unknown risk field \`${k}\``);
      if (r.data_class !== undefined && (typeof r.data_class !== "string" || !r.data_class)) err("`risk.data_class` must be a non-empty string");
      if (r.blast_radius !== undefined && !BLAST_RADII.includes(r.blast_radius as BlastRadius)) err(`\`risk.blast_radius\` must be one of ${BLAST_RADII.join(", ")}`);
      if (r.environment !== undefined && typeof r.environment !== "string") err("`risk.environment` must be a string");
      risk = r as ToolManifest["risk"];
    }
  }
  let timeout_ms: number | undefined;
  if (raw.timeout_ms !== undefined) {
    timeout_ms = parseDuration(raw.timeout_ms);
    if (timeout_ms === undefined) err("`timeout_ms` must be a positive number or a duration like 30s");
  }
  let retry: ToolManifest["retry"];
  if (raw.retry !== undefined) {
    const r = raw.retry;
    if (!isRecord(r)) err("`retry` must be an object");
    else {
      for (const k of Object.keys(r)) if (!["attempts", "base_ms", "max_ms"].includes(k)) err(`unknown retry field \`${k}\``);
      const attempts = r.attempts === undefined ? 3 : r.attempts;
      const base = r.base_ms === undefined ? 200 : parseDuration(r.base_ms);
      const max = r.max_ms === undefined ? 5000 : parseDuration(r.max_ms);
      if (!Number.isInteger(attempts) || (attempts as number) < 1 || (attempts as number) > 10) err("`retry.attempts` must be 1..10");
      if (base === undefined || max === undefined) err("`retry.base_ms` and `retry.max_ms` must be positive durations");
      else retry = { attempts: attempts as number, base_ms: base, max_ms: max };
    }
    if (effect !== "read_only" && effect !== "idempotent") err("forward retry is only allowed for read_only and idempotent tools: retrying anything else could repeat its effect");
  }
  let idempotency: ToolManifest["idempotency"];
  if (raw.idempotency !== undefined) {
    const i = raw.idempotency;
    if (!isRecord(i)) err("`idempotency` must be an object");
    else {
      for (const k of Object.keys(i)) if (!["key", "scope"].includes(k)) err(`unknown idempotency field \`${k}\``);
      if (typeof i.key !== "string" || !/\{\{\s*args(\.[A-Za-z0-9_-]+)+\s*\}\}/.test(i.key)) err("`idempotency.key` must be a template using at least one `{{args.field}}`");
      if (i.scope !== undefined && !["run", "actor", "global"].includes(i.scope as string)) err("`idempotency.scope` must be run, actor or global");
      if (typeof i.key === "string") idempotency = { key: i.key, scope: (i.scope as "run" | "actor" | "global") ?? "run" };
    }
  }
  let audit: ToolManifest["audit"];
  if (raw.audit !== undefined) {
    const a = raw.audit;
    if (!isRecord(a)) err("`audit` must be an object");
    else {
      for (const k of Object.keys(a)) if (!["retention_days", "evidence_export", "redaction"].includes(k)) err(`unknown audit field \`${k}\``);
      if (a.retention_days !== undefined && (!Number.isInteger(a.retention_days) || (a.retention_days as number) < 1)) err("`audit.retention_days` must be a positive integer");
      if (a.evidence_export !== undefined && a.evidence_export !== "required" && a.evidence_export !== "optional") err("`audit.evidence_export` must be required or optional");
      if (a.redaction !== undefined && (!Array.isArray(a.redaction) || a.redaction.some((p) => typeof p !== "string" || !/^\$(args|result)(\.[A-Za-z0-9_-]+)+$/.test(p)))) err("`audit.redaction` must be a list of paths like `$args.client_secret`");
      audit = a as ToolManifest["audit"];
    }
  }
  if (status === "deprecated" && raw.replaced_by === raw.tool) err("a manifest cannot be replaced by itself");

  if (errors.length) return { ok: false, errors };
  const manifest: ToolManifest = {
    tool: raw.tool as string,
    effect,
    permission: raw.permission as string,
    approval,
    requires,
    version: version as number,
    status: status as ManifestStatus,
  };
  if (approval_rules) manifest.approval_rules = approval_rules;
  for (const k of ["replaced_by", "owner", "oncall", "schema_hash"] as const) if (typeof raw[k] === "string") manifest[k] = raw[k] as string;
  if (risk) manifest.risk = risk;
  if (timeout_ms !== undefined) manifest.timeout_ms = timeout_ms;
  if (retry) manifest.retry = retry;
  if (idempotency) manifest.idempotency = idempotency;
  if (audit) manifest.audit = audit;
  if (typeof raw.description === "string") manifest.description = raw.description;
  if (compensation) manifest.compensation = compensation;
  return { ok: true, manifest };
}

export class Registry {
  private readonly tools = new Map<string, ToolManifest>();

  /** Register one manifest. Throws {@link ManifestError} if it is invalid or a duplicate. */
  register(raw: unknown): ToolManifest {
    const r = validateManifest(raw);
    if (!r.ok) throw new ManifestError(r.errors);
    if (this.tools.has(r.manifest.tool)) {
      throw new ManifestError([`\`${r.manifest.tool}\`: already registered`]);
    }
    this.tools.set(r.manifest.tool, r.manifest);
    return r.manifest;
  }

  static from(raws: unknown[]): Registry {
    const reg = new Registry();
    for (const r of raws) reg.register(r);
    reg.assertValid();
    return reg;
  }

  /** Cross-reference check, done after all tools are registered. Returns a list of problems. */
  validate(): string[] {
    const errors: string[] = [];
    for (const m of this.tools.values()) {
      if (m.compensation && !this.tools.has(m.compensation.tool)) {
        errors.push(`\`${m.tool}\`: compensation tool \`${m.compensation.tool}\` is not registered`);
      }
      for (const r of m.requires) {
        if (!this.tools.has(r)) errors.push(`\`${m.tool}\`: required tool \`${r}\` is not registered`);
      }
      const v = m.compensation?.verification;
      if (v && !this.tools.has(v.tool)) errors.push(`\`${m.tool}\`: verification tool \`${v.tool}\` is not registered`);
      if (v && this.tools.get(v.tool) && this.tools.get(v.tool)?.effect !== "read_only") {
        errors.push(`\`${m.tool}\`: verification tool \`${v.tool}\` must be read_only: a check must not change anything`);
      }
      if (m.replaced_by && !this.tools.has(m.replaced_by)) errors.push(`\`${m.tool}\`: replaced_by \`${m.replaced_by}\` is not registered`);
    }
    return errors;
  }

  assertValid(): void {
    const errors = this.validate();
    if (errors.length) throw new ManifestError(errors);
  }

  has(tool: string): boolean {
    return this.tools.has(tool);
  }

  get(tool: string): ToolManifest | undefined {
    return this.tools.get(tool);
  }

  list(): ToolManifest[] {
    return [...this.tools.values()];
  }

  get size(): number {
    return this.tools.size;
  }
}

/** Resolve a `$args.x.y` / `$result.x.y` reference against an object. Returns undefined if absent. */
export function resolveRef(ref: string, source: "args" | "result", obj: unknown): unknown {
  const m = REF_PATTERN.exec(ref);
  if (!m || m[1] !== source) return undefined;
  const segments = ref.split(".").slice(1);
  let cur: unknown = obj;
  for (const seg of segments) {
    if (Array.isArray(cur)) {
      if (!/^\d+$/.test(seg)) return undefined;
      cur = cur[Number(seg)];
    } else if (isRecord(cur) && Object.prototype.hasOwnProperty.call(cur, seg)) {
      cur = cur[seg];
    } else {
      return undefined;
    }
  }
  return cur;
}

/**
 * A normalized manifest written back in the form an author writes (the `approval` object instead of the internal
 * `approval_rules`), so it passes the validator again. Used wherever a stored manifest is republished or edited.
 */
export function authorForm(m: ToolManifest): Record<string, unknown> {
  const { approval_rules: r, ...rest } = m as ToolManifest & Record<string, unknown>;
  if (!r) return rest;
  return {
    ...rest,
    approval: {
      required: m.approval === "always",
      roles: r.roles,
      quorum: r.quorum,
      ...(r.timeout_ms !== undefined ? { timeout: `${r.timeout_ms}ms` } : {}),
      on_timeout: r.on_timeout,
      ...(r.escalate_to ? { escalate_to: r.escalate_to } : {}),
    },
  };
}
