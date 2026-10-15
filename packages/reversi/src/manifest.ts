/**
 * The tool manifest: how reversible a tool is, what undoes it, which permission it needs.
 * A tool without a manifest is an incomplete tool, the way a function that allocates without
 * a matching free is incomplete.
 */

export const EFFECTS = ["read_only", "idempotent", "reversible", "compensable", "irreversible"] as const;
export type Effect = (typeof EFFECTS)[number];

export interface Compensation {
  /** Name of the tool that undoes this one. */
  tool: string;
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
]);
const COMP_KEYS = new Set(["tool", "argument_map", "requires_approval"]);

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

export type ValidateResult = { ok: true; manifest: ToolManifest } | { ok: false; errors: string[] };

/** Validate one manifest and fill in defaults. Does not check references to other tools. */
export function validateManifest(raw: unknown): ValidateResult {
  const errors: string[] = [];
  if (!isRecord(raw)) return { ok: false, errors: ["manifest must be an object"] };

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
  if (raw.approval !== undefined) {
    if (raw.approval === "never" || raw.approval === "always") approval = raw.approval;
    else err("`approval` must be `never` or `always`");
  }
  if (effect === "irreversible") {
    if (raw.approval === "never") err("irreversible tools must require approval");
    approval = "always";
  }

  let requires: string[] = [];
  if (raw.requires !== undefined) {
    if (!Array.isArray(raw.requires) || raw.requires.some((r) => typeof r !== "string" || !r)) {
      err("`requires` must be a list of tool names");
    } else {
      requires = raw.requires as string[];
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
      if (typeof c.tool === "string") {
        compensation = {
          tool: c.tool,
          argument_map,
          requires_approval: c.requires_approval === true,
        };
      }
    }
  }

  if (effect === "reversible" || effect === "compensable") {
    if (raw.compensation === undefined) err(`${effect} tools must declare a compensation`);
  } else if (EFFECTS.includes(effect) && raw.compensation !== undefined) {
    err(`${effect} tools must not declare a compensation`);
  }

  if (errors.length) return { ok: false, errors };
  const manifest: ToolManifest = {
    tool: raw.tool as string,
    effect,
    permission: raw.permission as string,
    approval,
    requires,
  };
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
