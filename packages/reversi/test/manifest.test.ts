import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ManifestError, Registry, resolveRef, validateManifest } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(readFileSync(join(here, "../../../schemas/manifest.schema.json"), "utf8"));

const comp = (tool: string, extra: object = {}) => ({ tool, argument_map: {}, ...extra });

// [label, manifest, shouldBeValid]
const FIXTURES: Array<[string, unknown, boolean]> = [
  ["read_only", { tool: "read_order", effect: "read_only", permission: "orders:read" }, true],
  ["idempotent", { tool: "put_flag", effect: "idempotent", permission: "flags:write" }, true],
  [
    "compensable with argument map",
    {
      tool: "charge_card",
      effect: "compensable",
      permission: "pay:write",
      compensation: comp("refund", { argument_map: { charge_id: "$result.charge_id", amt: "$args.amount" } }),
    },
    true,
  ],
  [
    "reversible",
    { tool: "create_draft", effect: "reversible", permission: "docs:write", compensation: comp("delete_draft") },
    true,
  ],
  ["irreversible", { tool: "send_email", effect: "irreversible", permission: "mail:send" }, true],
  ["irreversible, explicit approval", { tool: "send_email", effect: "irreversible", permission: "mail:send", approval: "always" }, true],
  ["with requires", { tool: "b", effect: "read_only", permission: "p", requires: ["a"] }, true],
  ["compensable without compensation", { tool: "x", effect: "compensable", permission: "p" }, false],
  ["reversible without compensation", { tool: "x", effect: "reversible", permission: "p" }, false],
  ["read_only with compensation", { tool: "x", effect: "read_only", permission: "p", compensation: comp("y") }, false],
  ["irreversible with approval never", { tool: "x", effect: "irreversible", permission: "p", approval: "never" }, false],
  ["unknown effect", { tool: "x", effect: "magic", permission: "p" }, false],
  ["missing permission", { tool: "x", effect: "read_only" }, false],
  ["empty tool name", { tool: "", effect: "read_only", permission: "p" }, false],
  ["permission with whitespace", { tool: "x", effect: "read_only", permission: "a b" }, false],
  ["unknown field", { tool: "x", effect: "read_only", permission: "p", colour: "red" }, false],
  [
    "bad argument reference",
    { tool: "x", effect: "compensable", permission: "p", compensation: comp("y", { argument_map: { a: "args.id" } }) },
    false,
  ],
  [
    "bare $args reference",
    { tool: "x", effect: "compensable", permission: "p", compensation: comp("y", { argument_map: { a: "$args" } }) },
    false,
  ],
  ["duplicate requires", { tool: "x", effect: "read_only", permission: "p", requires: ["a", "a"] }, false],
  ["bad approval value", { tool: "x", effect: "read_only", permission: "p", approval: "sometimes" }, false],
];

describe("validateManifest", () => {
  it.each(FIXTURES)("%s", (_label, manifest, valid) => {
    expect(validateManifest(manifest).ok).toBe(valid);
  });

  it("fills in defaults", () => {
    const r = validateManifest({
      tool: "charge",
      effect: "compensable",
      permission: "pay:write",
      compensation: { tool: "refund" },
    });
    expect(r.ok && r.manifest).toMatchObject({
      approval: "never",
      requires: [],
      compensation: { tool: "refund", argument_map: {}, requires_approval: false },
    });
  });

  it("forces approval for irreversible tools", () => {
    const r = validateManifest({ tool: "send", effect: "irreversible", permission: "mail:send" });
    expect(r.ok && r.manifest.approval).toBe("always");
  });

  it("rejects self-compensation and self-requirement", () => {
    expect(validateManifest({ tool: "a", effect: "reversible", permission: "p", compensation: comp("a") }).ok).toBe(false);
    expect(validateManifest({ tool: "a", effect: "read_only", permission: "p", requires: ["a"] }).ok).toBe(false);
  });

  it("rejects non-objects", () => {
    expect(validateManifest(null).ok).toBe(false);
    expect(validateManifest([]).ok).toBe(false);
    expect(validateManifest("tool").ok).toBe(false);
  });

  it("reports every problem, not just the first", () => {
    const r = validateManifest({ tool: "x", effect: "nope", permission: "", colour: 1 });
    expect(!r.ok && r.errors.length).toBeGreaterThanOrEqual(3);
  });
});

describe("JSON Schema agrees with the validator", async () => {
  // Ajv's ESM/CJS interop differs by loader, so resolve the constructor defensively.
  const mod: any = await import("ajv/dist/2020.js");
  const Ajv2020 = mod.default?.default ?? mod.default ?? mod;
  const validate = new Ajv2020({ strict: false }).compile(schema);

  it.each(FIXTURES)("%s", (_label, manifest, valid) => {
    expect(validate(manifest)).toBe(valid);
  });
});

describe("Registry", () => {
  const base = [
    { tool: "charge", effect: "compensable", permission: "p", compensation: { tool: "refund" } },
    { tool: "refund", effect: "idempotent", permission: "p" },
  ];

  it("registers and looks up tools", () => {
    const reg = Registry.from(base);
    expect(reg.size).toBe(2);
    expect(reg.get("charge")?.compensation?.tool).toBe("refund");
    expect(reg.has("nope")).toBe(false);
  });

  it("rejects duplicates", () => {
    const reg = new Registry();
    reg.register(base[1]);
    expect(() => reg.register(base[1])).toThrow(ManifestError);
  });

  it("flags unknown compensation and required tools only after all are registered", () => {
    const reg = new Registry();
    reg.register(base[0]); // refund not registered yet: fine until validate()
    expect(reg.validate()).toEqual(["`charge`: compensation tool `refund` is not registered"]);
    reg.register(base[1]);
    expect(reg.validate()).toEqual([]);

    const reg2 = new Registry();
    reg2.register({ tool: "b", effect: "read_only", permission: "p", requires: ["ghost"] });
    expect(reg2.validate()).toEqual(["`b`: required tool `ghost` is not registered"]);
    expect(() => reg2.assertValid()).toThrow(ManifestError);
  });
});

describe("resolveRef", () => {
  const obj = { id: 7, nested: { list: [{ k: "v" }] }, "dash-key": 1 };
  it("resolves dotted paths, array indexes and dashes", () => {
    expect(resolveRef("$args.id", "args", obj)).toBe(7);
    expect(resolveRef("$args.nested.list.0.k", "args", obj)).toBe("v");
    expect(resolveRef("$args.dash-key", "args", obj)).toBe(1);
  });
  it("returns undefined for missing paths or the wrong source", () => {
    expect(resolveRef("$args.missing", "args", obj)).toBeUndefined();
    expect(resolveRef("$result.id", "args", obj)).toBeUndefined();
    expect(resolveRef("$args.nested.list.x", "args", obj)).toBeUndefined();
  });
  it("does not walk the prototype chain", () => {
    expect(resolveRef("$args.constructor", "args", {})).toBeUndefined();
    expect(resolveRef("$args.__proto__", "args", {})).toBeUndefined();
  });
});
