import { createServer } from "node:http";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { stringify } from "yaml";
import {
  ManifestRegistry,
  PolicyVersionError,
  PolicyVersions,
  RegistryError,
  Registry,
  banner,
  classifyTools,
  compensateMetaOf,
  generateSigningKey,
  hasErrors,
  hintsOf,
  lintManifests,
  loadRemoteRegistry,
  renderDiff,
  runManifestTests,
  schemaHash,
  suggestManifests,
  type McpToolInfo,
} from "../src/index.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), "rv-tool-"));
  dirs.push(d);
  return d;
};

const create = { tool: "issues.create", effect: "reversible", permission: "gh:write", compensation: { tool: "issues.close", argument_map: { number: "$result.number" } } };
const close = { tool: "issues.close", effect: "idempotent", permission: "gh:write" };

describe("diff", () => {
  it("shows only what changed, with context", () => {
    const a = ["a", "b", "c", "d", "e", "f", "g", "h"].join("\n");
    const b = ["a", "b", "c", "D", "e", "f", "g", "h", "i"].join("\n");
    expect(renderDiff(a, b, 1)).toBe(["...", " c", "-d", "+D", " e", "...", " h", "+i"].join("\n").replace(/^\.\.\.\n/, "") );
  });
});

describe("manifest registry", () => {
  it("publishes immutable versions, approves drafts, deprecates and restores, with a diff between versions", () => {
    const dir = tmp();
    let t = 1000;
    const reg = new ManifestRegistry(dir, { now: () => t++ });
    reg.publish(close, { by: "alice", status: "approved" });
    expect(reg.publish(create, { by: "alice" })).toMatchObject({ tool: "issues.create", version: 1 });
    expect(reg.history("issues.create")[0]).toMatchObject({ status: "draft", by: "alice" });
    expect(reg.load().size).toBe(1); // the draft is not enforceable
    expect(reg.load({ drafts: true }).size).toBe(2);
    expect(() => reg.approve("issues.create", { by: "alice", require_other: true })).toThrow(/author of a draft cannot approve/);
    const approved = reg.approve("issues.create", { by: "bob", require_other: true, note: "reviewed" });
    expect(approved.version).toBe(2);
    expect(reg.history("issues.create")[1]).toMatchObject({ status: "approved", approved_by: "bob", by: "alice" });
    expect(reg.load().size).toBe(2);

    reg.publish({ ...create, description: "Open an issue" }, { by: "alice", status: "approved" });
    expect(reg.diff("issues.create", 2, 3)).toContain('+  "description": "Open an issue",');
    const dep = reg.deprecate("issues.create", { by: "carol", replaced_by: "issues.close" });
    expect(reg.current("issues.create")).toMatchObject({ status: "deprecated", replaced_by: "issues.close", version: dep.version });
    expect(reg.load().get("issues.create")?.status).toBe("deprecated"); // still loaded: it must keep rolling back
    const restored = reg.rollbackTo("issues.create", 2, { by: "carol" });
    expect(restored.version).toBe(dep.version + 1);
    expect(reg.current("issues.create")?.status).toBe("approved");
    expect(reg.tools()).toEqual(["issues.close", "issues.create"]);
    expect(reg.verifyAll()).toEqual([]);
    expect(() => reg.history("nope")).toThrow(RegistryError);
    expect(() => reg.publish({ tool: "x", effect: "reversible", permission: "p" }, { by: "a" })).toThrow(/must declare a compensation/);
  });

  it("refuses a manifest edited outside the workflow, and a version whose index entry was edited to match", () => {
    const dir = tmp();
    const reg = new ManifestRegistry(dir);
    reg.publish(close, { by: "a", status: "approved" });
    const file = join(dir, "tools", "issues.close", "v1.json");
    writeFileSync(file, readFileSync(file, "utf8").replace('"gh:write"', '"gh:admin"'));
    expect(() => reg.load()).toThrow(/changed outside the registry/);
    expect(reg.verifyAll()[0]).toContain("checksum does not match");
  });

  it("with a trusted key every version must be signed by it", () => {
    const dir = tmp();
    const key = generateSigningKey();
    const signed = new ManifestRegistry(dir, { trusted_public_pem: key.public_pem });
    signed.publish(close, { by: "a", status: "approved", key });
    expect(signed.load().size).toBe(1);
    // someone with write access adds a manifest without the key
    new ManifestRegistry(dir).publish({ tool: "other", effect: "read_only", permission: "p" }, { by: "mallory", status: "approved" });
    expect(() => signed.load()).toThrow(/not signed by the trusted key/);
    const wrongKey = new ManifestRegistry(dir, { trusted_public_pem: generateSigningKey().public_pem });
    expect(() => wrongKey.get("issues.close", 1)).toThrow(/not signed/);
  });

  it("loads from a plain HTTP server that serves the same files, checking checksums", async () => {
    const dir = tmp();
    const reg = new ManifestRegistry(dir);
    reg.publish(create, { by: "a", status: "approved" });
    reg.publish(close, { by: "a", status: "approved" });
    let tamper = false;
    const server = createServer((req, res) => {
      const path = decodeURIComponent((req.url ?? "").split("?")[0] as string).replace(/^\//, "");
      try {
        let body = readFileSync(join(dir, path), "utf8");
        if (tamper && path.endsWith("issues.close/v1.json")) body = body.replace("gh:write", "gh:root");
        res.writeHead(200, { "content-type": "application/json" }).end(body);
      } catch {
        res.writeHead(404).end();
      }
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    try {
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      expect((await loadRemoteRegistry(url)).size).toBe(2);
      tamper = true;
      await expect(loadRemoteRegistry(url)).rejects.toThrow(/does not match its checksum/);
      await expect(loadRemoteRegistry("http://169.254.169.254")).rejects.toThrow(/metadata/);
      await expect(loadRemoteRegistry(`${url}/nope`)).rejects.toThrow(/answered 404/);
    } finally {
      server.close();
    }
  });
});

describe("policy versions", () => {
  const good = "version: 1\nrules:\n  - id: r\n    match: { tool: x }\n    action: deny\ntests:\n  - { name: x denied, input: { tool: x }, expect: deny }\n";
  it("publishes, refuses a failing or invalid policy, activates, diffs and detects tampering", () => {
    const dir = tmp();
    const pv = new PolicyVersions(dir);
    expect(PolicyVersions.isVersioned(dir)).toBe(false);
    const v1 = pv.publish(good, { by: "alice", note: "first" });
    expect(v1).toMatchObject({ version: 1, tests_passed: 1 });
    expect(PolicyVersions.isVersioned(dir)).toBe(true);
    expect(pv.activeVersion()).toBe(1);
    expect(() => pv.publish(good.replace("expect: deny", "expect: allow"), { by: "a" })).toThrow(/1 of the policy's own tests fail: x denied/);
    expect(() => pv.publish("rules: [{ id: a, action: nope }]", { by: "a" })).toThrow();
    const v2 = pv.publish(good.replace("tool: x", "tool: y").replace("{ tool: x }", "{ tool: y }"), { by: "bob", activate: false });
    expect(pv.activeVersion()).toBe(1);
    pv.activate(v2.version);
    expect(pv.activeVersion()).toBe(2);
    expect(pv.diff(1, 2)).toContain("+    match: { tool: y }");
    pv.activate(1); // rollback
    expect(pv.doc(pv.activeVersion() as number).rules[0]?.id).toBe("r");
    expect(pv.history().map((h) => h.by)).toEqual(["alice", "bob"]);
    writeFileSync(join(dir, "policy-v1.yaml"), good.replace("deny", "allow"));
    expect(() => pv.activeText()).toThrow(PolicyVersionError);
    expect(() => pv.activate(9)).toThrow(/no policy version 9/);
    expect(readdirSync(dir).sort()).toEqual(["policy-index.json", "policy-v1.yaml", "policy-v2.yaml"]);
  });
});

describe("lint", () => {
  it("flags unsafe, incomplete and contradictory manifests, and checks against the upstream's schemas", () => {
    const reg = Registry.from([
      { tool: "a.read", effect: "read_only", permission: "a:write" },
      { tool: "a.write", effect: "compensable", permission: "a:write", compensation: { tool: "a.undo", argument_map: { id: "$args.missing" } }, idempotency: { key: "{{args.ghost}}" } },
      { tool: "a.undo", effect: "reversible", permission: "a:write", compensation: { tool: "a.redo", kind: "compensation", residue: ["x"] } },
      { tool: "a.redo", effect: "read_only", permission: "a:read" },
      { tool: "a.drop", effect: "irreversible", permission: "a:admin", status: "draft" },
      { tool: "loop.1", effect: "read_only", permission: "l", requires: ["loop.2"] },
      { tool: "loop.2", effect: "read_only", permission: "l", requires: ["loop.1"] },
    ]);
    const f = lintManifests(reg, { tools: [{ name: "a.write", inputSchema: { properties: { id: {} } } }, { name: "a.unknown" }] });
    const codes = (tool: string) => f.filter((x) => x.tool === tool).map((x) => x.code);
    expect(codes("a.read")).toContain("L019");
    expect(codes("a.write")).toEqual(expect.arrayContaining(["L010", "L011", "L012", "L013", "L014", "L017", "L020", "L016"]));
    expect(codes("a.undo")).toContain("L030");
    expect(codes("a.drop")).toEqual(expect.arrayContaining(["L015", "L021", "L024"]));
    expect(codes("loop.1")).toContain("L023");
    expect(f.find((x) => x.code === "L035")?.tool).toBe("a.unknown");
    expect(f.find((x) => x.code === "L034")?.tool).toBe("a.read");
    expect(hasErrors(f)).toBe(true);
    const clean = Registry.from([{ tool: "r", effect: "read_only", permission: "r:read", description: "reads" }]);
    expect(lintManifests(clean)).toEqual([]);
  });
});

const TOOLS: McpToolInfo[] = [
  { name: "gh.get_issue", description: "Get an issue", annotations: { readOnlyHint: true }, inputSchema: { properties: { number: {} } } },
  { name: "gh.create_issue", description: "Open an issue\nlong text", inputSchema: { properties: { title: {}, body: {} }, required: ["title"] } },
  { name: "gh.close_issue", description: "Close an issue", annotations: { idempotentHint: true }, inputSchema: { properties: { number: {} }, required: ["number"] } },
  { name: "gh.delete_repo", description: "Delete a repo", annotations: { destructiveHint: true }, inputSchema: { properties: { name: {} } } },
  { name: "gh.list_labels", inputSchema: { properties: {} } },
  { name: "pay.charge", description: "Charge a customer card", inputSchema: { properties: { amount: {}, customer: {} } }, _meta: { "mcp-compensate": { compensable: true, compensation: { tool: "pay.refund", mapping: { charge_id: "$result.id", amount: "$args.amount", bogus: "nope" } } } } },
  { name: "pay.refund", description: "Refund a charge", inputSchema: { properties: { charge_id: {}, amount: {} } } },
  { name: "dns.set_record", description: "Set a record", annotations: { openWorldHint: true }, inputSchema: { properties: { name: {}, value: {} } } },
];

describe("suggest manifests", () => {
  it("drafts effects, undo pairs and argument maps from names, schemas and hints, always as drafts", () => {
    const r = suggestManifests(TOOLS, { server: "github" });
    const by = Object.fromEntries(r.suggestions.map((s) => [s.manifest.tool as string, s]));
    expect(by["gh.get_issue"]?.manifest).toMatchObject({ effect: "read_only", permission: "github:read", status: "draft" });
    expect(by["gh.get_issue"]?.notes[0]).toContain("readOnlyHint");
    expect(by["gh.list_labels"]).toMatchObject({ confidence: "low", manifest: { effect: "read_only" } });
    expect(by["gh.create_issue"]?.manifest).toMatchObject({ effect: "compensable", compensation: { tool: "gh.close_issue", argument_map: { number: "$result.number" } } });
    expect(by["gh.create_issue"]?.manifest.description).toBe("Open an issue");
    expect(by["gh.delete_repo"]?.manifest).toMatchObject({ effect: "irreversible", approval: "always", permission: "github:admin", risk: { blast_radius: "high" } });
    expect(by["gh.close_issue"]?.manifest.effect).toBe("idempotent");
    expect(by["dns.set_record"]?.manifest.effect).toBe("irreversible"); // no inverse found: the safe default
    expect(by["dns.set_record"]?.notes.join()).toContain("openWorldHint");
    // mcp-compensate wins over guessing, keeps only valid references, and the undo is drafted too
    expect(by["pay.charge"]).toMatchObject({ confidence: "high", manifest: { effect: "compensable", compensation: { tool: "pay.refund", argument_map: { charge_id: "$result.id", amount: "$args.amount" } }, risk: { data_class: "financial" } } });
    expect(by["pay.refund"]?.manifest.effect).toBe("idempotent");
    expect(Object.values(by).every((s) => s.manifest.status === "draft")).toBe(true);
    // the drafts are valid manifests once the TODO residue note is accepted
    const reg = Registry.from(r.suggestions.map((s) => s.manifest));
    expect(reg.size).toBe(r.suggestions.length);
    expect(r.suggestions.every((s) => typeof s.manifest.schema_hash === "string" || !TOOLS.find((t) => t.name === s.manifest.tool)?.inputSchema)).toBe(true);
  });

  it("skips tools that already have manifests, can be limited, and reports schema hashes that change with the schema", () => {
    const existing = Registry.from([{ tool: "gh.get_issue", effect: "read_only", permission: "p" }]);
    const r = suggestManifests(TOOLS, { existing, only: ["gh.get_issue", "gh.delete_repo"] });
    expect(r.skipped).toEqual(["gh.get_issue"]);
    expect(r.suggestions.map((s) => s.manifest.tool)).toEqual(["gh.delete_repo"]);
    const a = schemaHash({ name: "t", inputSchema: { properties: { a: {} } } });
    expect(schemaHash({ name: "t", inputSchema: { properties: { a: {} } } })).toBe(a);
    expect(schemaHash({ name: "t", inputSchema: { properties: { a: {}, b: {} } } })).not.toBe(a);
  });

  it("reads annotations and the mcp-compensate convention in its accepted shapes", () => {
    expect(hintsOf({ name: "x", annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true, title: "t" } })).toEqual({ read_only: true, destructive: false, idempotent: true, open_world: true });
    expect(compensateMetaOf({ name: "x", annotations: { "mcp-compensate": { irreversible: true } } })).toEqual({ irreversible: true });
    expect(compensateMetaOf({ name: "x", _meta: { compensate: { compensation: "undo_x" } } })).toEqual({ compensation: { tool: "undo_x", mapping: {} } });
    expect(compensateMetaOf({ name: "x", _meta: { "mcp-compensate": { readonly: true } } })).toEqual({ readonly: true });
    expect(compensateMetaOf({ name: "x" })).toBeUndefined();
    expect(compensateMetaOf({ name: "x", _meta: { "mcp-compensate": "yes" } })).toBeUndefined();
  });

  it("the drafts survive a YAML round trip", () => {
    const text = stringify(suggestManifests(TOOLS.slice(0, 3)).suggestions.map((s) => s.manifest));
    expect(text).toContain("status: draft");
  });
});

describe("classification banner", () => {
  it("separates classified tools, unclassified reads, unclassified changes and destructive ones", () => {
    const reg = Registry.from([{ tool: "gh.get_issue", effect: "read_only", permission: "p" }, { tool: "gh.create_issue", effect: "idempotent", permission: "p", status: "draft" }]);
    const rows = classifyTools(reg, TOOLS.slice(0, 5));
    expect(rows.map((r) => [r.name, r.class])).toEqual([
      ["gh.get_issue", "classified"],
      ["gh.create_issue", "classified"],
      ["gh.close_issue", "unclassified_mutation"],
      ["gh.delete_repo", "destructive_no_manifest"],
      ["gh.list_labels", "unclassified_mutation"],
    ]);
    const text = banner(rows, { mode: "observe", next: "Next: reversi suggest-manifest" });
    expect(text).toContain("Reversi gateway running in observe mode.");
    expect(text).toContain("OK     gh.get_issue - read_only");
    expect(text).toContain("(draft)");
    expect(text).toContain("BLOCK  gh.delete_repo");
    expect(text).toContain("2 unclassified changes, 1 destructive");
    expect(text.trim().endsWith("Next: reversi suggest-manifest")).toBe(true);
    expect(classifyTools(Registry.from([]), [{ name: "r", annotations: { readOnlyHint: true } }])[0]?.class).toBe("unclassified_read_hint");
  });
});

describe("manifest contract tests", () => {
  const reg = Registry.from([
    { tool: "orders.create", effect: "reversible", permission: "p", compensation: { tool: "orders.cancel", argument_map: { id: "$result.id" } } },
    { tool: "orders.cancel", effect: "idempotent", permission: "p" },
    { tool: "pay.charge", effect: "compensable", permission: "p", requires: ["orders.create"], idempotency: { key: "{{args.order}}" }, compensation: { tool: "pay.refund", argument_map: { charge: "$result.charge_id", amount: "$args.amount" }, verification: { tool: "pay.get", arguments: { charge: "$result.charge_id" }, expect: { status: "refunded" } } } },
    { tool: "pay.refund", effect: "idempotent", permission: "p" },
    { tool: "pay.get", effect: "read_only", permission: "p" },
    { tool: "never.tested", effect: "idempotent", permission: "p" },
  ]);

  it("passes a correct manifest and names every way a wrong expectation fails", async () => {
    const { results, untested } = await runManifestTests(reg, [
      { name: "order maps its id", tool: "orders.create", result: { id: 7 }, expect_handle: { id: 7 }, expect_plan: "compensate" },
      { name: "charge maps charge, amount and verification", tool: "pay.charge", args: { order: "o1", amount: 20 }, result: { charge_id: "c1" }, expect_handle: { charge: "c1", amount: 20 }, expect_verification: { charge: "c1" }, verify_with: { status: "refunded" }, expect_verified: true },
      { name: "read-back that disagrees is rejected", tool: "pay.charge", args: { order: "o1", amount: 20 }, result: { charge_id: "c1" }, verify_with: { status: "pending" }, expect_verified: false },
      { name: "a failure leaves nothing to undo", tool: "orders.create", fail: "boom" },
      { name: "duplicates are refused", tool: "pay.charge", args: { order: "o1", amount: 1 }, result: { charge_id: "c" }, expect_duplicate: true },
      { name: "missing key argument is refused", tool: "pay.charge", args: {}, expect_blocked: "missing or not simple" },
      { name: "wrong expectation", tool: "orders.create", result: { id: 7 }, expect_handle: { id: 8 } },
      { name: "result lacks the id", tool: "orders.create", result: { nope: 1 }, expect_plan: "compensate" },
      { name: "should have been refused", tool: "orders.cancel", expect_blocked: "x" },
      { name: "unknown", tool: "ghost" },
    ]);
    const by = Object.fromEntries(results.map((r) => [r.name, r]));
    for (const ok of ["order maps its id", "charge maps charge, amount and verification", "read-back that disagrees is rejected", "a failure leaves nothing to undo", "duplicates are refused", "missing key argument is refused"]) expect(by[ok]?.problems, ok).toEqual([]);
    expect(by["wrong expectation"]?.problems[0]).toContain("`id` is 7, expected 8");
    expect(by["result lacks the id"]?.problems[0]).toContain("expected plan kind compensate, got unrecoverable");
    expect(by["should have been refused"]?.problems[0]).toContain("expected the call to be refused");
    expect(by["unknown"]?.problems[0]).toContain("no manifest for `ghost`");
    expect(untested.sort()).toEqual(["never.tested", "pay.refund"]);
  });
});
