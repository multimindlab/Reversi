import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Approvals, ContentChecker, Ledger, ManifestRegistry, Policy, PolicyVersions, Registry, Reversi } from "@multimindlab/reversi";
import { createApp } from "../src/index.js";

const MANIFESTS = [
  { tool: "create_order", effect: "reversible", permission: "o:w", compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } } },
  { tool: "cancel_order", effect: "idempotent", permission: "o:w" },
];

function make(console_: { mode: "off" | "open" | "login"; role?: "auditor" | "operator" | "admin" } | undefined, extra: Record<string, unknown> = {}) {
  const approvals = new Approvals();
  const reversi = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(), approver: approvals.asApprover(), policy: Policy.from({ rules: [] }), content: new ContentChecker() });
  const app = createApp({ reversi, approvals, keys: [{ name: "ops", role: "operator", key: "k-ops" }], session_secret: "s", ...(console_ ? { console: console_ as never } : {}), ...extra });
  return { app, reversi };
}
const local = { host: "localhost:8787" };

describe("console modes", () => {
  it("off serves nothing", async () => {
    const { app } = make(undefined);
    for (const p of ["/console", "/console/runs", "/console/login"]) expect((await app.request(p, { headers: local })).status).toBe(404);
  });

  it("open needs no login, but refuses foreign hosts and origins", async () => {
    const { app } = make({ mode: "open" });
    const ok = await app.request("/console/runs", { headers: local });
    expect(ok.status).toBe(200);
    expect(await ok.text()).toContain("open console, no login");
    expect((await app.request("/console/runs", { headers: { host: "reversi.example.com" } })).status).toBeGreaterThanOrEqual(400);
    expect((await app.request("/console/runs", { headers: { ...local, "sec-fetch-site": "cross-site" } })).status).toBeGreaterThanOrEqual(400);
    const post = await app.request("/console/halt", { method: "POST", headers: { ...local, origin: "http://evil.example", "content-type": "application/x-www-form-urlencoded" }, body: "reason=x" });
    expect(post.status).toBeGreaterThanOrEqual(400);
  });

  it("open never runs as admin", () => {
    expect(() => make({ mode: "open", role: "admin" })).toThrow(/never runs as admin/);
  });
});

describe("console pages", () => {
  const get = (app: ReturnType<typeof make>["app"], p: string) => app.request(p, { headers: local });
  it("render for an operator in open mode", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rv-console-"));
    const { app } = make({ mode: "open" }, { registry_dir: join(dir, "reg"), policy_dir: join(dir, "pol") });
    for (const p of ["/console/runs", "/console/approvals", "/console/alerts", "/console/manifests", "/console/manifests/new", "/console/manifests/import", "/console/manifests/create_order", "/console/policy", "/console/impact?tool=create_order&args=%7B%7D", "/console/tools", "/console/connectors", "/console/settings", "/console/evidence", "/console/compare"]) {
      const r = await get(app, p);
      expect(r.status, p).toBe(200);
    }
    expect(await (await get(app, "/console/impact?tool=create_order")).text()).toContain("rollback outlook");
  });

  it("validates a manifest and publishes a draft that an admin must approve", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rv-console-"));
    const reg = new ManifestRegistry(join(dir, "reg"));
    const { app } = make({ mode: "open" }, { registry_dir: join(dir, "reg"), policy_dir: join(dir, "pol") });
    const csrf = /name="csrf" value="([^"]+)"/.exec(await (await get(app, "/console/manifests/new")).text())?.[1] ?? "";
    const send = (path: string, fields: Record<string, string>) =>
      app.request(path, { method: "POST", headers: { ...local, origin: "http://localhost:8787", "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, ...fields }) });
    const text = "tool: shop.ping\neffect: read_only\npermission: shop:read\n";
    const v = await (await send("/console/manifests/save", { text, do: "validate" })).text();
    expect(v).toContain("Valid.");
    const bad = await (await send("/console/manifests/save", { text: "tool: x\neffect: nonsense\npermission: p\n", do: "validate" })).text();
    expect(bad).toContain("Not valid");
    const saved = await send("/console/manifests/save", { text, do: "draft" });
    expect(saved.status).toBe(303);
    expect(reg.history("shop.ping").at(-1)?.status).toBe("draft");
    expect((await send("/console/manifests/save", { text, do: "approved" })).status).toBe(403); // open mode is never admin
    const built = await (await send("/console/manifests/build", { tool: "shop.charge", effect: "compensable", permission: "shop:w", comp_tool: "shop.refund", map_name0: "id", map_src0: "$result", map_path0: "id" })).text();
    expect(built).toContain("shop.refund");
  });

  it("validates a policy and runs its tests", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rv-console-"));
    const { app } = make({ mode: "open" }, { registry_dir: join(dir, "reg"), policy_dir: join(dir, "pol") });
    const csrf = /name="csrf" value="([^"]+)"/.exec(await (await get(app, "/console/policy")).text())?.[1] ?? "";
    const send = (fields: Record<string, string>) => app.request("/console/policy/save", { method: "POST", headers: { ...local, origin: "http://localhost:8787", "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, ...fields }) });
    const good = await (await send({ do: "validate", text: "version: 1\nrules:\n  - id: r\n    match: { tool: 'create_order' }\n    action: deny\n" })).text();
    expect(good).toContain("Valid");
    expect(await (await send({ do: "validate", text: "rules: 5" })).text()).toContain("Not valid");
    expect((await send({ do: "publish", text: "version: 1\nrules: []\n" })).status).toBe(403);
    expect(new PolicyVersions(join(dir, "pol")).history()).toHaveLength(0);
  });
});
