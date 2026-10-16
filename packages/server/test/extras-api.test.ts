import { createHmac } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ManifestRegistry,
  PolicyVersions,
  generateSigningKey,
  openEngine,
  verifyBundle,
  type CompensationCall,
  type EngineHandle,
} from "@multimindlab/reversi";
import { createApp, type ApiKey } from "../src/index.js";

const MANIFESTS = [
  { tool: "create_order", effect: "reversible", permission: "o:w", compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } } },
  { tool: "cancel_order", effect: "idempotent", permission: "o:w" },
  { tool: "refund", effect: "idempotent", permission: "o:w" },
  { tool: "payout", effect: "idempotent", permission: "o:w" },
  { tool: "lookup", effect: "read_only", permission: "o:r" },
  { tool: "book", effect: "reversible", permission: "o:w", compensation: { tool: "unbook", argument_map: { id: "$result.id" }, requires_approval: true } },
  { tool: "unbook", effect: "idempotent", permission: "o:w" },
];
const POLICY = `version: 1
rules:
  - id: refund-approval
    match: { tool: refund }
    action: require_approval
    approvers: [approver]
  - id: payout-approval
    match: { tool: payout }
    action: require_approval
retention:
  default_days: 1
`;
const KEYS: ApiKey[] = [
  { name: "agent", role: "agent", key: "k-agent" },
  { name: "audit", role: "auditor", key: "k-audit" },
  { name: "appr", role: "approver", key: "k-appr" },
  { name: "ops", role: "operator", key: "k-ops" },
  { name: "root", role: "admin", key: "k-root" },
];
const ORDER = ["k-agent", "k-audit", "k-appr", "k-ops", "k-root"] as const;
type Key = (typeof ORDER)[number];
const NAMES: Record<Key, string> = { "k-agent": "agent", "k-audit": "auditor", "k-appr": "approver", "k-ops": "operator", "k-root": "admin" };
const SLACK_SECRET = "slack-signing-secret";

const dirs: string[] = [];
const engines: EngineHandle[] = [];
afterEach(async () => {
  while (engines.length) await (engines.pop() as EngineHandle).close();
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

interface Opts {
  noEngine?: boolean;
  noCapture?: boolean;
  noRetention?: boolean;
  noAnchor?: boolean;
  noCompensator?: boolean;
  noKeysFile?: boolean;
  noRegistry?: boolean;
  noSlack?: boolean;
}

async function fx(o: Opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), "rv-extras-"));
  dirs.push(dir);
  const reg = join(dir, "registry");
  const pol = join(dir, "policy");
  const keysFile = join(dir, "keys.json");
  const anchorFile = join(dir, "anchors.jsonl");
  const sk = generateSigningKey();
  writeFileSync(join(dir, "sign.pem"), sk.private_pem);
  const mr = new ManifestRegistry(reg);
  for (const m of MANIFESTS) mr.publish(m, { by: "ci", status: "approved" });
  const pv = new PolicyVersions(pol);
  pv.publish(o.noRetention ? POLICY.replace(/retention:\n {2}default_days: 1\n/, "") : POLICY, { by: "ci" });
  writeFileSync(keysFile, JSON.stringify(KEYS));
  const clock = { t: Date.now() + 60_000 };
  const engine = await openEngine({
    manifests: reg,
    policy: pol,
    data: { dir: join(dir, "data"), store: "files" },
    capture: o.noCapture ? undefined : { enabled: true },
    signing_key: join(dir, "sign.pem"),
    anchor: o.noAnchor ? undefined : { sinks: [{ type: "file", path: anchorFile }] },
    log: () => {},
  });
  engines.push(engine);
  const compensations: CompensationCall[] = [];
  const compensator = vi.fn(async (c: CompensationCall) => {
    compensations.push(c);
  });
  const app = createApp({
    reversi: engine.reversi,
    approvals: engine.approvals,
    delegations: engine.delegations,
    keys: KEYS,
    session_secret: "s",
    now: () => clock.t,
    ...(o.noEngine ? {} : { engine }),
    ...(o.noRegistry ? {} : { registry_dir: reg, policy_dir: pol }),
    ...(o.noCompensator ? {} : { compensator }),
    ...(o.noKeysFile ? {} : { keys_file: keysFile }),
    ...(o.noSlack ? {} : { slack: { signing_secret: SLACK_SECRET, users: { U_APPR: { name: "slack-appr" }, U_AUD: { name: "slack-aud", roles: ["auditor" as const] }, U_GROUP: { name: "slack-fin", roles: ["approver" as const], groups: ["finance"] } } } }),
    connectors: async () => [{ name: "github", kind: "mcp", healthy: true, tools: 3, classified: 2, unclassified: 1 }],
    health: async () => [{ name: "upstream-a", ok: false }],
  });
  const call = async (key: string | null, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) => {
    const h: Record<string, string> = { ...headers };
    if (key) h.authorization = `Bearer ${key}`;
    let payload: string | undefined;
    if (body !== undefined && method !== "GET") {
      h["content-type"] ??= "application/json";
      payload = typeof body === "string" ? body : JSON.stringify(body);
    }
    const res = await app.request(path, { method, headers: h, body: payload });
    const text = await res.text();
    let json: any;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: res.status, json, text, res };
  };
  return { dir, reg, pol, keysFile, anchorFile, engine, app, call, clock, compensator, compensations, mr, pv, sk };
}
type Fx = Awaited<ReturnType<typeof fx>>;

// agent journals: an executed create_order (result id 7), a pending refund, and a blocked unknown tool
async function seed(f: Fx, run = "r1") {
  const open = await f.call("k-agent", "POST", "/v1/runs", { run_id: run, permissions: ["o:w", "o:r"] });
  expect(open.status).toBe(201);
  const a = await f.call("k-agent", "POST", `/v1/runs/${run}/intents`, { tool: "create_order", args: { sku: "abc", qty: 2 }, reason: "customer asked" });
  expect(a.json.decision).toBe("allow");
  const done = await f.call("k-agent", "POST", `/v1/runs/${run}/steps/${a.json.step}/outcome`, { status: "succeeded", result: { id: 7 } });
  expect(done.status).toBe(200);
  return { step: a.json.step as number };
}

const rolesBelow = (min: Key): Key[] => ORDER.slice(0, ORDER.indexOf(min)) as unknown as Key[];
const rolesFrom = (min: Key): Key[] => ORDER.slice(ORDER.indexOf(min)) as unknown as Key[];
async function expectForbidden(f: Fx, min: Key, method: string, path: string, body?: unknown) {
  for (const k of rolesBelow(min)) {
    const r = await f.call(k, method, path, body);
    expect(r.status, `${method} ${path} as ${NAMES[k]}`).toBe(403);
  }
}
async function expectAllowed(f: Fx, min: Key, method: string, path: string, body?: unknown) {
  for (const k of rolesFrom(min)) {
    const r = await f.call(k, method, path, body);
    expect(r.status, `${method} ${path} as ${NAMES[k]}`).not.toBe(403);
    expect(r.status, `${method} ${path} as ${NAMES[k]}`).not.toBe(401);
  }
}

describe("authentication and engine gating", () => {
  it("every extras route rejects a missing or wrong key with 401", async () => {
    const f = await fx();
    const routes: Array<[string, string]> = [
      ["GET", "/v1/search/runs"], ["GET", "/v1/search/records"], ["GET", "/v1/report"], ["GET", "/v1/runs/r1/report.pdf"], ["GET", "/v1/impact?tool=x"],
      ["POST", "/v1/simulate"], ["POST", "/v1/runs/r1/replay"], ["POST", "/v1/speculate"], ["GET", "/v1/alerts"], ["GET", "/v1/holds"], ["POST", "/v1/holds"],
      ["GET", "/v1/retention/plan"], ["POST", "/v1/retention/apply"], ["POST", "/v1/anchor"], ["GET", "/v1/registry"], ["POST", "/v1/registry/manifests"],
      ["POST", "/v1/reload"], ["GET", "/v1/keys"], ["POST", "/v1/keys"], ["GET", "/v1/connectors"], ["POST", "/v1/runs/r1/rollback"], ["GET", "/v1/runs/r1/rollback"],
    ];
    for (const [m, p] of routes) {
      expect((await f.call(null, m, p, m === "POST" ? {} : undefined)).status, `${m} ${p}`).toBe(401);
      expect((await f.call("wrong", m, p, m === "POST" ? {} : undefined)).status, `${m} ${p} wrong key`).toBe(401);
    }
  });

  it("engine-backed routes answer 404 when the engine services are not enabled", async () => {
    const f = await fx({ noEngine: true });
    const routes: Array<[Key, string, string, unknown?]> = [
      ["k-audit", "GET", "/v1/search/runs"], ["k-audit", "GET", "/v1/search/records"], ["k-audit", "GET", "/v1/report"], ["k-audit", "GET", "/v1/alerts"],
      ["k-audit", "GET", "/v1/holds"], ["k-root", "POST", "/v1/holds", { run_id: "r1", reason: "case 12345" }], ["k-audit", "GET", "/v1/retention/plan"],
      ["k-root", "POST", "/v1/anchor", {}], ["k-root", "POST", "/v1/reload"], ["k-audit", "GET", "/v1/impact?tool=create_order"],
    ];
    for (const [k, m, p, b] of routes) {
      const r = await f.call(k, m, p, b);
      expect(r.status, `${m} ${p}`).toBe(404);
      expect(r.json.error).toMatch(/engine services/);
    }
  });
});

describe("GET /v1/search/runs", () => {
  it("filters runs by actor, tool, status, text, tenant and pages with a cursor", async () => {
    const f = await fx();
    await seed(f, "run-a");
    await seed(f, "run-b");
    await f.call("k-agent", "POST", "/v1/runs", { run_id: "run-empty", permissions: ["o:w"] });
    const all = await f.call("k-audit", "GET", "/v1/search/runs");
    expect(all.status).toBe(200);
    expect(all.json.runs.map((r: any) => r.run_id)).toEqual(["run-a", "run-b", "run-empty"]);
    expect(all.json.runs[0]).toMatchObject({ run_id: "run-a", actor: "agent", mode: "enforce", steps: 1, tools: ["create_order"] });

    expect((await f.call("k-audit", "GET", "/v1/search/runs?tool=create_order")).json.runs).toHaveLength(2);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?tool=refund")).json.runs).toEqual([]);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?actor=nobody")).json.runs).toEqual([]);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?actor=agent")).json.runs).toHaveLength(3);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?text=run-b")).json.runs.map((r: any) => r.run_id)).toEqual(["run-b"]);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?status=empty")).json.runs.map((r: any) => r.run_id)).toEqual(["run-empty"]);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?tenant=acme")).json.runs).toEqual([]);

    const page1 = await f.call("k-audit", "GET", "/v1/search/runs?limit=1");
    expect(page1.json.runs).toHaveLength(1);
    expect(page1.json.next).toBe("run-a");
    const page2 = await f.call("k-audit", "GET", "/v1/search/runs?limit=1&after=run-a");
    expect(page2.json.runs[0].run_id).toBe("run-b");
  });

  it("accepts relative and ISO times for since/until and rejects unreadable ones with 400", async () => {
    const f = await fx();
    await seed(f);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?since=1h")).json.runs).toHaveLength(1);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?since=30m")).json.runs).toHaveLength(1);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?until=2000-01-01")).json.runs).toEqual([]);
    f.clock.t += 3 * 86_400_000;
    expect((await f.call("k-audit", "GET", "/v1/search/runs?since=1d")).json.runs).toEqual([]);
    expect((await f.call("k-audit", "GET", "/v1/search/runs?since=3d")).json.runs.length).toBeGreaterThanOrEqual(0);
    const bad = await f.call("k-audit", "GET", "/v1/search/runs?since=yesterday-ish");
    expect(bad.status).toBe(400);
    expect(bad.json.error).toContain("cannot read");
    expect((await f.call("k-audit", "GET", "/v1/search/records?until=nope")).status).toBe(400);
  });

  it("needs the auditor role", async () => {
    const f = await fx();
    await expectForbidden(f, "k-audit", "GET", "/v1/search/runs");
    await expectAllowed(f, "k-audit", "GET", "/v1/search/runs");
  });
});

describe("GET /v1/search/records", () => {
  it("filters ledger records by run, tool, event list, actor and text, and pages by seq", async () => {
    const f = await fx();
    await seed(f, "r1");
    await seed(f, "r2");
    const all = await f.call("k-audit", "GET", "/v1/search/records");
    expect(all.status).toBe(200);
    expect(all.json.records.length).toBeGreaterThanOrEqual(4);
    const r1 = await f.call("k-audit", "GET", "/v1/search/records?run=r1");
    expect(r1.json.records.every((r: any) => r.run_id === "r1")).toBe(true);
    expect(r1.json.records.map((r: any) => r.event)).toContain("succeeded");
    const succeeded = await f.call("k-audit", "GET", "/v1/search/records?event=succeeded");
    expect(succeeded.json.records.length).toBe(2);
    expect(succeeded.json.records.every((r: any) => r.event === "succeeded")).toBe(true);
    const multi = await f.call("k-audit", "GET", "/v1/search/records?event=succeeded,intended&run=r1");
    expect(new Set(multi.json.records.map((r: any) => r.event))).toEqual(new Set(["succeeded", "intended"]));
    expect((await f.call("k-audit", "GET", "/v1/search/records?tool=create_order")).json.records.length).toBeGreaterThanOrEqual(2);
    expect((await f.call("k-audit", "GET", "/v1/search/records?tool=refund")).json.records).toEqual([]);
    expect((await f.call("k-audit", "GET", "/v1/search/records?actor=agent&run=r2")).json.records.length).toBeGreaterThan(0);
    expect((await f.call("k-audit", "GET", "/v1/search/records?text=customer%20asked&run=r1")).json.records.length).toBeGreaterThan(0);
    expect((await f.call("k-audit", "GET", "/v1/search/records?text=zzz-no-match")).json.records).toEqual([]);

    const p1 = await f.call("k-audit", "GET", "/v1/search/records?limit=2");
    expect(p1.json.records).toHaveLength(2);
    expect(p1.json.next_seq).toBe(p1.json.records[1].seq);
    const p2 = await f.call("k-audit", "GET", `/v1/search/records?limit=2&after_seq=${p1.json.next_seq}`);
    expect(p2.json.records[0].seq).toBeGreaterThan(p1.json.next_seq);
  });

  it("never returns call arguments, only the ledger fields", async () => {
    const f = await fx();
    await seed(f);
    expect((await f.call("k-audit", "GET", "/v1/search/records")).text).not.toContain("abc");
  });

  it("needs the auditor role", async () => {
    const f = await fx();
    await expectForbidden(f, "k-audit", "GET", "/v1/search/records");
    await expectAllowed(f, "k-audit", "GET", "/v1/search/records");
  });
});

describe("GET /v1/report and /v1/runs/:id/report.pdf", () => {
  it("returns the period report as JSON by default and counts the journaled calls", async () => {
    const f = await fx();
    await seed(f);
    await f.call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "refund", args: { amount: 5 }, reason: "x" });
    const r = await f.call("k-audit", "GET", "/v1/report");
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ runs: 1, calls: 1, outcomes: { succeeded: 1 }, approvals: { requested: 1 } });
    expect(r.json.to_ms).toBe(f.clock.t);
    expect(r.json.from_ms).toBe(f.clock.t - 7 * 86_400_000);
    expect(r.json.tools[0]).toMatchObject({ key: "create_order", count: 1 });
  });

  it("honours since and renders markdown and html", async () => {
    const f = await fx();
    await seed(f);
    const wide = await f.call("k-audit", "GET", "/v1/report?since=12h");
    expect(wide.json.from_ms).toBe(f.clock.t - 12 * 3_600_000);
    const md = await f.call("k-audit", "GET", "/v1/report?format=md");
    expect(md.status).toBe(200);
    expect(md.res.headers.get("content-type")).toContain("text/markdown");
    expect(md.text).toContain("create_order");
    const html = await f.call("k-audit", "GET", "/v1/report?format=html");
    expect(html.res.headers.get("content-type")).toContain("text/html");
    expect(html.text.toLowerCase()).toContain("<html");
    expect((await f.call("k-audit", "GET", "/v1/report?since=bogus")).status).toBe(400);
    f.clock.t += 30 * 86_400_000;
    expect((await f.call("k-audit", "GET", "/v1/report?since=7d")).json.calls).toBe(0);
  });

  it("renders a PDF for a run, 404 for an unknown run", async () => {
    const f = await fx();
    await seed(f);
    const r = await f.app.request("/v1/runs/r1/report.pdf", { headers: { authorization: "Bearer k-audit" } });
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("application/pdf");
    expect(r.headers.get("content-disposition")).toContain("reversi-r1.pdf");
    const bytes = Buffer.from(await r.arrayBuffer());
    expect(bytes.subarray(0, 5).toString()).toBe("%PDF-");
    expect(bytes.length).toBeGreaterThan(500);
    const missing = await f.call("k-audit", "GET", "/v1/runs/nope/report.pdf");
    expect(missing.status).toBe(404);
    expect(missing.json.error).toContain("nope");
  });

  it("needs the auditor role", async () => {
    const f = await fx();
    await seed(f);
    for (const p of ["/v1/report", "/v1/runs/r1/report.pdf"]) {
      await expectForbidden(f, "k-audit", "GET", p);
      await expectAllowed(f, "k-audit", "GET", p);
    }
  });
});

describe("GET /v1/impact", () => {
  it("previews a reversible tool with its compensation", async () => {
    const f = await fx();
    const r = await f.call("k-audit", "GET", `/v1/impact?tool=create_order&args=${encodeURIComponent('{"sku":"a"}')}`);
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ tool: "create_order", known: true, effect: "reversible", verdict: "allow" });
    expect(r.json.compensation).toMatchObject({ tool: "cancel_order" });
    expect(r.json.rollback_outlook.join(" ")).toContain("cancel_order");
  });

  it("reports needs_approval for a tool the policy gates and block for an unknown tool", async () => {
    const f = await fx();
    const gated = await f.call("k-audit", "GET", "/v1/impact?tool=refund&actor=agent");
    expect(gated.json).toMatchObject({ tool: "refund", known: true, verdict: "needs_approval" });
    const unknown = await f.call("k-audit", "GET", "/v1/impact?tool=mystery");
    expect(unknown.json).toMatchObject({ tool: "mystery", known: false, verdict: "block", effect: null });
    expect(unknown.json.warnings).toContain("unclassified tool");
  });

  it("is a side-effect free sandbox: nothing reaches the real ledger or runs", async () => {
    const f = await fx();
    const before = f.engine.reversi.ledger.records().length;
    await f.call("k-audit", "GET", "/v1/impact?tool=create_order");
    expect(f.engine.reversi.ledger.records().length).toBe(before);
    expect(f.engine.reversi.runIds()).toEqual([]);
  });

  it("400 for a missing tool and for args that are not JSON", async () => {
    const f = await fx();
    const a = await f.call("k-audit", "GET", "/v1/impact");
    expect(a.status).toBe(400);
    expect(a.json.error).toContain("`tool` is required");
    const b = await f.call("k-audit", "GET", "/v1/impact?tool=create_order&args=%7Bnope");
    expect(b.status).toBe(400);
    expect(b.json.error).toContain("JSON");
  });

  it("needs the auditor role", async () => {
    const f = await fx();
    await expectForbidden(f, "k-audit", "GET", "/v1/impact?tool=create_order");
    await expectAllowed(f, "k-audit", "GET", "/v1/impact?tool=create_order");
  });
});

describe("POST /v1/simulate", () => {
  const DENY_ORDERS = "version: 1\nrules:\n  - id: freeze\n    match: { tool: create_order }\n    action: deny\n    reason: frozen for audit\n";

  it("replays captured history through a candidate policy and lists what would change", async () => {
    const f = await fx();
    await seed(f);
    const r = await f.call("k-ops", "POST", "/v1/simulate", { policy: DENY_ORDERS });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ calls: 1, runs: 1, unchanged: 0 });
    expect(r.json.newly_blocked).toHaveLength(1);
    expect(r.json.newly_blocked[0]).toMatchObject({ before: "allow", after: "block", run: "r1", tool: "create_order" });
    expect(r.json.newly_blocked[0].reasons.join(" ")).toContain("frozen for audit");
  });

  it("uses the active policy when none is given, and can target one run", async () => {
    const f = await fx();
    await seed(f, "r1");
    await seed(f, "r2");
    const same = await f.call("k-ops", "POST", "/v1/simulate", {});
    expect(same.json).toMatchObject({ calls: 2, runs: 2, unchanged: 2 });
    const one = await f.call("k-ops", "POST", "/v1/simulate", { run_id: "r2", policy: DENY_ORDERS });
    expect(one.json).toMatchObject({ calls: 1, runs: 1 });
    expect(one.json.newly_blocked[0].run).toBe("r2");
  });

  it("respects since: old captures fall out of the window", async () => {
    const f = await fx();
    await seed(f);
    f.clock.t += 10 * 86_400_000;
    expect((await f.call("k-ops", "POST", "/v1/simulate", { since: "7d" })).json.calls).toBe(0);
    expect((await f.call("k-ops", "POST", "/v1/simulate", { since: "30d" })).json.calls).toBe(1);
  });

  it("400 for an invalid candidate policy, 404 when capture is off, 400 for a bad body", async () => {
    const f = await fx();
    const bad = await f.call("k-ops", "POST", "/v1/simulate", { policy: "rules: [{ id: a, action: nope }]" });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toContain("the policy is not valid");
    expect((await f.call("k-ops", "POST", "/v1/simulate", "not json")).status).toBe(400);
    expect((await f.call("k-ops", "POST", "/v1/simulate", { since: "bogus" })).status).toBe(400);
    const off = await fx({ noCapture: true });
    const r = await off.call("k-ops", "POST", "/v1/simulate", {});
    expect(r.status).toBe(404);
    expect(r.json.error).toContain("capture is off");
  });

  it("needs the operator role", async () => {
    const f = await fx();
    await expectForbidden(f, "k-ops", "POST", "/v1/simulate", {});
    await expectAllowed(f, "k-ops", "POST", "/v1/simulate", {});
  });
});

describe("POST /v1/runs/:id/replay", () => {
  const DENY_BIG = "version: 1\nrules:\n  - id: cap\n    match: { tool: create_order }\n    when: [{ path: $args.qty, op: gt, value: 5 }]\n    action: deny\n    reason: too many\n";

  it("replays a captured run and applies an argument change", async () => {
    const f = await fx();
    await seed(f);
    const plain = await f.call("k-ops", "POST", "/v1/runs/r1/replay", { policy: DENY_BIG });
    expect(plain.status).toBe(200);
    expect(JSON.stringify(plain.json)).toContain("create_order");
    const changed = await f.call("k-ops", "POST", "/v1/runs/r1/replay", { policy: DENY_BIG, changes: [{ tool: "create_order", path: "$args.qty", value: 50 }] });
    expect(changed.status).toBe(200);
    expect(JSON.stringify(changed.json)).toContain("too many");
    expect(JSON.stringify(plain.json)).not.toContain("too many");
  });

  it("leaves the real ledger and run state untouched", async () => {
    const f = await fx();
    await seed(f);
    const before = f.engine.reversi.ledger.records().length;
    await f.call("k-ops", "POST", "/v1/runs/r1/replay", { changes: [{ path: "qty", value: 1 }] });
    expect(f.engine.reversi.ledger.records().length).toBe(before);
    expect(f.engine.reversi.runIds()).toEqual(["r1"]);
  });

  it("404 for a run with no captures, 404 when capture is off, 400 for an invalid policy", async () => {
    const f = await fx();
    const none = await f.call("k-ops", "POST", "/v1/runs/ghost/replay", {});
    expect(none.status).toBe(404);
    expect(none.json.error).toContain("nothing captured");
    await seed(f);
    expect((await f.call("k-ops", "POST", "/v1/runs/r1/replay", { policy: "default: maybe" })).status).toBe(400);
    expect((await f.call("k-ops", "POST", "/v1/runs/r1/replay", "nope")).status).toBe(400);
    const off = await fx({ noCapture: true });
    expect((await off.call("k-ops", "POST", "/v1/runs/r1/replay", {})).json.error).toContain("capture is off");
  });

  it("needs the operator role", async () => {
    const f = await fx();
    await seed(f);
    await expectForbidden(f, "k-ops", "POST", "/v1/runs/r1/replay", {});
    await expectAllowed(f, "k-ops", "POST", "/v1/runs/r1/replay", {});
  });
});

describe("POST /v1/speculate", () => {
  it("ranks plans and recommends the safest one that can run to the end", async () => {
    const f = await fx();
    const r = await f.call("k-audit", "POST", "/v1/speculate", {
      actor: "agent",
      plans: [
        { name: "with-refund", calls: [{ tool: "create_order", args: { sku: "a" } }, { tool: "refund", args: { amount: 1 } }] },
        { name: "orders-only", calls: [{ tool: "create_order", args: { sku: "a" } }] },
        { name: "unknown", calls: [{ tool: "mystery" }] },
      ],
    });
    expect(r.status).toBe(200);
    expect(r.json.recommended).toBe("orders-only");
    expect(r.json.plans.map((p: any) => p.name)).toEqual(["orders-only", "with-refund", "unknown"]);
    const [safe, refund, unknown] = r.json.plans;
    expect(safe).toMatchObject({ approvals_needed: 0, fully_reversible: true });
    expect(refund.approvals_needed).toBe(1);
    expect(refund.steps[1].verdict).toBe("needs_approval");
    expect(unknown.blocked_at).toBe(0);
  });

  it("400 for missing or empty plans or a bad policy, with nothing written", async () => {
    const f = await fx();
    const before = f.engine.reversi.ledger.records().length;
    expect((await f.call("k-audit", "POST", "/v1/speculate", {})).status).toBe(400);
    expect((await f.call("k-audit", "POST", "/v1/speculate", { plans: [] })).status).toBe(400);
    expect((await f.call("k-audit", "POST", "/v1/speculate", { plans: "x" })).status).toBe(400);
    expect((await f.call("k-audit", "POST", "/v1/speculate", { plans: [{ name: "p", calls: [] }], policy: "default: maybe" })).status).toBe(400);
    expect(f.engine.reversi.ledger.records().length).toBe(before);
  });

  it("needs the auditor role", async () => {
    const f = await fx();
    const b = { plans: [{ name: "p", calls: [{ tool: "lookup" }] }] };
    await expectForbidden(f, "k-audit", "POST", "/v1/speculate", b);
    await expectAllowed(f, "k-audit", "POST", "/v1/speculate", b);
  });
});

describe("GET /v1/alerts", () => {
  it("lists live alerts: halts, unhealthy upstreams, irreversible execution", async () => {
    const f = await fx();
    const base = await f.call("k-audit", "GET", "/v1/alerts");
    expect(base.status).toBe(200);
    expect(base.json.alerts.map((a: any) => a.kind)).toEqual(["upstream_unhealthy"]);
    expect(base.json.alerts[0]).toMatchObject({ severity: "critical", title: expect.stringContaining("upstream-a") });
    await f.call("k-root", "POST", "/v1/halt", { reason: "drill" });
    const halted = await f.call("k-audit", "GET", "/v1/alerts");
    expect(halted.json.alerts.map((a: any) => a.kind).sort()).toEqual(["halted", "upstream_unhealthy"]);
    expect(halted.json.alerts.find((a: any) => a.kind === "halted").detail).toContain("drill");
  });

  it("needs the auditor role", async () => {
    const f = await fx();
    await expectForbidden(f, "k-audit", "GET", "/v1/alerts");
    await expectAllowed(f, "k-audit", "GET", "/v1/alerts");
  });
});

describe("legal holds", () => {
  it("creates, lists and releases a hold, and records who placed it", async () => {
    const f = await fx();
    const made = await f.call("k-root", "POST", "/v1/holds", { run_id: "r1", reason: "case 2026-114" });
    expect(made.status).toBe(201);
    expect(made.json).toMatchObject({ scope: { run_id: "r1" }, reason: "case 2026-114", by: "root" });
    expect(made.json.id).toMatch(/^hold_/);
    const list = await f.call("k-audit", "GET", "/v1/holds");
    expect(list.json.holds.map((h: any) => h.id)).toEqual([made.json.id]);
    expect(f.engine.holds.list()).toHaveLength(1);

    expect((await f.call("k-root", "DELETE", `/v1/holds/${made.json.id}`)).json).toEqual({ ok: true });
    expect((await f.call("k-audit", "GET", "/v1/holds")).json.holds).toEqual([]);
    const all = await f.call("k-audit", "GET", "/v1/holds?all=1");
    expect(all.json.holds).toHaveLength(1);
    expect(all.json.holds[0].released_ms).toBeTypeOf("number");
  });

  it("accepts tenant, actor and tool scopes", async () => {
    const f = await fx();
    const r = await f.call("k-root", "POST", "/v1/holds", { tenant: "acme", actor: "agent", tool: "refund", reason: "matter 55555" });
    expect(r.status).toBe(201);
    expect(r.json.scope).toEqual({ tenant: "acme", actor: "agent", tool: "refund" });
  });

  it("400 for an empty scope, a short reason or a non-string scope; 404 releasing an unknown or already released hold", async () => {
    const f = await fx();
    const noScope = await f.call("k-root", "POST", "/v1/holds", { reason: "case 2026-114" });
    expect(noScope.status).toBe(400);
    expect(noScope.json.error).toContain("scope");
    const shortReason = await f.call("k-root", "POST", "/v1/holds", { run_id: "r1", reason: "x" });
    expect(shortReason.status).toBe(400);
    expect(shortReason.json.error).toContain("reason");
    expect((await f.call("k-root", "POST", "/v1/holds", { run_id: 5, reason: "case 2026-114" })).status).toBe(400);
    expect((await f.call("k-root", "POST", "/v1/holds", { run_id: "r1" })).status).toBe(400);
    expect(f.engine.holds.list()).toEqual([]);
    expect((await f.call("k-root", "DELETE", "/v1/holds/hold_nope")).status).toBe(404);
    const made = await f.call("k-root", "POST", "/v1/holds", { run_id: "r1", reason: "case 2026-114" });
    await f.call("k-root", "DELETE", `/v1/holds/${made.json.id}`);
    expect((await f.call("k-root", "DELETE", `/v1/holds/${made.json.id}`)).status).toBe(404);
  });

  it("listing needs the auditor role; placing and releasing need admin", async () => {
    const f = await fx();
    await expectForbidden(f, "k-audit", "GET", "/v1/holds");
    await expectAllowed(f, "k-audit", "GET", "/v1/holds");
    await expectForbidden(f, "k-root", "POST", "/v1/holds", { run_id: "r1", reason: "case 2026-114" });
    expect(f.engine.holds.list()).toEqual([]);
    const made = await f.call("k-root", "POST", "/v1/holds", { run_id: "r1", reason: "case 2026-114" });
    await expectForbidden(f, "k-root", "DELETE", `/v1/holds/${made.json.id}`);
    expect(f.engine.holds.list()).toHaveLength(1);
  });
});

describe("retention", () => {
  const AGE = 3 * 86_400_000;

  it("plans: a fresh run is not due, an old one is, a held one is flagged", async () => {
    const f = await fx();
    await seed(f);
    const fresh = await f.call("k-audit", "GET", "/v1/retention/plan");
    expect(fresh.status).toBe(200);
    expect(fresh.json.config).toMatchObject({ default_days: 1 });
    expect(fresh.json.runs).toEqual([expect.objectContaining({ run_id: "r1", due: false, retention_days: 1, needs_export: false })]);
    f.clock.t += AGE;
    const due = await f.call("k-audit", "GET", "/v1/retention/plan");
    expect(due.json.runs[0]).toMatchObject({ run_id: "r1", due: true, age_days: 3 });
    expect(due.json.runs[0].held).toBeUndefined();
    const hold = await f.call("k-root", "POST", "/v1/holds", { run_id: "r1", reason: "case 2026-114" });
    const held = await f.call("k-audit", "GET", "/v1/retention/plan");
    expect(held.json.runs[0].held.id).toBe(hold.json.id);
  });

  it("apply with dry_run reports but deletes nothing", async () => {
    const f = await fx();
    await seed(f);
    f.clock.t += AGE;
    const before = f.engine.reversi.ledger.records().length;
    const r = await f.call("k-root", "POST", "/v1/retention/apply", { dry_run: true });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ dry_run: true, purged: ["r1"], skipped: [], exported: [] });
    expect(f.engine.reversi.runIds()).toEqual(["r1"]);
    expect(f.engine.reversi.ledger.records().length).toBe(before);
    expect(f.engine.capture?.list({ run_id: "r1" }).length).toBe(1);
  });

  it("apply purges the run, its approvals and captures, and appends a purged record by the caller", async () => {
    const f = await fx();
    await seed(f);
    await f.call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "refund", args: { n: 1 }, reason: "x" });
    expect(f.engine.approvals.list({ run_id: "r1" })).toHaveLength(1);
    f.clock.t += AGE;
    const r = await f.call("k-root", "POST", "/v1/retention/apply", {});
    expect(r.json).toMatchObject({ dry_run: false, purged: ["r1"], skipped: [] });
    expect(f.engine.reversi.runIds()).toEqual([]);
    expect(f.engine.approvals.list({ run_id: "r1" })).toEqual([]);
    expect(f.engine.capture?.list({ run_id: "r1" })).toEqual([]);
    const purged = f.engine.reversi.ledger.records().filter((x) => x.event === "purged");
    expect(purged).toHaveLength(1);
    expect(purged[0]).toMatchObject({ run_id: "r1", actor: "root" });
    expect(f.engine.reversi.ledger.verify().ok).toBe(true);
  });

  it("apply leaves runs that are not yet due, and skips runs under a legal hold", async () => {
    const f = await fx();
    await seed(f);
    expect((await f.call("k-root", "POST", "/v1/retention/apply", {})).json.purged).toEqual([]);
    f.clock.t += AGE;
    const hold = await f.call("k-root", "POST", "/v1/holds", { run_id: "r1", reason: "case 2026-114" });
    const r = await f.call("k-root", "POST", "/v1/retention/apply", {});
    expect(r.json.purged).toEqual([]);
    expect(r.json.skipped[0]).toMatchObject({ run_id: "r1" });
    expect(r.json.skipped[0].reason).toContain(hold.json.id);
    expect(f.engine.reversi.runIds()).toEqual(["r1"]);
    await f.call("k-root", "DELETE", `/v1/holds/${hold.json.id}`);
    expect((await f.call("k-root", "POST", "/v1/retention/apply", {})).json.purged).toEqual(["r1"]);
  });

  it("apply with archive_dir writes a signed evidence bundle before deleting", async () => {
    const f = await fx();
    await seed(f);
    f.clock.t += AGE;
    const archive = join(f.dir, "archive");
    const r = await f.call("k-root", "POST", "/v1/retention/apply", { archive_dir: archive });
    expect(r.json.purged).toEqual(["r1"]);
    expect(r.json.exported).toEqual([{ run_id: "r1", file: join(archive, "r1.json") }]);
    expect(readdirSync(archive)).toEqual(["r1.json"]);
    const bundle = JSON.parse(readFileSync(join(archive, "r1.json"), "utf8"));
    expect(verifyBundle(bundle, { trusted_public_pem: f.sk.public_pem }).ok).toBe(true);
  });

  it("404 without a retention section in the active policy", async () => {
    const f = await fx({ noRetention: true });
    for (const [k, m, p] of [["k-audit", "GET", "/v1/retention/plan"], ["k-root", "POST", "/v1/retention/apply"]] as const) {
      const r = await f.call(k, m, p, m === "POST" ? {} : undefined);
      expect(r.status).toBe(404);
      expect(r.json.error).toContain("retention");
    }
  });

  it("plan needs the auditor role; apply needs admin", async () => {
    const f = await fx();
    await seed(f);
    f.clock.t += AGE;
    await expectForbidden(f, "k-audit", "GET", "/v1/retention/plan");
    await expectAllowed(f, "k-audit", "GET", "/v1/retention/plan");
    await expectForbidden(f, "k-root", "POST", "/v1/retention/apply", {});
    expect(f.engine.reversi.runIds()).toEqual(["r1"]);
  });
});

describe("POST /v1/anchor", () => {
  it("writes a signed anchor of the ledger head to the file sink", async () => {
    const f = await fx();
    await seed(f);
    const r = await f.call("k-root", "POST", "/v1/anchor", {});
    expect(r.status).toBe(200);
    expect(r.json.errors).toEqual([]);
    expect(r.json.anchor).toMatchObject({ format: "reversi-anchor", version: 1, head: f.engine.reversi.ledger.head(), records: f.engine.reversi.ledger.records().length });
    expect(r.json.anchor.signature).toBeTypeOf("string");
    expect(r.json.anchor.key_id).toBeTypeOf("string");
    expect(r.json.delivered).toHaveLength(1);
    expect(existsSync(f.anchorFile)).toBe(true);
    const line = readFileSync(f.anchorFile, "utf8").trim().split("\n").at(-1) as string;
    expect(JSON.parse(line)).toMatchObject({ head: r.json.anchor.head });
  });

  it("answers 502 with the errors when a sink fails, and still returns the anchor", async () => {
    const f = await fx();
    const blocker = join(f.dir, "blocker");
    writeFileSync(blocker, "x");
    // a file sink under a path whose parent is a regular file cannot be written
    f.engine.config.anchor = { sinks: [{ type: "file", path: join(blocker, "sub", "a.jsonl") }] };
    const r = await f.call("k-root", "POST", "/v1/anchor", {});
    expect(r.status).toBe(502);
    expect(r.json.errors.length).toBe(1);
    expect(r.json.delivered).toEqual([]);
    expect(r.json.anchor.head).toBeTypeOf("string");
  });

  it("404 when no anchor sinks are configured", async () => {
    const f = await fx({ noAnchor: true });
    const r = await f.call("k-root", "POST", "/v1/anchor", {});
    expect(r.status).toBe(404);
    expect(r.json.error).toContain("no anchor sinks");
  });

  it("needs admin", async () => {
    const f = await fx();
    await expectForbidden(f, "k-root", "POST", "/v1/anchor", {});
    expect(existsSync(f.anchorFile)).toBe(false);
  });
});

describe("manifest and policy registry", () => {
  const NEW_TOOL = { tool: "ship_order", effect: "idempotent", permission: "o:w" };

  it("GET /v1/registry lists the current version of each manifest and the policy history", async () => {
    const f = await fx();
    const r = await f.call("k-ops", "GET", "/v1/registry");
    expect(r.status).toBe(200);
    expect(r.json.manifests.map((m: any) => m.tool).sort()).toEqual(MANIFESTS.map((m) => m.tool).sort());
    const order = r.json.manifests.find((m: any) => m.tool === "create_order");
    expect(order).toMatchObject({ version: 1, status: "approved" });
    expect(order.checksum).toMatch(/^[0-9a-f]{64}$/);
    expect(order.manifest.compensation.tool).toBe("cancel_order");
    expect(r.json.policy).toMatchObject({ version: 1 });
    expect(r.json.policy.history).toHaveLength(1);
    expect(r.json.policy.checksum).toBe(r.json.policy.history[0].checksum);
  });

  it("GET /v1/registry is 404 without a registry folder and omits the policy without a policy folder", async () => {
    const none = await fx({ noRegistry: true });
    expect((await none.call("k-ops", "GET", "/v1/registry")).status).toBe(404);
  });

  it("GET /v1/registry needs the operator role", async () => {
    const f = await fx();
    await expectForbidden(f, "k-ops", "GET", "/v1/registry");
    await expectAllowed(f, "k-ops", "GET", "/v1/registry");
  });

  it("publishes a draft as an operator without touching the live engine", async () => {
    const f = await fx();
    const r = await f.call("k-ops", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL, status: "draft", note: "proposal" });
    expect(r.status).toBe(201);
    expect(r.json).toMatchObject({ tool: "ship_order", version: 1 });
    expect(f.mr.history("ship_order")[0]).toMatchObject({ status: "draft", by: "ops", note: "proposal" });
    expect(f.engine.registry.has("ship_order")).toBe(false);
    expect(f.engine.reversi.ledger.records().filter((x) => x.event === "reloaded")).toEqual([]);
  });

  it("publishing as approved needs an admin, signs, reloads and records the reload", async () => {
    const f = await fx();
    const r = await f.call("k-root", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL });
    expect(r.status).toBe(201);
    expect(f.mr.history("ship_order")[0]).toMatchObject({ status: "approved", by: "root" });
    expect(f.mr.history("ship_order")[0]?.signature).toBeTypeOf("string");
    expect(f.engine.registry.has("ship_order")).toBe(true);
    const reloaded = f.engine.reversi.ledger.records().filter((x) => x.event === "reloaded");
    expect(reloaded).toHaveLength(1);
    expect(reloaded[0]).toMatchObject({ actor: "root" });
  });

  it("an operator cannot publish an approved manifest (the default status is approved)", async () => {
    const f = await fx();
    const r = await f.call("k-ops", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL });
    expect(r.status).toBe(403);
    expect((await f.call("k-ops", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL, status: "approved" })).status).toBe(403);
    expect(f.mr.tools()).not.toContain("ship_order");
    // a status that is neither draft nor approved is treated as approved, so it needs admin too
    expect((await f.call("k-ops", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL, status: "deprecated" })).status).toBe(403);
  });

  it("publish role matrix: drafts need operator, approved needs admin", async () => {
    const f = await fx();
    await expectForbidden(f, "k-ops", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL, status: "draft" });
    await expectForbidden(f, "k-root", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL });
    expect(f.mr.tools()).not.toContain("ship_order");
  });

  it("400 for an invalid manifest or a missing manifest, nothing written", async () => {
    const f = await fx();
    const bad = await f.call("k-root", "POST", "/v1/registry/manifests", { manifest: { tool: "x", effect: "sometimes" } });
    expect(bad.status).toBe(400);
    expect((await f.call("k-root", "POST", "/v1/registry/manifests", {})).status).toBe(400);
    expect((await f.call("k-root", "POST", "/v1/registry/manifests", "nope")).status).toBe(400);
    expect(f.mr.tools()).not.toContain("x");
  });

  it("404 when no registry folder is configured", async () => {
    const f = await fx({ noRegistry: true });
    const r = await f.call("k-root", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL });
    expect(r.status).toBe(404);
    expect(r.json.error).toContain("manifest registry");
  });

  it("approves a draft, as admin, and the engine picks it up", async () => {
    const f = await fx();
    await f.call("k-ops", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL, status: "draft" });
    const r = await f.call("k-root", "POST", "/v1/registry/manifests/ship_order/approve", {});
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ tool: "ship_order", version: 2 });
    expect(f.mr.history("ship_order")[0]).toMatchObject({ status: "draft" });
    expect(f.mr.history("ship_order")[1]).toMatchObject({ status: "approved", approved_by: "root", by: "ops" });
    expect(f.engine.registry.has("ship_order")).toBe(true);
    expect(f.engine.reversi.ledger.records().filter((x) => x.event === "reloaded")).toHaveLength(1);
  });

  it("approve works with no body at all, and with an explicit version", async () => {
    const f = await fx();
    await f.call("k-ops", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL, status: "draft" });
    const nobody = await f.app.request("/v1/registry/manifests/ship_order/approve", { method: "POST", headers: { authorization: "Bearer k-root" } });
    expect(nobody.status).toBe(200);
    await f.call("k-ops", "POST", "/v1/registry/manifests", { manifest: { ...NEW_TOOL, description: "v2" }, status: "draft" });
    expect(f.mr.history("ship_order").map((v) => v.status)).toEqual(["draft", "approved", "draft"]);
    const v3 = await f.call("k-root", "POST", "/v1/registry/manifests/ship_order/approve", { version: 3 });
    expect(v3.json).toMatchObject({ version: 4 });
    const again = await f.call("k-root", "POST", "/v1/registry/manifests/ship_order/approve", { version: 2 });
    expect(again.status).toBe(400);
    expect(again.json.error).toContain("not a draft");
  });

  it("four_eyes: the author cannot approve their own draft; another admin can", async () => {
    const f = await fx();
    await f.call("k-root", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL, status: "draft" });
    const self = await f.call("k-root", "POST", "/v1/registry/manifests/ship_order/approve", { four_eyes: true });
    expect(self.status).toBe(400);
    expect(f.mr.history("ship_order")[0]?.status).toBe("draft");
  });

  it("approve: 400 for an unknown tool or version, admin only", async () => {
    const f = await fx();
    expect((await f.call("k-root", "POST", "/v1/registry/manifests/ghost/approve", {})).status).toBe(400);
    await f.call("k-ops", "POST", "/v1/registry/manifests", { manifest: NEW_TOOL, status: "draft" });
    expect((await f.call("k-root", "POST", "/v1/registry/manifests/ship_order/approve", { version: 9 })).status).toBe(400);
    await expectForbidden(f, "k-root", "POST", "/v1/registry/manifests/ship_order/approve", {});
    expect(f.mr.history("ship_order")[0]?.status).toBe("draft");
    expect((await (await fx({ noRegistry: true })).call("k-root", "POST", "/v1/registry/manifests/ship_order/approve", {})).status).toBe(404);
  });

  it("deprecates a tool and reloads; records the replacement; admin only", async () => {
    const f = await fx();
    await expectForbidden(f, "k-root", "POST", "/v1/registry/manifests/refund/deprecate", {});
    expect(f.mr.history("refund").at(-1)?.status).toBe("approved");
    const r = await f.call("k-root", "POST", "/v1/registry/manifests/refund/deprecate", { replaced_by: "payout" });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ tool: "refund" });
    const last = f.mr.history("refund").at(-1);
    expect(last).toMatchObject({ status: "deprecated", by: "root" });
    expect(f.engine.reversi.ledger.records().filter((x) => x.event === "reloaded")).toHaveLength(1);
    expect((await f.call("k-root", "POST", "/v1/registry/manifests/ghost/deprecate", {})).status).toBe(400);
  });

  it("publishes and activates a policy, reloads, and the engine enforces it", async () => {
    const f = await fx();
    const fixed = POLICY.replace("retention:", "  - id: block-lookup\n    match: { tool: lookup }\n    action: deny\nretention:");
    const r = await f.call("k-root", "POST", "/v1/registry/policy", { text: fixed, note: "freeze lookups" });
    expect(r.status).toBe(201);
    expect(r.json).toMatchObject({ version: 2, by: "root", note: "freeze lookups" });
    expect(f.pv.activeVersion()).toBe(2);
    expect(readFileSync(join(f.pol, "policy-v2.yaml"), "utf8")).toBe(fixed);
    expect(f.engine.reversi.ledger.records().filter((x) => x.event === "reloaded")).toHaveLength(1);
    await f.call("k-agent", "POST", "/v1/runs", { run_id: "p1", permissions: ["o:r"] });
    const blocked = await f.call("k-agent", "POST", "/v1/runs/p1/intents", { tool: "lookup", reason: "x" });
    expect(blocked.json.decision).toBe("block");
  });

  it("publishes a policy without activating when activate is false", async () => {
    const f = await fx();
    const r = await f.call("k-root", "POST", "/v1/registry/policy", { text: "version: 1\nrules: []\n", activate: false });
    expect(r.status).toBe(201);
    expect(r.json.version).toBe(2);
    expect(f.pv.activeVersion()).toBe(1);
    expect(f.engine.reversi.ledger.records().filter((x) => x.event === "reloaded")).toEqual([]);
  });

  it("policy publish: 400 for invalid or failing-test policies, admin only, 404 without a policy folder", async () => {
    const f = await fx();
    expect((await f.call("k-root", "POST", "/v1/registry/policy", { text: "rules: [{ id: a, action: nope }]" })).status).toBe(400);
    expect((await f.call("k-root", "POST", "/v1/registry/policy", {})).status).toBe(400);
    const failing = "version: 1\nrules: []\ntests:\n  - name: should-deny\n    tool: lookup\n    expect: deny\n";
    const t = await f.call("k-root", "POST", "/v1/registry/policy", { text: failing });
    expect(t.status).toBe(400);
    expect(t.json.error).toContain("should-deny");
    expect(f.pv.history()).toHaveLength(1);
    await expectForbidden(f, "k-root", "POST", "/v1/registry/policy", { text: "version: 1\nrules: []\n" });
    expect(f.pv.history()).toHaveLength(1);
    const noPol = await createApp({ reversi: f.engine.reversi, approvals: f.engine.approvals, keys: KEYS, engine: f.engine }).request("/v1/registry/policy", { method: "POST", headers: { authorization: "Bearer k-root", "content-type": "application/json" }, body: JSON.stringify({ text: "version: 1\n" }) });
    expect(noPol.status).toBe(404);
  });

  it("activates an earlier policy version and reloads; 400 for an unknown version", async () => {
    const f = await fx();
    await f.call("k-root", "POST", "/v1/registry/policy", { text: "version: 1\nrules: []\n" });
    expect(f.pv.activeVersion()).toBe(2);
    const r = await f.call("k-root", "POST", "/v1/registry/policy/1/activate");
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ active: 1 });
    expect(f.pv.activeVersion()).toBe(1);
    expect(f.engine.reversi.policy?.doc.retention?.default_days).toBe(1);
    expect((await f.call("k-root", "POST", "/v1/registry/policy/9/activate")).status).toBe(400);
    expect((await f.call("k-root", "POST", "/v1/registry/policy/abc/activate")).status).toBe(400);
    await expectForbidden(f, "k-root", "POST", "/v1/registry/policy/2/activate");
    expect(f.pv.activeVersion()).toBe(1);
  });

  it("answers 409 when the saved configuration does not load, keeping the old one live", async () => {
    const f = await fx();
    // break the registry on disk behind the API's back, then publish a policy: the reload fails
    const idx = join(f.reg, "index.json");
    const raw = JSON.parse(readFileSync(idx, "utf8"));
    raw.tools.refund.versions[0].checksum = "0".repeat(64);
    writeFileSync(idx, JSON.stringify(raw));
    const r = await f.call("k-root", "POST", "/v1/registry/policy", { text: "version: 1\nrules: []\n" });
    expect(r.status).toBe(409);
    expect(r.json.error).toContain("saved, but the new configuration did not load");
    expect(f.engine.registry.has("refund")).toBe(true);
    expect(f.engine.reversi.policy?.doc.rules.map((x) => x.id)).toContain("refund-approval");
  });
});

describe("POST /v1/reload", () => {
  it("reloads configuration changed on disk and records who asked", async () => {
    const f = await fx();
    const none = await f.call("k-root", "POST", "/v1/reload");
    expect(none.status).toBe(200);
    expect(none.json).toMatchObject({ changed: false, tools: MANIFESTS.length });
    f.mr.publish({ tool: "ship_order", effect: "idempotent", permission: "o:w" }, { by: "ci", status: "approved" });
    const r = await f.call("k-root", "POST", "/v1/reload");
    expect(r.json).toMatchObject({ changed: true, tools: MANIFESTS.length + 1 });
    expect(f.engine.registry.has("ship_order")).toBe(true);
    const ev = f.engine.reversi.ledger.records().filter((x) => x.event === "reloaded");
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ actor: "root" });
  });

  it("reports an error (200, changed false) and keeps the old configuration when the new one is broken", async () => {
    const f = await fx();
    const idx = join(f.reg, "index.json");
    const raw = JSON.parse(readFileSync(idx, "utf8"));
    raw.tools.refund.versions[0].checksum = "0".repeat(64);
    writeFileSync(idx, JSON.stringify(raw));
    const r = await f.call("k-root", "POST", "/v1/reload");
    expect(r.status).toBe(200);
    expect(r.json.changed).toBe(false);
    expect(r.json.error).toContain("checksum");
    expect(f.engine.registry.has("refund")).toBe(true);
  });

  it("needs admin", async () => {
    const f = await fx();
    await expectForbidden(f, "k-root", "POST", "/v1/reload");
    await expectAllowed(f, "k-root", "POST", "/v1/reload");
  });
});

describe("API keys", () => {
  const readFile = (f: Fx) => JSON.parse(readFileSync(f.keysFile, "utf8")) as ApiKey[];

  it("lists keys with a fingerprint and never the key or its hash", async () => {
    const f = await fx();
    const r = await f.call("k-root", "GET", "/v1/keys");
    expect(r.status).toBe(200);
    expect(r.json.keys).toHaveLength(5);
    expect(r.json.keys[0]).toMatchObject({ index: 0, name: "agent", roles: ["agent"], disabled: false, allow_observe: false });
    expect(r.json.keys[0].fingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(r.text).not.toContain("k-agent");
    expect(r.text).not.toContain("key_sha256");
  });

  it("creates a key, shows the secret once, stores only the hash, and the key works immediately", async () => {
    const f = await fx();
    const r = await f.call("k-root", "POST", "/v1/keys", { name: "bot", role: "auditor", groups: ["finance"], tenant: "acme" });
    expect(r.status).toBe(201);
    expect(r.json).toMatchObject({ name: "bot", roles: ["auditor"], note: expect.stringContaining("only time") });
    expect(r.json.key).toMatch(/^rv_[0-9a-f]{48}$/);
    const onDisk = readFile(f);
    expect(onDisk).toHaveLength(6);
    expect(onDisk[5]).toMatchObject({ name: "bot", roles: ["auditor"], groups: ["finance"], tenant: "acme" });
    expect(onDisk[5]?.key).toBeUndefined();
    expect(readFileSync(f.keysFile, "utf8")).not.toContain(r.json.key);
    expect((await f.call(r.json.key, "GET", "/v1/alerts")).status).toBe(200);
    expect((await f.call(r.json.key, "POST", "/v1/halt", { reason: "x" })).status).toBe(403);
    const listed = await f.call("k-root", "GET", "/v1/keys");
    expect(listed.json.keys[5]).toMatchObject({ name: "bot", tenant: "acme", groups: ["finance"] });
    expect(listed.text).not.toContain(r.json.key);
  });

  it("supports several roles, max_permissions and expires_in_days (the key stops working after expiry)", async () => {
    const f = await fx();
    const r = await f.call("k-root", "POST", "/v1/keys", { name: "temp", roles: ["agent", "auditor"], max_permissions: ["o:r"], expires_in_days: 2 });
    expect(r.status).toBe(201);
    expect(r.json.roles).toEqual(["agent", "auditor"]);
    const entry = readFile(f)[5] as ApiKey;
    expect(entry.max_permissions).toEqual(["o:r"]);
    expect(Date.parse(entry.expires_at as string)).toBe(f.clock.t + 2 * 86_400_000);
    expect((await f.call(r.json.key, "GET", "/v1/alerts")).status).toBe(200);
    f.clock.t += 3 * 86_400_000;
    expect((await f.call(r.json.key, "GET", "/v1/alerts")).status).toBe(401);
  });

  it("400 for missing name, no valid role, bad expiry; nothing written", async () => {
    const f = await fx();
    for (const b of [{ role: "auditor" }, { name: "x" }, { name: "x", role: "superuser" }, { name: "x", roles: [] }, { name: "x", role: "auditor", expires_in_days: 0 }, { name: "x", role: "auditor", expires_in_days: "soon" }, { name: "x", role: "auditor", expires_in_days: -3 }]) {
      const r = await f.call("k-root", "POST", "/v1/keys", b);
      expect(r.status, JSON.stringify(b)).toBe(400);
    }
    expect(readFile(f)).toHaveLength(5);
  });

  it("disables and re-enables a key through PATCH, and sets or clears an expiry", async () => {
    const f = await fx();
    expect((await f.call("k-audit", "GET", "/v1/alerts")).status).toBe(200);
    expect((await f.call("k-root", "PATCH", "/v1/keys/1", { disabled: true })).json).toEqual({ ok: true });
    expect(readFile(f)[1]?.disabled).toBe(true);
    expect((await f.call("k-audit", "GET", "/v1/alerts")).status).toBe(401);
    expect((await f.call("k-root", "GET", "/v1/keys")).json.keys[1].disabled).toBe(true);
    await f.call("k-root", "PATCH", "/v1/keys/1", { disabled: false });
    expect((await f.call("k-audit", "GET", "/v1/alerts")).status).toBe(200);
    await f.call("k-root", "PATCH", "/v1/keys/1", { expires_at: "2000-01-01T00:00:00Z" });
    expect((await f.call("k-audit", "GET", "/v1/alerts")).status).toBe(401);
    await f.call("k-root", "PATCH", "/v1/keys/1", { expires_at: null });
    expect(readFile(f)[1]?.expires_at).toBeUndefined();
    expect((await f.call("k-audit", "GET", "/v1/alerts")).status).toBe(200);
    expect((await f.call("k-root", "PATCH", "/v1/keys/99", { disabled: true })).status).toBe(404);
  });

  it("deletes a key, which stops authenticating at once; 404 for an unknown index", async () => {
    const f = await fx();
    const del = await f.call("k-root", "DELETE", "/v1/keys/1");
    expect(del.json).toEqual({ ok: true });
    expect(readFile(f).map((k) => k.name)).toEqual(["agent", "appr", "ops", "root"]);
    expect((await f.call("k-audit", "GET", "/v1/alerts")).status).toBe(401);
    expect((await f.call("k-root", "DELETE", "/v1/keys/42")).status).toBe(404);
    expect((await f.call("k-root", "DELETE", "/v1/keys/-1")).status).toBe(404);
    expect(readFile(f)).toHaveLength(4);
  });

  it("writes the file with mode 600 and leaves no temp file", async () => {
    const f = await fx();
    await f.call("k-root", "POST", "/v1/keys", { name: "bot", role: "auditor" });
    expect(readdirSync(f.dir).filter((n) => n.startsWith("keys.json."))).toEqual([]);
    expect(statSync(f.keysFile).mode & 0o777).toBe(0o600);
  });

  it("404 on every key route when no keys file is configured", async () => {
    const f = await fx({ noKeysFile: true });
    for (const [m, p, b] of [["GET", "/v1/keys"], ["POST", "/v1/keys", { name: "x", role: "auditor" }], ["PATCH", "/v1/keys/0", { disabled: true }], ["DELETE", "/v1/keys/0"]] as const) {
      const r = await f.call("k-root", m, p, b);
      expect(r.status, `${m} ${p}`).toBe(404);
      expect(r.json.error).toContain("REVERSI_KEYS");
    }
  });

  it("every key route needs admin", async () => {
    const f = await fx();
    for (const [m, p, b] of [["GET", "/v1/keys"], ["POST", "/v1/keys", { name: "x", role: "auditor" }], ["PATCH", "/v1/keys/0", { disabled: true }], ["DELETE", "/v1/keys/0"]] as const) {
      await expectForbidden(f, "k-root", m, p, b);
    }
    expect(readFile(f)).toHaveLength(5);
    expect(readFile(f)[0]?.disabled).toBeUndefined();
  });
});

describe("GET /v1/connectors", () => {
  it("returns what the connector provider reports; an empty list without one", async () => {
    const f = await fx();
    const r = await f.call("k-audit", "GET", "/v1/connectors");
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ connectors: [{ name: "github", kind: "mcp", healthy: true, tools: 3, classified: 2, unclassified: 1 }] });
    const bare = createApp({ reversi: f.engine.reversi, approvals: f.engine.approvals, keys: KEYS });
    const e = await bare.request("/v1/connectors", { headers: { authorization: "Bearer k-audit" } });
    expect(await e.json()).toEqual({ connectors: [] });
  });

  it("needs the auditor role", async () => {
    const f = await fx();
    await expectForbidden(f, "k-audit", "GET", "/v1/connectors");
    await expectAllowed(f, "k-audit", "GET", "/v1/connectors");
  });
});

describe("rollback start and status", () => {
  const waitDone = async (f: Fx, id = "r1") => {
    for (let i = 0; i < 100; i++) {
      const s = await f.call("k-audit", "GET", `/v1/runs/${id}/rollback`);
      if (s.json && !s.json.running) return s.json;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("rollback did not finish");
  };

  it("without confirm it returns the plan as a dry run and executes nothing", async () => {
    const f = await fx();
    await seed(f);
    const r = await f.call("k-ops", "POST", "/v1/runs/r1/rollback", {});
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ dry_run: true, executable: true });
    expect(r.json.plan.actions[0]).toMatchObject({ kind: "compensate", compensation_tool: "cancel_order", args: { id: 7 } });
    expect(f.compensator).not.toHaveBeenCalled();
    expect((await f.call("k-ops", "GET", "/v1/runs/r1/rollback")).status).toBe(404);
    const noBody = await f.app.request("/v1/runs/r1/rollback", { method: "POST", headers: { authorization: "Bearer k-ops" } });
    expect((await noBody.json()).dry_run).toBe(true);
  });

  it("dry run says executable false when no compensator is configured", async () => {
    const f = await fx({ noCompensator: true });
    await seed(f);
    expect((await f.call("k-ops", "POST", "/v1/runs/r1/rollback", {})).json.executable).toBe(false);
  });

  it("with confirm it starts a job (202), runs the compensation, and status shows the report", async () => {
    const f = await fx();
    await seed(f);
    const r = await f.call("k-ops", "POST", "/v1/runs/r1/rollback", { confirm: true });
    expect(r.status).toBe(202);
    expect(r.json).toMatchObject({ run_id: "r1", running: true, by: "ops" });
    const done = await waitDone(f);
    expect(done).toMatchObject({ run_id: "r1", running: false, by: "ops" });
    expect(done.error).toBeUndefined();
    expect(done.finished_ms).toBeTypeOf("number");
    expect(done.report).toBeDefined();
    expect(f.compensations).toHaveLength(1);
    expect(f.compensations[0]).toMatchObject({ tool: "cancel_order", args: { id: 7 } });
    expect(f.engine.reversi.openRun("r1").state().steps[0]?.status).toBe("compensated");
    const events = f.engine.reversi.ledger.records().filter((x) => x.run_id === "r1").map((x) => x.event);
    expect(events).toContain("compensated");
  });

  it("409 when a rollback of the same run is still running", async () => {
    const f = await fx();
    await seed(f);
    let release!: () => void;
    f.compensator.mockImplementationOnce(() => new Promise<void>((res) => (release = res)));
    const first = await f.call("k-ops", "POST", "/v1/runs/r1/rollback", { confirm: true });
    expect(first.status).toBe(202);
    const second = await f.call("k-ops", "POST", "/v1/runs/r1/rollback", { confirm: true });
    expect(second.status).toBe(409);
    expect(second.json.error).toContain("already running");
    expect((await f.call("k-audit", "GET", "/v1/runs/r1/rollback")).json.running).toBe(true);
    release();
    expect((await waitDone(f)).running).toBe(false);
  });

  it("records a compensator failure on the job without losing the report", async () => {
    const f = await fx();
    await seed(f);
    f.compensator.mockRejectedValue(new Error("downstream is down"));
    await f.call("k-ops", "POST", "/v1/runs/r1/rollback", { confirm: true });
    const done = await waitDone(f);
    expect(done.running).toBe(false);
    expect(JSON.stringify(done)).toContain("downstream is down");
    expect(f.engine.reversi.openRun("r1").state().steps[0]?.status).toBe("compensation_failed");
  });

  it("a compensation that needs approval stays pending unless approve_compensations is set", async () => {
    const f = await fx();
    await f.call("k-agent", "POST", "/v1/runs", { run_id: "b1", permissions: ["o:w"] });
    const a = await f.call("k-agent", "POST", "/v1/runs/b1/intents", { tool: "book", args: { room: 1 }, reason: "x" });
    await f.call("k-agent", "POST", `/v1/runs/b1/steps/${a.json.step}/outcome`, { status: "succeeded", result: { id: 3 } });
    expect((await f.call("k-ops", "POST", "/v1/runs/b1/rollback", {})).json.plan.actions[0]).toMatchObject({ kind: "compensate", compensation_tool: "unbook", needs_approval: true });
    await f.call("k-ops", "POST", "/v1/runs/b1/rollback", { confirm: true });
    const held = await waitDone(f, "b1");
    expect(held.running).toBe(false);
    expect(f.compensator).not.toHaveBeenCalled();
    expect(f.engine.approvals.list({ status: "pending" }).some((x) => x.tool === "unbook")).toBe(true);

    const g = await fx();
    await g.call("k-agent", "POST", "/v1/runs", { run_id: "b1", permissions: ["o:w"] });
    const b = await g.call("k-agent", "POST", "/v1/runs/b1/intents", { tool: "book", args: { room: 1 }, reason: "x" });
    await g.call("k-agent", "POST", `/v1/runs/b1/steps/${b.json.step}/outcome`, { status: "succeeded", result: { id: 3 } });
    await g.call("k-ops", "POST", "/v1/runs/b1/rollback", { confirm: true, approve_compensations: true });
    const ok = await waitDone(g, "b1");
    expect(ok.running).toBe(false);
    expect(g.compensations.map((c) => c.tool)).toEqual(["unbook"]);
    expect(g.engine.reversi.openRun("b1").state().steps[0]?.status).toBe("compensated");
  });

  it("404 for an unknown run (dry run and confirmed), 404 without a compensator, and 404 status for a run never rolled back", async () => {
    const f = await fx();
    expect((await f.call("k-ops", "POST", "/v1/runs/ghost/rollback", {})).status).toBe(404);
    const c = await f.call("k-ops", "POST", "/v1/runs/ghost/rollback", { confirm: true });
    expect(c.status).toBe(404);
    expect((await f.call("k-audit", "GET", "/v1/runs/ghost/rollback")).status).toBe(404);
    const g = await fx({ noCompensator: true });
    await seed(g);
    const r = await g.call("k-ops", "POST", "/v1/runs/r1/rollback", { confirm: true });
    expect(r.status).toBe(404);
    expect(r.json.error).toContain("no compensator");
  });

  it("confirm must be exactly true", async () => {
    const f = await fx();
    await seed(f);
    for (const confirm of ["true", 1, "yes"]) {
      const r = await f.call("k-ops", "POST", "/v1/runs/r1/rollback", { confirm });
      expect(r.json.dry_run, String(confirm)).toBe(true);
    }
    expect(f.compensator).not.toHaveBeenCalled();
  });

  it("start needs the operator role; status needs the auditor role", async () => {
    const f = await fx();
    await seed(f);
    await expectForbidden(f, "k-ops", "POST", "/v1/runs/r1/rollback", { confirm: true });
    expect(f.compensator).not.toHaveBeenCalled();
    await expectForbidden(f, "k-audit", "GET", "/v1/runs/r1/rollback");
    await f.call("k-ops", "POST", "/v1/runs/r1/rollback", { confirm: true });
    await waitDone(f);
    await expectAllowed(f, "k-audit", "GET", "/v1/runs/r1/rollback");
  });
});

describe("POST /integrations/slack/actions", () => {
  const PATH = "/integrations/slack/actions";

  async function pending(f: Fx, tool = "refund") {
    await f.call("k-agent", "POST", "/v1/runs", { run_id: "s1", permissions: ["o:w"] });
    const r = await f.call("k-agent", "POST", "/v1/runs/s1/intents", { tool, args: { amount: 1 }, reason: "x" });
    expect(r.json.decision).toBe("block");
    const rec = f.engine.approvals.list({ status: "pending" })[0];
    expect(rec?.tool).toBe(tool);
    return rec?.id as string;
  }
  function signed(f: Fx, user: string, action: string, id: string, o: { ts?: number; secret?: string; sig?: string } = {}) {
    const raw = new URLSearchParams({ payload: JSON.stringify({ user: { id: user }, actions: [{ action_id: action, value: id }] }) }).toString();
    const ts = String(o.ts ?? Math.floor(f.clock.t / 1000));
    const sig = o.sig ?? `v0=${createHmac("sha256", o.secret ?? SLACK_SECRET).update(`v0:${ts}:${raw}`).digest("hex")}`;
    return f.app.request(PATH, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-slack-request-timestamp": ts, "x-slack-signature": sig }, body: raw });
  }

  it("approves a pending request for a mapped approver, recording the Slack user in the ledger", async () => {
    const f = await fx();
    const id = await pending(f);
    const res = await signed(f, "U_APPR", "reversi_approve", id);
    expect(res.status).toBe(200);
    const j = (await res.json()) as any;
    expect(j).toMatchObject({ response_type: "in_channel", replace_original: false });
    expect(j.text).toBe("approved by slack-appr.");
    expect(f.engine.approvals.get(id)).toMatchObject({ status: "approved", decided_by: "slack-appr", decision_note: "from Slack" });
    const rec = f.engine.reversi.ledger.records().filter((x) => x.event === "approved").at(-1);
    expect(rec).toMatchObject({ actor: "slack-appr", tool: "refund" });
    // the agent's retry now goes through
    expect((await f.call("k-agent", "POST", "/v1/runs/s1/intents", { tool: "refund", args: { amount: 1 }, reason: "x" })).json.decision).toBe("allow");
  });

  it("denies on reversi_deny", async () => {
    const f = await fx();
    const id = await pending(f);
    const j = (await (await signed(f, "U_APPR", "reversi_deny", id)).json()) as any;
    expect(j.text).toBe("denied by slack-appr.");
    expect(f.engine.approvals.get(id)).toMatchObject({ status: "denied", decided_by: "slack-appr" });
  });

  it("rejects a bad signature, a wrong secret and a missing signature with 401, and decides nothing", async () => {
    const f = await fx();
    const id = await pending(f);
    for (const o of [{ sig: "v0=deadbeef" }, { secret: "other-secret" }, { sig: "" }]) {
      const res = await signed(f, "U_APPR", "reversi_approve", id, o);
      expect(res.status).toBe(401);
      expect(((await res.json()) as any).error).toBe("bad signature");
    }
    expect(f.engine.approvals.get(id)?.status).toBe("pending");
  });

  it("rejects a signature computed over a different body (tampered payload)", async () => {
    const f = await fx();
    const id = await pending(f);
    const ts = String(Math.floor(f.clock.t / 1000));
    const orig = new URLSearchParams({ payload: JSON.stringify({ user: { id: "U_APPR" }, actions: [{ action_id: "reversi_deny", value: id }] }) }).toString();
    const sig = `v0=${createHmac("sha256", SLACK_SECRET).update(`v0:${ts}:${orig}`).digest("hex")}`;
    const tampered = new URLSearchParams({ payload: JSON.stringify({ user: { id: "U_APPR" }, actions: [{ action_id: "reversi_approve", value: id }] }) }).toString();
    const res = await f.app.request(PATH, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-slack-request-timestamp": ts, "x-slack-signature": sig }, body: tampered });
    expect(res.status).toBe(401);
    expect(f.engine.approvals.get(id)?.status).toBe("pending");
  });

  it("rejects stale or future timestamps (over 5 minutes) and a missing or non-numeric timestamp, even with a valid signature", async () => {
    const f = await fx();
    const id = await pending(f);
    const now = Math.floor(f.clock.t / 1000);
    for (const ts of [now - 301, now - 3600, now + 301]) {
      const res = await signed(f, "U_APPR", "reversi_approve", id, { ts });
      expect(res.status, String(ts)).toBe(401);
      expect(((await res.json()) as any).error).toContain("timestamp");
    }
    const raw = new URLSearchParams({ payload: "{}" }).toString();
    const noTs = await f.app.request(PATH, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-slack-signature": "v0=x" }, body: raw });
    expect(noTs.status).toBe(401);
    const badTs = await f.app.request(PATH, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-slack-request-timestamp": "12ab", "x-slack-signature": "v0=x" }, body: raw });
    expect(badTs.status).toBe(401);
    expect(f.engine.approvals.get(id)?.status).toBe("pending");
    // inside the window it works
    expect((await signed(f, "U_APPR", "reversi_approve", id, { ts: now - 290 })).status).toBe(200);
  });

  it("needs no bearer key (the signature is the credential); a replay inside the window cannot decide twice", async () => {
    const f = await fx();
    const id = await pending(f);
    expect((await signed(f, "U_APPR", "reversi_approve", id)).status).toBe(200);
    const again = (await (await signed(f, "U_APPR", "reversi_approve", id)).json()) as any;
    expect(again.response_type).toBe("ephemeral");
    expect(again.text).toContain("not pending");
  });

  it("tells an unmapped Slack user they are not an approver and decides nothing", async () => {
    const f = await fx();
    const id = await pending(f);
    const j = (await (await signed(f, "U_STRANGER", "reversi_approve", id)).json()) as any;
    expect(j).toMatchObject({ response_type: "ephemeral", text: "You are not set up as an approver in Reversi." });
    expect(f.engine.approvals.get(id)?.status).toBe("pending");
  });

  it("the mapped user needs the approver role: an auditor-mapped user is refused on a request that names approvers", async () => {
    const f = await fx();
    const id = await pending(f);
    const j = (await (await signed(f, "U_AUD", "reversi_approve", id)).json()) as any;
    expect(j.response_type).toBe("ephemeral");
    expect(j.text).toBe("You are not set up as an approver in Reversi.");
    expect(f.engine.approvals.get(id)?.status).toBe("pending");
  });

  it("an auditor-only Slack user cannot approve even when the policy names no approvers", async () => {
    const f = await fx();
    const id = await pending(f, "payout");
    expect(f.engine.approvals.get(id)?.required_roles ?? []).toEqual([]);
    const j = (await (await signed(f, "U_AUD", "reversi_approve", id)).json()) as any;
    expect(f.engine.approvals.get(id)?.status, JSON.stringify(j)).toBe("pending");
    const d = (await (await signed(f, "U_AUD", "reversi_deny", id)).json()) as any;
    expect(f.engine.approvals.get(id)?.status, JSON.stringify(d)).toBe("pending");
  });

  it("an approver-mapped user can approve a request that names no approvers (default role is approver)", async () => {
    const f = await fx();
    const id = await pending(f, "payout");
    expect(f.engine.approvals.get(id)?.status).toBe("pending");
    expect(((await (await signed(f, "U_APPR", "reversi_approve", id)).json()) as any).text).toBe("approved by slack-appr.");
  });

  it("group membership from the mapping counts toward routing", async () => {
    const f = await fx();
    const id = await pending(f);
    // U_GROUP has the approver role too, so it satisfies the policy's role requirement
    expect(((await (await signed(f, "U_GROUP", "reversi_approve", id)).json()) as any).text).toBe("approved by slack-fin.");
  });

  it("answers Unknown action for an unknown action id or a missing value, and 400 for an unreadable payload", async () => {
    const f = await fx();
    const id = await pending(f);
    expect(((await (await signed(f, "U_APPR", "something_else", id)).json()) as any).text).toBe("Unknown action.");
    expect(((await (await signed(f, "U_APPR", "reversi_approve", "")).json()) as any).text).toBe("Unknown action.");
    const ts = String(Math.floor(f.clock.t / 1000));
    const raw = new URLSearchParams({ payload: "{not json" }).toString();
    const sig = `v0=${createHmac("sha256", SLACK_SECRET).update(`v0:${ts}:${raw}`).digest("hex")}`;
    const bad = await f.app.request(PATH, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-slack-request-timestamp": ts, "x-slack-signature": sig }, body: raw });
    expect(bad.status).toBe(400);
    expect(f.engine.approvals.get(id)?.status).toBe("pending");
  });

  it("an unknown approval id gets an ephemeral message, not a server error", async () => {
    const f = await fx();
    const j = (await (await signed(f, "U_APPR", "reversi_approve", "apr_missing")).json()) as any;
    expect(j.response_type).toBe("ephemeral");
    expect(j.text).toContain("not found");
  });

  it("404 when Slack approvals are not configured", async () => {
    const f = await fx({ noSlack: true });
    const res = await f.app.request(PATH, { method: "POST", body: "payload={}" });
    expect(res.status).toBe(404);
  });
});
