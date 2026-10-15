import { createSign, generateKeyPairSync, sign as nodeSign, type JsonWebKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  Approvals,
  ContentChecker,
  Ledger,
  Policy,
  Registry,
  Reversi,
  generateSigningKey,
  verifyBundle,
  type EvidenceBundle,
} from "@multimindlab/reversi";
import { KeyRing, OidcVerifier, createApp, type ApiKey, type LogEntry } from "../src/index.js";

const MANIFESTS = [
  { tool: "create_order", effect: "reversible", permission: "o:w", compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } } },
  { tool: "cancel_order", effect: "idempotent", permission: "o:w" },
  { tool: "refund", effect: "idempotent", permission: "o:w" },
];
const KEYS: ApiKey[] = [
  { name: "agent", role: "agent", key: "k-agent" },
  { name: "audit", role: "auditor", key: "k-audit" },
  { name: "appr", role: "approver", key: "k-appr" },
  { name: "ops", role: "operator", key: "k-ops" },
  { name: "root", role: "admin", key: "k-root" },
];

function make(extra: Partial<Parameters<typeof createApp>[0]> = {}, keys: ApiKey[] = KEYS) {
  const approvals = new Approvals();
  const policy = Policy.from({ rules: [{ id: "refund-approval", match: { tool: "refund" }, action: "require_approval" }] });
  const reversi = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(), approver: approvals.asApprover(), policy, content: new ContentChecker() });
  const logs: LogEntry[] = [];
  const app = createApp({ reversi, approvals, keys, logger: (e) => logs.push(e), session_secret: "test-secret", ...extra });
  const call = async (key: string | null, method: string, path: string, body?: unknown) => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (key) headers.authorization = `Bearer ${key}`;
    const res = await app.request(path, { method, headers, body: body === undefined || method === "GET" ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let json: any;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: res.status, json, text, res };
  };
  return { app, call, reversi, approvals, logs };
}
type Call = ReturnType<typeof make>["call"];
const openRun = (call: Call, id = "r1") => call("k-agent", "POST", "/v1/runs", { run_id: id, permissions: ["o:w"] });

describe("roles", () => {
  const matrix: Array<[string, string, string, Record<string, number>]> = [
    // method, path, (unused), expected status per key, against a run that exists
    ["GET", "/v1/runs/r1/plan", "", { "k-agent": 403, "k-audit": 200, "k-appr": 200, "k-ops": 200, "k-root": 200 }],
    ["GET", "/v1/runs/r1/export", "", { "k-agent": 403, "k-audit": 200, "k-appr": 200, "k-ops": 200, "k-root": 200 }],
    ["GET", "/v1/ledger/verify", "", { "k-agent": 403, "k-audit": 200, "k-appr": 200, "k-ops": 200, "k-root": 200 }],
    ["GET", "/v1/approvals", "", { "k-agent": 403, "k-audit": 200, "k-appr": 200, "k-ops": 200, "k-root": 200 }],
    ["POST", "/v1/runs/r1/steps/0/compensation", "", { "k-agent": 403, "k-audit": 403, "k-appr": 403 }],
    ["POST", "/v1/halt", "x", { "k-agent": 403, "k-audit": 403, "k-appr": 403, "k-ops": 403 }],
  ];
  it("enforces the capability each route needs", async () => {
    for (const [method, path, , expected] of matrix) {
      for (const [key, status] of Object.entries(expected)) {
        const { call } = make();
        await openRun(call);
        const r = await call(key, method, path, method === "POST" ? { reason: "x" } : undefined);
        expect(r.status, `${method} ${path} as ${key}`).toBe(status);
      }
    }
  });

  it("auditors and approvers cannot open or write runs; approvers cannot roll back", async () => {
    const { call } = make();
    expect((await call("k-audit", "POST", "/v1/runs", { permissions: ["o:w"] })).status).toBe(403);
    await openRun(call);
    expect((await call("k-audit", "POST", "/v1/runs/r1/intents", { tool: "create_order", reason: "x" })).status).toBe(403);
    expect((await call("k-appr", "POST", "/v1/runs/r1/steps/0/resolve", { status: "failed", note: "x" })).status).toBe(403);
    expect((await call("k-audit", "GET", "/v1/runs/r1")).status).toBe(200);
  });

  it("agents see only their own runs; others see all", async () => {
    const { call } = make({}, [...KEYS, { name: "agent2", role: "agent", key: "k-agent2" }]);
    await openRun(call);
    expect((await call("k-agent2", "GET", "/v1/runs/r1")).status).toBe(404);
    expect((await call("k-audit", "GET", "/v1/runs/r1")).status).toBe(200);
    expect((await call("k-agent2", "GET", "/v1/runs")).json.runs).toEqual([]);
  });
});

describe("api key rotation", () => {
  it("honours validity windows and disabled keys, and reloads without a restart", () => {
    let t = Date.parse("2026-01-15T00:00:00Z");
    const ring = new KeyRing(
      [
        { name: "svc", role: "operator", key: "old", expires_at: "2026-02-01T00:00:00Z" },
        { name: "svc", role: "operator", key: "new", not_before: "2026-01-20T00:00:00Z" },
        { name: "x", role: "auditor", key: "off", disabled: true },
      ],
      () => t,
    );
    expect(ring.authenticate("old")?.name).toBe("svc");
    expect(ring.authenticate("new")).toBeNull();
    expect(ring.authenticate("off")).toBeNull();
    t = Date.parse("2026-01-25T00:00:00Z");
    expect(ring.authenticate("old")).not.toBeNull();
    expect(ring.authenticate("new")).not.toBeNull();
    t = Date.parse("2026-02-02T00:00:00Z");
    expect(ring.authenticate("old")).toBeNull();
    ring.replace([{ name: "svc", role: "operator", key: "newer" }]);
    expect(ring.authenticate("new")).toBeNull();
    expect(ring.authenticate("newer")).not.toBeNull();
  });

  it("rejects malformed key entries", () => {
    expect(() => new KeyRing([{ name: "a", role: "agent" }])).toThrow(/key/);
    expect(() => new KeyRing([{ name: "a", key: "k" }])).toThrow(/role/);
    expect(() => new KeyRing([{ name: "a", role: "agent", key: "k", expires_at: "soon" }])).toThrow(/not a valid date/);
  });
});

describe("oidc", () => {
  const ISS = "https://id.example.com/realm";
  const AUD = "reversi";
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwks = {
    keys: [
      { ...(rsa.publicKey.export({ format: "jwk" }) as JsonWebKey), kid: "rsa1", use: "sig", alg: "RS256" },
      { ...(ec.publicKey.export({ format: "jwk" }) as JsonWebKey), kid: "ec1", use: "sig", alg: "ES256" },
    ],
  };
  const b64 = (o: unknown) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
  function token(claims: Record<string, unknown>, opts: { alg?: string; kid?: string; key?: "rsa" | "ec" } = {}) {
    const alg = opts.alg ?? "RS256";
    const head = b64({ alg, kid: opts.kid ?? (opts.key === "ec" ? "ec1" : "rsa1"), typ: "JWT" });
    const body = b64({ iss: ISS, aud: AUD, sub: "alice", exp: 2_000_000_000, roles: ["reversi-ops"], ...claims });
    const data = `${head}.${body}`;
    let sig: Buffer;
    if (alg === "RS256") sig = createSign("sha256").update(data).sign(rsa.privateKey);
    else if (alg === "ES256") sig = nodeSign("sha256", Buffer.from(data), { key: ec.privateKey, dsaEncoding: "ieee-p1363" });
    else sig = Buffer.from("forged");
    return `${data}.${sig.toString("base64url")}`;
  }
  function verifier(extra: Partial<ConstructorParameters<typeof OidcVerifier>[0]> = {}) {
    const fetched: string[] = [];
    const v = new OidcVerifier({
      issuer: ISS,
      audience: AUD,
      role_map: { "reversi-ops": "operator", "reversi-admin": "admin" },
      now: () => 1_900_000_000_000,
      fetch: (async (url: string) => {
        fetched.push(String(url));
        if (String(url).endsWith("openid-configuration")) return Response.json({ issuer: ISS, jwks_uri: `${ISS}/jwks` });
        if (String(url).endsWith("/jwks")) return Response.json(jwks);
        return new Response("nope", { status: 404 });
      }) as typeof fetch,
      ...extra,
    });
    return { v, fetched };
  }

  it("accepts RS256 and ES256 tokens and maps roles", async () => {
    const { v, fetched } = verifier();
    expect(await v.authenticate(token({}))).toMatchObject({ name: "alice", roles: ["operator"], via: "oidc" });
    expect(await v.authenticate(token({ roles: ["reversi-admin", "other"] }, { alg: "ES256", key: "ec" }))).toMatchObject({ roles: ["admin"] });
    expect(fetched.filter((u) => u.endsWith("/jwks"))).toHaveLength(1); // cached after the first fetch
  });

  it("rejects bad tokens: wrong audience, issuer, expiry, signature, alg, role", async () => {
    const { v } = verifier();
    expect(await v.authenticate(token({ aud: "other" }))).toBeNull();
    expect(await v.authenticate(token({ aud: ["x", AUD] }))).not.toBeNull();
    expect(await v.authenticate(token({ iss: "https://evil" }))).toBeNull();
    expect(await v.authenticate(token({ exp: 1_000_000_000 }))).toBeNull();
    expect(await v.authenticate(token({ nbf: 2_000_000_000 }))).toBeNull();
    expect(await v.authenticate(token({ roles: ["unmapped"] }))).toBeNull();
    expect(await v.authenticate(token({ sub: "" }))).toBeNull();
    expect(await v.authenticate(token({}, { alg: "HS256" }))).toBeNull();
    expect(await v.authenticate(token({}, { alg: "none" }))).toBeNull();
    const good = token({});
    const [h, , s] = good.split(".");
    expect(await v.authenticate(`${h}.${b64({ iss: ISS, aud: AUD, sub: "mallory", exp: 2_000_000_000, roles: ["reversi-admin"] })}.${s}`)).toBeNull();
    expect(await v.authenticate(token({}, { kid: "unknown" }))).toBeNull();
    expect(await v.authenticate("not.a.jwt")).toBeNull();
    expect(await v.authenticate("")).toBeNull();
  });

  it("supports nested role claims and custom actor claims", async () => {
    const { v } = verifier({ role_claim: "realm_access.roles", actor_claim: "preferred_username" });
    expect(await v.authenticate(token({ realm_access: { roles: ["reversi-ops"] }, preferred_username: "alice@example.com" }))).toMatchObject({ name: "alice@example.com" });
  });

  it("works through the HTTP API alongside API keys", async () => {
    const { v } = verifier();
    const { call } = make({ oidc: v });
    expect((await call(token({}), "GET", "/v1/approvals")).status).toBe(200);
    expect((await call(token({}), "POST", "/v1/halt", { reason: "x" })).status).toBe(403); // operator, not admin
    expect((await call(token({ roles: ["reversi-admin"] }), "POST", "/v1/halt", { reason: "x" })).status).toBe(200);
    expect((await call("k-audit", "GET", "/v1/approvals")).status).toBe(200);
    expect((await call("garbage", "GET", "/v1/approvals")).status).toBe(401);
  });
});

describe("approvals over HTTP", () => {
  it("queues a request, lets an approver decide, then lets the agent retry once", async () => {
    const { call } = make();
    await openRun(call);
    const intent = () => call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "refund", args: { amount: 50 }, reason: "customer" });
    const first = await intent();
    expect(first.json).toMatchObject({ decision: "block", reasons: [expect.stringContaining("pending")] });
    const list = await call("k-audit", "GET", "/v1/approvals?status=pending");
    expect(list.json.approvals).toHaveLength(1);
    const id = list.json.approvals[0].id;
    expect(list.json.approvals[0]).toMatchObject({ tool: "refund", arg_keys: ["amount"] });
    expect(JSON.stringify(list.json)).not.toContain("50,");

    expect((await call("k-agent", "POST", `/v1/approvals/${id}/approve`, {})).status).toBe(403);
    expect((await call("k-audit", "POST", `/v1/approvals/${id}/approve`, {})).status).toBe(403);
    const ok = await call("k-appr", "POST", `/v1/approvals/${id}/approve`, { note: "checked ticket" });
    expect(ok.json).toMatchObject({ status: "approved", decided_by: "appr", decision_note: "checked ticket" });
    expect((await call("k-appr", "POST", `/v1/approvals/${id}/approve`, {})).status).toBe(409);
    expect((await call("k-appr", "POST", "/v1/approvals/nope/approve", {})).status).toBe(404);

    expect((await intent()).json.decision).toBe("allow");
    expect((await intent()).json.decision).toBe("block");
  });

  it("deny is final for that call and carries the reason", async () => {
    const { call } = make();
    await openRun(call);
    const intent = () => call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "refund", args: { a: 1 }, reason: "x" });
    await intent();
    const id = (await call("k-appr", "GET", "/v1/approvals")).json.approvals[0].id;
    await call("k-appr", "POST", `/v1/approvals/${id}/deny`, { note: "not today" });
    expect((await intent()).json.reasons[0]).toContain("not today");
  });
});

describe("reconciliation, kill switch, evidence, ops endpoints", () => {
  it("resolves an uncertain step, records who and why, and makes it rollbackable", async () => {
    const { call, reversi } = make();
    await openRun(call);
    await call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "create_order", reason: "x" });
    await call("k-agent", "POST", "/v1/runs/r1/steps/0/outcome", { status: "uncertain", error: "timeout" });
    expect((await call("k-ops", "POST", "/v1/runs/r1/steps/0/resolve", { status: "succeeded", result: { id: 5 } })).status).toBe(400); // note required
    const r = await call("k-ops", "POST", "/v1/runs/r1/steps/0/resolve", { status: "succeeded", result: { id: 5 }, note: "found order 5 in admin UI" });
    expect(r.json).toEqual({ step: 0, status: "succeeded" });
    const last = reversi.ledger.records().at(-1);
    expect(last).toMatchObject({ actor: "ops", event: "succeeded" });
    expect(last?.detail).toContain("found order 5");
    expect((await call("k-ops", "GET", "/v1/runs/r1/plan")).json.actions[0]).toMatchObject({ kind: "compensate", args: { id: 5 } });
  });

  it("admin can halt and resume; calls are blocked meanwhile", async () => {
    const { call } = make();
    await openRun(call);
    expect((await call("k-root", "POST", "/v1/halt", { reason: "incident" })).json.halted).toContain("incident (by root)");
    expect((await call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "create_order", reason: "x" })).json.decision).toBe("block");
    expect((await call("k-audit", "GET", "/v1/status")).json.halted).toContain("incident");
    expect((await call("k-root", "POST", "/v1/resume")).json.halted).toBeNull();
    expect((await call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "create_order", reason: "x" })).json.decision).toBe("allow");
  });

  it("serves signed bundles that verify, and refuses when no key is configured", async () => {
    const key = generateSigningKey();
    const { call } = make({ signing_key: key });
    await openRun(call);
    await call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "create_order", reason: "x" });
    const full = (await call("k-audit", "GET", "/v1/ledger/bundle")).json as EvidenceBundle;
    expect(verifyBundle(full, { trusted_public_pem: key.public_pem })).toMatchObject({ ok: true, chain: "full" });
    const one = (await call("k-audit", "GET", "/v1/runs/r1/bundle")).json as EvidenceBundle;
    expect(verifyBundle(one)).toMatchObject({ ok: true, chain: "per-record" });
    expect((await call("k-audit", "GET", "/v1/evidence/key")).json.public_key_pem).toBe(key.public_pem);
    expect((await call("k-agent", "GET", "/v1/ledger/bundle")).status).toBe(403);
    const none = make();
    expect((await none.call("k-audit", "GET", "/v1/ledger/bundle")).status).toBe(404);
  });

  it("renders an HTML report", async () => {
    const { call } = make();
    await openRun(call);
    const r = await call("k-audit", "GET", "/v1/runs/r1/report");
    expect(r.status).toBe(200);
    expect(r.text).toContain("Run r1");
  });

  it("exposes health, readiness and metrics", async () => {
    const { call, logs } = make();
    await openRun(call);
    await call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "refund", reason: "x" }); // queues an approval
    expect((await call(null, "GET", "/readyz")).json).toMatchObject({ ok: true });
    expect((await call(null, "GET", "/metrics")).status).toBe(401);
    expect((await call("k-agent", "GET", "/metrics")).status).toBe(403);
    const m = (await call("k-audit", "GET", "/metrics")).text;
    expect(m).toContain('reversi_ledger_events_total{event="blocked"} 1');
    expect(m).toContain('reversi_approvals{status="pending"} 1');
    expect(m).toContain("reversi_halted 0");
    expect(m).toMatch(/reversi_http_requests_total\{method="POST",route="\/v1\/runs\/:id\/intents",status="200"\} 1/);
    expect(logs.some((l) => l.path === "/v1/runs/r1/intents" && l.principal === "agent" && l.status === 200)).toBe(true);
    const open = make({ metrics_public: true });
    expect((await open.call(null, "GET", "/metrics")).status).toBe(200);
  });
});

describe("console", () => {
  const cookieOf = (res: Response) => (res.headers.get("set-cookie") ?? "").split(";")[0] as string;
  async function login(app: ReturnType<typeof make>["app"], key: string) {
    const res = await app.request("/console/login", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ key }) });
    return res;
  }
  const get = (app: ReturnType<typeof make>["app"], path: string, cookie: string) => app.request(path, { headers: { cookie } });
  const csrfIn = (html: string) => /name="csrf" value="([^"]+)"/.exec(html)?.[1] as string;
  const post = (app: ReturnType<typeof make>["app"], path: string, cookie: string, form: Record<string, string>) =>
    app.request(path, { method: "POST", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form) });

  it("requires a console role to sign in and sets a locked-down cookie", async () => {
    const { app } = make();
    expect((await login(app, "wrong")).status).toBe(401);
    expect((await login(app, "k-agent")).status).toBe(401);
    const ok = await login(app, "k-audit");
    expect(ok.status).toBe(303);
    const cookie = ok.headers.get("set-cookie") ?? "";
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Strict/);
    expect(cookie).toMatch(/Path=\/console/);
    expect((await app.request("/console/runs")).status).toBe(302);
    const secure = make({ secure_cookies: true });
    expect((await login(secure.app, "k-audit")).headers.get("set-cookie")).toMatch(/; Secure/);
  });

  it("rejects forged and tampered session cookies", async () => {
    const { app } = make();
    const c = cookieOf(await login(app, "k-audit"));
    expect((await get(app, "/console/runs", c)).status).toBe(200);
    const [payload, mac] = c.replace("rv_session=", "").split(".") as [string, string];
    const forged = Buffer.from(JSON.stringify({ name: "x", roles: ["admin"], exp: Date.now() + 1e6, sid: "a" })).toString("base64url");
    expect((await get(app, "/console/runs", `rv_session=${forged}.${mac}`)).status).toBe(302);
    expect((await get(app, "/console/runs", `rv_session=${payload}.${"A".repeat(mac.length)}`)).status).toBe(302);
  });

  it("lists runs, shows a run, escapes HTML and sets CSP", async () => {
    const { app, call } = make();
    await call("k-agent", "POST", "/v1/runs", { run_id: "r1", permissions: ["o:w"], reason: "<script>alert(1)</script>" });
    await call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "<img src=x onerror=alert(1)>", reason: "<b>x</b>" });
    const c = cookieOf(await login(app, "k-audit"));
    const runs = await get(app, "/console/runs", c);
    expect(await runs.text()).toContain("r1");
    expect(runs.headers.get("content-security-policy")).toContain("default-src 'none'");
    const page = await (await get(app, "/console/runs/r1", c)).text();
    expect(page).not.toContain("<script>alert(1)</script>");
    expect(page).not.toContain("<img src=x");
    expect(page).toContain("&lt;img src=x");
    expect((await get(app, "/console/runs/missing", c)).status).toBe(404);
    expect(await (await get(app, "/console/tools", c)).text()).toContain("create_order");
    expect((await get(app, "/console/runs/r1/report", c)).status).toBe(200);
  });

  it("approves through a form, needs CSRF, and respects roles", async () => {
    const { app, call, approvals } = make();
    await openRun(call);
    await call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "refund", args: { n: 1 }, reason: "x" });
    const id = approvals.list({ status: "pending" })[0]?.id as string;

    const auditor = cookieOf(await login(app, "k-audit"));
    const aPage = await (await get(app, "/console/approvals", auditor)).text();
    expect(aPage).toContain("refund");
    expect(aPage).not.toContain(`/console/approvals/${id}/approve`); // no buttons for an auditor
    expect((await post(app, `/console/approvals/${id}/approve`, auditor, { csrf: csrfIn(aPage) })).status).toBe(403);

    const approver = cookieOf(await login(app, "k-appr"));
    const page = await (await get(app, "/console/approvals", approver)).text();
    expect(page).toContain(`/console/approvals/${id}/approve`);
    expect((await post(app, `/console/approvals/${id}/approve`, approver, {})).status).toBe(403); // no csrf
    expect((await post(app, `/console/approvals/${id}/approve`, approver, { csrf: "bad" })).status).toBe(403);
    const done = await post(app, `/console/approvals/${id}/approve`, approver, { csrf: csrfIn(page), note: "ok" });
    expect(done.status).toBe(303);
    expect(approvals.get(id)).toMatchObject({ status: "approved", decided_by: "appr" });
    // A token from another session does not work.
    const other = cookieOf(await login(app, "k-appr"));
    expect((await post(app, `/console/approvals/${id}/deny`, other, { csrf: csrfIn(page) })).status).toBe(403);
  });

  it("resolves a step and toggles the kill switch from the console", async () => {
    const { app, call, reversi } = make();
    await openRun(call);
    await call("k-agent", "POST", "/v1/runs/r1/intents", { tool: "create_order", reason: "x" });
    const ops = cookieOf(await login(app, "k-ops"));
    let page = await (await get(app, "/console/runs/r1", ops)).text();
    expect(page).toContain("/console/runs/r1/steps/0/resolve");
    const res = await post(app, "/console/runs/r1/steps/0/resolve", ops, { csrf: csrfIn(page), status: "failed", note: "never created" });
    expect(res.status).toBe(303);
    expect(reversi.openRun("r1").state().steps[0]?.status).toBe("failed");

    const evidence = await (await get(app, "/console/evidence", ops)).text();
    expect(evidence).toContain("chain verified");
    expect((await post(app, "/console/halt", ops, { csrf: csrfIn(evidence), reason: "x" })).status).toBe(403); // operator is not admin
    const root = cookieOf(await login(app, "k-root"));
    page = await (await get(app, "/console/evidence", root)).text();
    expect((await post(app, "/console/halt", root, { csrf: csrfIn(page), reason: "drill" })).status).toBe(303);
    expect(reversi.halted()).toContain("drill");
    expect(await (await get(app, "/console/runs", root)).text()).toContain("Kill switch active");
    page = await (await get(app, "/console/evidence", root)).text();
    await post(app, "/console/resume", root, { csrf: csrfIn(page) });
    expect(reversi.halted()).toBeNull();
  });

  it("logs out", async () => {
    const { app } = make();
    const c = cookieOf(await login(app, "k-audit"));
    const page = await (await get(app, "/console/runs", c)).text();
    const out = await post(app, "/console/logout", c, { csrf: csrfIn(page) });
    expect(out.status).toBe(303);
    expect(out.headers.get("set-cookie")).toMatch(/Max-Age=0/);
  });
});
