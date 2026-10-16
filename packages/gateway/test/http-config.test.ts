import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { generateKeyPairSync, createSign, type JsonWebKey } from "node:crypto";
import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { KeyRing, OidcVerifier } from "@multimindlab/reversi";
import { ConfigError, createHttpGateway, expandEnv, isLoopback, parseGatewayConfig } from "../src/index.js";
import { build, fakeUpstream, json, textOf } from "./helpers.js";

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (closers.length) await (closers.pop() as () => Promise<void>)();
});

async function serve(opts: { keys?: KeyRing; oidc?: OidcVerifier; allowed_origins?: string[]; allowed_hosts?: string[] } = {}) {
  const up = await fakeUpstream("shop", { create_order: () => json({ id: 7 }), cancel_order: () => json({ ok: true }), lookup: () => json({}) });
  const { gateway, pool, reversi } = build({ fakes: [up] });
  const http = createHttpGateway({ gateway, pool, host: "127.0.0.1", port: 0, anonymous_actor: "anon", ...opts });
  await new Promise<void>((r) => http.server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(http.server.address() as AddressInfo).port}`;
  closers.push(http.close);
  return { url, up, reversi, http };
}

async function mcp(url: string, path: string, token?: string) {
  const client = new Client({ name: "t", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(url + path), { requestInit: { headers: token ? { Authorization: `Bearer ${token}` } : {} } }));
  closers.push(() => client.close());
  return client;
}

const KEYS = new KeyRing([
  { name: "agent-1", role: "agent", key: "k-agent" },
  { name: "agent-2", role: "agent", key: "k-agent2" },
  { name: "ops", role: "operator", key: "k-ops" },
  { name: "aud", role: "auditor", key: "k-aud" },
]);

const post = (url: string, headers: Record<string, string>, body: unknown = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "x", version: "1" } } }) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(body) });

describe("HTTP gateway with API keys", () => {
  it("rejects missing or wrong credentials with a protected-resource pointer", async () => {
    const { url } = await serve({ keys: KEYS });
    const none = await post(`${url}/mcp`, {});
    expect(none.status).toBe(401);
    expect(none.headers.get("www-authenticate")).toContain("/.well-known/oauth-protected-resource");
    expect((await post(`${url}/mcp`, { authorization: "Bearer wrong" })).status).toBe(401);
  });

  it("serves an agent session: one run per session, actor from the key, upstream calls journaled", async () => {
    const { url, reversi, up } = await serve({ keys: KEYS });
    const c = await mcp(url, "/mcp", "k-agent");
    expect(textOf(await c.callTool({ name: "create_order", arguments: {} }))).toBe('{"id":7}');
    expect(up.calls).toHaveLength(1);
    const start = reversi.ledger.records().find((r) => r.event === "run_started");
    expect(start?.actor).toBe("agent-1");
    const c2 = await mcp(url, "/mcp", "k-agent2");
    await c2.callTool({ name: "lookup", arguments: {} });
    expect(reversi.runIds()).toHaveLength(2);
  });

  it("separates the endpoints by role", async () => {
    const { url } = await serve({ keys: KEYS });
    expect((await post(`${url}/operator/mcp`, { authorization: "Bearer k-agent" })).status).toBe(403);
    expect((await post(`${url}/mcp`, { authorization: "Bearer k-ops" })).status).toBe(403);
    const op = await mcp(url, "/operator/mcp", "k-ops");
    const names = (await op.listTools()).tools.map((t) => t.name);
    expect(names).toContain("reversi.approve_action");
    const aud = await mcp(url, "/operator/mcp", "k-aud");
    expect((await aud.listTools()).tools.map((t) => t.name)).not.toContain("reversi.approve_action");
  });

  it("an operator approves and rolls back over HTTP, end to end", async () => {
    const { url, up } = await serve({ keys: KEYS });
    const agent = await mcp(url, "/mcp", "k-agent");
    const ops = await mcp(url, "/operator/mcp", "k-ops");
    await agent.callTool({ name: "create_order", arguments: {} });
    const runs = JSON.parse(textOf(await ops.callTool({ name: "reversi.list_runs", arguments: {} }))).runs as string[];
    expect(runs).toHaveLength(1);
    const out = JSON.parse(textOf(await ops.callTool({ name: "reversi.execute_rollback", arguments: { run_id: runs[0], confirm: true } })));
    expect(out.report.complete).toBe(true);
    expect(up.calls.map((c) => c.name)).toEqual(["create_order", "cancel_order"]);
  });

  it("a session cannot be used by another principal", async () => {
    const { url, http } = await serve({ keys: KEYS });
    await mcp(url, "/mcp", "k-agent");
    const [id] = [...http.sessions.keys()];
    const r = await post(`${url}/mcp`, { authorization: "Bearer k-agent2", "mcp-session-id": id as string }, { jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect(r.status).toBe(403);
    const unknown = await post(`${url}/mcp`, { authorization: "Bearer k-agent", "mcp-session-id": "nope" }, { jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect(unknown.status).toBe(404);
    const noInit = await post(`${url}/mcp`, { authorization: "Bearer k-agent" }, { jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect(noInit.status).toBe(400);
  });

  it("ties a session to the roles it was opened with", async () => {
    const keys = new KeyRing([{ name: "svc", role: "agent", key: "k-svc" }]);
    const { url, http } = await serve({ keys });
    await mcp(url, "/mcp", "k-svc");
    const [id] = [...http.sessions.keys()];
    keys.replace([{ name: "svc", roles: ["agent", "admin"], key: "k-svc" }]); // same name, different roles
    const r = await post(`${url}/mcp`, { authorization: "Bearer k-svc", "mcp-session-id": id as string }, { jsonrpc: "2.0", id: 2, method: "tools/list" });
    expect(r.status).toBe(403);
  });

  it("validates Host and Origin, and serves health and readiness", async () => {
    const { url } = await serve({ keys: KEYS });
    // fetch() will not let a caller set Host, so send this one with node:http.
    const rawStatus = (headers: Record<string, string>) =>
      new Promise<number>((resolve, reject) => {
        const u = new URL(url);
        const req = request({ host: u.hostname, port: u.port, path: "/healthz", headers }, (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        });
        req.on("error", reject);
        req.end();
      });
    expect(await rawStatus({ host: "evil.example.com" })).toBe(403);
    expect(await rawStatus({ host: `localhost:${new URL(url).port}` })).toBe(200);
    expect((await post(`${url}/mcp`, { authorization: "Bearer k-agent", origin: "https://evil.example.com" })).status).toBe(403);
    expect((await fetch(`${url}/healthz`)).status).toBe(200);
    const ready = await (await fetch(`${url}/readyz`)).json();
    expect(ready).toMatchObject({ ok: true, upstreams: [{ name: "shop", ok: true }] });
    expect((await fetch(`${url}/nope`)).status).toBe(404);
    const allowed = await serve({ keys: KEYS, allowed_origins: ["https://app.example.com"] });
    expect((await post(`${allowed.url}/mcp`, { authorization: "Bearer k-agent", origin: "https://app.example.com" })).status).toBe(200);
  });

  it("rejects oversized bodies", async () => {
    const { url, reversi } = await serve({ keys: KEYS });
    // The server answers 413 as soon as the limit is crossed. A client still sending its megabytes may see that answer or,
    // if the connection closes under it first, a failed fetch: what must never happen is the request being processed.
    const r = await post(`${url}/mcp`, { authorization: "Bearer k-agent" }, { pad: "x".repeat(5_000_000) }).then(
      (res) => res.status,
      () => "reset",
    );
    expect([413, "reset"]).toContain(r);
    expect(reversi.runIds()).toEqual([]);
  });
});

describe("HTTP gateway without auth", () => {
  it("serves only the agent endpoint, as the configured actor", async () => {
    const { url, reversi } = await serve();
    expect((await post(`${url}/operator/mcp`, {})).status).toBe(404);
    const c = await mcp(url, "/mcp");
    await c.callTool({ name: "lookup", arguments: {} });
    expect(reversi.ledger.records()[0]?.actor).toBe("anon");
  });

  it("refuses to listen beyond loopback", async () => {
    const up = await fakeUpstream("shop", {});
    const { gateway, pool } = build({ fakes: [up] });
    expect(() => createHttpGateway({ gateway, pool, host: "0.0.0.0", port: 0, anonymous_actor: "x" })).toThrow(/without authentication/);
    expect(isLoopback("127.0.0.1")).toBe(true);
    expect(isLoopback("10.0.0.5")).toBe(false);
    expect(isLoopback("127.attacker.example.com")).toBe(false);
    expect(isLoopback("127.0.0.256x")).toBe(false);
    expect(isLoopback("127.0.0.2")).toBe(true);
  });
});

describe("HTTP gateway with OIDC", () => {
  it("accepts a valid token and advertises the issuer", async () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = { ...(rsa.publicKey.export({ format: "jwk" }) as JsonWebKey), kid: "k1", use: "sig", alg: "RS256" };
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const data = `${b64({ alg: "RS256", kid: "k1" })}.${b64({ iss: "https://idp", aud: "https://gw", sub: "agent-x", exp: 2_000_000_000, roles: ["bot"] })}`;
    const token = `${data}.${createSign("sha256").update(data).sign(rsa.privateKey).toString("base64url")}`;
    const oidc = new OidcVerifier({
      issuer: "https://idp",
      audience: "https://gw",
      role_map: { bot: "agent" },
      now: () => 1_900_000_000_000,
      fetch: (async (u: string) => (String(u).endsWith("openid-configuration") ? Response.json({ jwks_uri: "https://idp/jwks" }) : Response.json({ keys: [jwk] }))) as typeof fetch,
    });
    const { url, reversi } = await serve({ oidc });
    const meta = await (await fetch(`${url}/.well-known/oauth-protected-resource`)).json();
    expect(meta.authorization_servers).toEqual(["https://idp"]);
    const c = await mcp(url, "/mcp", token);
    await c.callTool({ name: "lookup", arguments: {} });
    expect(reversi.ledger.records()[0]?.actor).toBe("agent-x");
    expect((await post(`${url}/mcp`, { authorization: "Bearer a.b.c" })).status).toBe(401);
  });
});

describe("config", () => {
  it("parses a full config with defaults", () => {
    const c = parseGatewayConfig({
      upstreams: [{ name: "gh", url: "https://example.com/mcp", headers: { Authorization: "Bearer ${TOK}" } }, { name: "fs", command: "node", args: ["x.js"] }],
      allow: ["gh.*"],
      listen: { port: 7431 },
    });
    expect(c).toMatchObject({ mode: "enforce", actor: "mcp-client", listen: { host: "127.0.0.1", port: 7431 }, deny: [] });
  });

  it("reports every problem", () => {
    try {
      parseGatewayConfig({ mode: "loud", upstreams: [{ name: "a b", command: "x", url: "https://e" }, { name: "dup", command: "x" }, { name: "dup", url: "ftp://x" }], listen: { port: 99999 }, nope: 1, auth: { oidc: { issuer: "i" } } });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      const m = (e as ConfigError).errors.join("\n");
      expect(m).toContain("`mode` must be observe or enforce");
      expect(m).toContain("name must be letters");
      expect(m).toContain("exactly one of");
      expect(m).toContain("duplicate name");
      expect(m).toContain("url must be http(s)");
      expect(m).toContain("`listen` needs a port");
      expect(m).toContain("unknown field `nope`");
      expect(m).toContain("auth.oidc needs");
    }
    expect(() => parseGatewayConfig({})).toThrow(/at least one upstream/);
  });

  it("expands environment variables and fails loudly when one is missing", () => {
    expect(expandEnv("Bearer ${TOK}", { TOK: "abc" })).toBe("Bearer abc");
    expect(() => expandEnv("${MISSING}", {})).toThrow(/MISSING is not set/);
  });
});

describe("Reversi-Run-Id header", () => {
  it("continues the named run over HTTP, and refuses another principal's run", async () => {
    const { url, reversi } = await serve({ keys: KEYS });
    const withRun = async (key: string, run: string) => {
      const client = new Client({ name: "t", version: "1" });
      await client.connect(new StreamableHTTPClientTransport(new URL(`${url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${key}`, "Reversi-Run-Id": run } } }));
      closers.push(() => client.close());
      return client;
    };
    const a = await withRun("k-agent", "shared-run");
    await a.callTool({ name: "lookup", arguments: {} });
    const b = await withRun("k-agent", "shared-run");
    await b.callTool({ name: "lookup", arguments: {} });
    expect(reversi.runIds()).toEqual(["shared-run"]);
    expect(reversi.openRun("shared-run").state().steps).toHaveLength(2);
    await expect(withRun("k-agent2", "shared-run")).rejects.toThrow();
    expect((await post(`${url}/mcp`, { authorization: "Bearer k-agent", "reversi-run-id": "bad id!" })).status).toBe(400);
  });
});
