/**
 * Streamable HTTP front end for the gateway.
 *
 *   /mcp           agent endpoint. Needs the `agent` role. One MCP session = one run.
 *   /operator/mcp  operator endpoint. Needs credentials; never served without authentication.
 *
 * Authentication is API keys and/or OIDC bearer tokens (the same verifiers the server uses). With
 * none configured the gateway serves only the agent endpoint, only on loopback, as one fixed actor.
 * The MCP spec's guidance is followed: a 401 points at protected-resource metadata, and Host and
 * Origin are validated so a web page cannot drive a loopback gateway (DNS rebinding).
 */
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { RUN_ID_PATTERN, can, type KeyRing, type OidcVerifier, type Principal } from "@multimindlab/reversi";
import type { Gateway } from "./gateway.js";
import type { UpstreamPool } from "./upstream.js";

export interface HttpGatewayOptions {
  gateway: Gateway;
  pool: UpstreamPool;
  host: string;
  port: number;
  keys?: KeyRing;
  oidc?: OidcVerifier;
  /** Public URL of this gateway, for protected-resource metadata. Default: derived from host and port. */
  resource_url?: string;
  /** Actor for unauthenticated agent sessions (only when no auth is configured). */
  anonymous_actor: string;
  allowed_hosts?: string[];
  allowed_origins?: string[];
  /** Serves `/console/*` (the server's console, mounted on this port). Its own checks guard it, so the MCP Origin rule does not apply. */
  console?: (req: IncomingMessage, res: ServerResponse) => unknown;
  /** Idle sessions are closed after this long. Default 30 minutes. */
  session_ttl_ms?: number;
  max_body_bytes?: number;
}

interface Session {
  transport: StreamableHTTPServerTransport;
  owner: string;
  kind: "agent" | "operator";
  last: number;
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

export function isLoopback(host: string): boolean {
  return LOOPBACK.has(host) || /^127(\.\d{1,3}){3}$/.test(host);
}

/** Who a session belongs to: the name and the roles it was opened with. Changed roles mean a new login. */
const ownerKey = (p: Principal) => `${p.name}|${[...p.roles].sort().join(",")}`;

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage, limit: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > limit) throw Object.assign(new Error("body too large"), { status: 413 });
    chunks.push(c as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    throw Object.assign(new Error("body must be JSON"), { status: 400 });
  }
}

export function createHttpGateway(o: HttpGatewayOptions): { server: HttpServer; sessions: Map<string, Session>; close: () => Promise<void> } {
  const authConfigured = !!o.keys?.size || !!o.oidc;
  if (!authConfigured && !isLoopback(o.host)) {
    throw new Error(`refusing to listen on ${o.host} without authentication: configure auth.keys or auth.oidc, or bind to 127.0.0.1`);
  }
  const resource = (o.resource_url ?? `http://${o.host}:${o.port}`).replace(/\/$/, "");
  const metadataUrl = `${resource}/.well-known/oauth-protected-resource`;
  const sessions = new Map<string, Session>();
  const ttl = o.session_ttl_ms ?? 30 * 60_000;
  const limit = o.max_body_bytes ?? 4_000_000;
  const allowedHosts = new Set((o.allowed_hosts ?? []).map((h) => h.toLowerCase()));
  const allowedOrigins = new Set(o.allowed_origins ?? []);

  const authenticate = async (req: IncomingMessage): Promise<Principal | null> => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
    if (!m) return null;
    const token = m[1] as string;
    return o.keys?.authenticate(token) ?? (o.oidc && token.split(".").length === 3 ? await o.oidc.authenticate(token) : null);
  };

  let ready: { at: number; up: Array<{ name: string; ok: boolean }> } | null = null;
  const reap = setInterval(() => {
    const cutoff = Date.now() - ttl;
    for (const [id, s] of sessions) if (s.last < cutoff) void s.transport.close();
  }, 60_000);
  reap.unref();

  const handleMcp = async (req: IncomingMessage, res: ServerResponse, kind: "agent" | "operator") => {
    let who: Principal | null = null;
    if (authConfigured) {
      who = await authenticate(req);
      if (!who) return json(res, 401, { error: "missing or invalid credentials" }, { "WWW-Authenticate": `Bearer resource_metadata="${metadataUrl}"` });
      const allowed = kind === "agent" ? who.roles.includes("agent") : can(who, "read");
      if (!allowed) return json(res, 403, { error: kind === "agent" ? "agent role required" : "auditor role or higher required" });
    } else {
      if (kind === "operator") return json(res, 404, { error: "the operator endpoint needs authentication to be configured" });
      who = { name: o.anonymous_actor, roles: ["agent"], via: "api_key" };
    }

    const sid = req.headers["mcp-session-id"];
    const sessionId = Array.isArray(sid) ? sid[0] : sid;
    let body: unknown;
    if (req.method === "POST") body = await readBody(req, limit);

    if (sessionId) {
      const s = sessions.get(sessionId);
      if (!s || s.kind !== kind) return json(res, 404, { error: "unknown session" });
      if (s.owner !== ownerKey(who)) return json(res, 403, { error: "this session belongs to another principal, or the credential's roles changed" });
      s.last = Date.now();
      return s.transport.handleRequest(req, res, body);
    }
    if (req.method !== "POST" || !isInitializeRequest(body)) {
      return json(res, 400, { error: "send an initialize request first (no Mcp-Session-Id)" });
    }
    const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, owner: ownerKey(who as Principal), kind, last: Date.now() });
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    };
    const wanted = req.headers["reversi-run-id"];
    const runId = Array.isArray(wanted) ? wanted[0] : wanted;
    if (runId !== undefined && !RUN_ID_PATTERN.test(runId)) return json(res, 400, { error: "invalid Reversi-Run-Id" });
    let session;
    try {
      session = o.gateway.createSession({ principal: who, operator: kind === "operator", run_id: runId });
    } catch (e) {
      return json(res, 403, { error: e instanceof Error ? e.message : "cannot continue that run" });
    }
    const { server } = session;
    await server.connect(transport);
    return transport.handleRequest(req, res, body);
  };

  const server = createServer((req, res) => {
    void (async () => {
      try {
        const host = (req.headers.host ?? "").toLowerCase();
        const hostname = host.startsWith("[") ? host.slice(0, host.indexOf("]") + 1) : host.split(":")[0] ?? "";
        const hostOk = allowedHosts.size ? allowedHosts.has(host) || allowedHosts.has(hostname) : !isLoopback(o.host) || isLoopback(hostname);
        if (!hostOk) return json(res, 403, { error: "host not allowed" });
        const path = (req.url ?? "/").split("?")[0];
        const origin = req.headers.origin;
        const isConsole = o.console !== undefined && (path === "/console" || path?.startsWith("/console/"));
        if (origin && !isConsole && !allowedOrigins.has(origin)) return json(res, 403, { error: "origin not allowed" });
        if (isConsole) return void (await o.console?.(req, res));
        if (path === "/healthz") return json(res, 200, { ok: true });
        if (path === "/readyz") {
          // Unauthenticated, and it pings every upstream: answer from a two-second cache.
          if (!ready || Date.now() - ready.at > 2000) {
            const up = await o.pool.status();
            ready = { at: Date.now(), up };
          }
          const ok = ready.up.every((u) => u.ok);
          return json(res, ok ? 200 : 503, { ok, upstreams: ready.up, sessions: sessions.size });
        }
        if (path === "/.well-known/oauth-protected-resource") {
          return json(res, 200, { resource, authorization_servers: o.oidc ? [o.oidc.issuer] : [], bearer_methods_supported: ["header"] });
        }
        if (path === "/mcp") return await handleMcp(req, res, "agent");
        if (path === "/operator/mcp") return await handleMcp(req, res, "operator");
        return json(res, 404, { error: "not found" });
      } catch (e) {
        const status = (e as { status?: number }).status ?? 500;
        if (!res.headersSent) {
          // An oversized upload is answered at once and the rest is read and discarded (never buffered), so the client sees
          // the 413 instead of a reset connection. A slow sender is cut off after five seconds.
          if (status === 413) {
            req.resume();
            const t = setTimeout(() => req.destroy(), 5000);
            t.unref();
            req.once("close", () => clearTimeout(t));
          }
          json(res, status, { error: status === 500 ? "internal error" : (e as Error).message }, status === 413 ? { Connection: "close" } : {});
        }
        if (status === 500) console.error(e);
      }
    })();
  });

  return {
    server,
    sessions,
    close: async () => {
      clearInterval(reap);
      await Promise.allSettled([...sessions.values()].map((s) => s.transport.close()));
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}
