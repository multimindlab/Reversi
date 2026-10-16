import { randomBytes } from "node:crypto";
import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import {
  KeyRing,
  OidcVerifier,
  can,
  isAgent,
  type ApiKey,
  type Capability,
  type Principal,
  type Role,
  ApprovalError,
  LedgerError,
  RUN_ID_PATTERN,
  Reversi,
  ReversiError,
  SealedScope,
  createBundle,
  keyId,
  renderReport,
  toJsonl,
  type Approvals,
  type Delegations,
  type Mode,
  type Outcome,
  type SigningKey,
} from "@multimindlab/reversi";
import { mountConsole, type ConsoleMode } from "./console.js";
import { ApiError, mountExtras, type ExtraOptions } from "./extras.js";
import { Metrics } from "./metrics.js";

export interface LogEntry {
  ts: string;
  method: string;
  path: string;
  status: number;
  ms: number;
  principal: string | null;
}

export type { ConnectorInfo, RollbackState } from "./extras.js";

export interface AppOptions extends ExtraOptions {
  /** The engine's approver should be `approvals.asApprover()`. */
  reversi: Reversi;
  approvals: Approvals;
  /** Enables delegation endpoints. */
  delegations?: Delegations;
  keys: ApiKey[] | KeyRing;
  oidc?: OidcVerifier;
  /** Enables signed evidence bundles. */
  signing_key?: SigningKey;
  maxBodyBytes?: number;
  /** One call per request, after the response. Default: none. Never receives bodies or credentials. */
  logger?: (e: LogEntry) => void;
  /** Serve /metrics without credentials (otherwise an auditor-or-higher key is required). */
  metrics_public?: boolean;
  /** Signs console session cookies. Random per process by default, so sessions end on restart. */
  session_secret?: string;
  secure_cookies?: boolean;
  /**
   * The operator console. `off` (default) serves nothing. `open` has no login, answers only requests addressed to the
   * loopback interface from the same origin, and acts with a fixed role (default operator, never admin). `login` asks
   * for an API key or OIDC token.
   */
  console?: { mode: ConsoleMode; role?: Role };
  now?: () => number;
}

class HttpError extends Error {
  constructor(
    readonly status: 400 | 401 | 403 | 404 | 409 | 413,
    message: string,
  ) {
    super(message);
  }
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function str(o: Record<string, unknown>, k: string, opts: { optional?: boolean } = {}): string | undefined {
  const v = o[k];
  if (v === undefined && opts.optional) return undefined;
  if (typeof v !== "string" || v.trim() === "") throw new HttpError(400, `\`${k}\` must be a non-empty string`);
  return v;
}

function stepParam(c: Context): number {
  const n = Number(c.req.param("n"));
  if (!Number.isInteger(n) || n < 0) throw new HttpError(400, "step must be a non-negative integer");
  return n;
}

type Env = { Variables: { who: Principal } };

export function createApp(opts: AppOptions): Hono {
  const { reversi, approvals } = opts;
  const ring = opts.keys instanceof KeyRing ? opts.keys : new KeyRing(opts.keys, opts.now);
  const metrics = new Metrics();
  const now = opts.now ?? Date.now;

  const authenticate = async (header: string | undefined): Promise<Principal | null> => {
    const m = /^Bearer (.+)$/.exec(header ?? "");
    return m ? authenticateToken(m[1] as string) : null;
  };
  const authenticateToken = async (token: string): Promise<Principal | null> => {
    const k = ring.authenticate(token);
    if (k) return k;
    // JWTs have two dots; skip the issuer round trip for anything else.
    return opts.oidc && token.split(".").length === 3 ? opts.oidc.authenticate(token) : null;
  };

  const app = new Hono<Env>();

  // Request log and metrics. Route labels use the matched pattern, so ids never create new series.
  app.use("*", async (c, next) => {
    const t0 = performance.now();
    await next();
    const ms = performance.now() - t0;
    const route = c.req.routePath === "/*" ? "unmatched" : c.req.routePath;
    metrics.request(c.req.method, route, c.res.status, ms);
    const who = c.get("who") as Principal | undefined;
    opts.logger?.({ ts: new Date(now()).toISOString(), method: c.req.method, path: c.req.path, status: c.res.status, ms: Math.round(ms * 10) / 10, principal: who?.name ?? null });
  });

  app.get("/healthz", (c) => c.json({ ok: true }));
  app.get("/readyz", (c) => {
    try {
      reversi.runIds();
      const head = reversi.ledger.head();
      return c.json({ ok: true, ledger_head: head, halted: reversi.halted() });
    } catch {
      return c.json({ ok: false }, 503);
    }
  });

  app.get("/metrics", async (c) => {
    if (!opts.metrics_public) {
      const who = await authenticate(c.req.header("authorization"));
      if (!who) return c.json({ error: "missing or invalid API key" }, 401, { "WWW-Authenticate": "Bearer" });
      if (!can(who, "read")) return c.json({ error: "auditor role required" }, 403);
    }
    return c.text(metrics.render({ ledger: reversi.ledger, approvals, halted: reversi.halted(), runs: reversi.runIds().length }), 200, {
      "Content-Type": "text/plain; version=0.0.4",
    });
  });

  // The login form is reachable without credentials: keep its body small.
  app.use("/console/*", bodyLimit({ maxSize: 16_384, onError: (c) => c.text("body too large", 413) }));
  app.use("/v1/*", bodyLimit({ maxSize: opts.maxBodyBytes ?? 1_000_000, onError: (c) => c.json({ error: "body too large" }, 413) }));
  app.use("/v1/*", async (c, next) => {
    const who = await authenticate(c.req.header("authorization"));
    if (!who) return c.json({ error: "missing or invalid API key" }, 401, { "WWW-Authenticate": "Bearer" });
    c.set("who", who);
    await next();
  });

  const need = (c: Context<Env>, cap: Capability) => {
    if (!can(c.get("who"), cap)) {
      const label = { "runs:own": "agent", read: "auditor", approve: "approver", rollback: "operator", halt: "admin" }[cap];
      throw new HttpError(403, `${label} role required`);
    }
  };

  /** Agents may only touch runs they opened; anyone with a read role may see any. */
  const openRun = (c: Context<Env>, id: string, write = false) => {
    let run;
    try {
      run = reversi.openRun(id);
    } catch {
      throw new HttpError(404, `run \`${id}\` not found`);
    }
    const who = c.get("who");
    // Journaling on a run (intents, outcomes) is only ever the opening principal's: a key that also holds a read role
    // must not be able to write into someone else's run.
    if ((write || isAgent(who)) && run.state().actor !== who.name) throw new HttpError(404, `run \`${id}\` not found`);
    return run;
  };

  const body = async (c: Context): Promise<Record<string, unknown>> => {
    let v: unknown;
    try {
      v = await c.req.json();
    } catch {
      throw new HttpError(400, "body must be JSON");
    }
    if (!isObj(v)) throw new HttpError(400, "body must be a JSON object");
    return v;
  };

  const evidenceBundle = (run_id: string | null) => {
    if (!opts.signing_key) throw new HttpError(404, "signed bundles are not enabled on this server");
    const records = run_id ? reversi.ledger.forRun(run_id) : reversi.ledger.records();
    return createBundle({ records, ledger_head: reversi.ledger.head(), run_id, key: opts.signing_key, now: now() });
  };
  const runReport = (run_id: string) => {
    const run = reversi.openRun(run_id);
    return renderReport({ run: run.state(), records: reversi.ledger.forRun(run_id), plan: run.plan(), ledger_head: reversi.ledger.head(), generated_ms: now() });
  };

  // ---- runs ----
  app.post("/v1/runs", async (c) => {
    need(c, "runs:own");
    const who = c.get("who");
    const b = await body(c);
    const run_id = str(b, "run_id", { optional: true });
    if (run_id !== undefined && !RUN_ID_PATTERN.test(run_id)) throw new HttpError(400, "invalid run_id");
    const perms = b.permissions;
    if (!Array.isArray(perms) || perms.some((p) => typeof p !== "string" || !p)) {
      throw new HttpError(400, "`permissions` must be an array of non-empty strings");
    }
    if (who.max_permissions) {
      const extra = (perms as string[]).filter((p) => !who.max_permissions?.includes(p));
      if (extra.length) throw new HttpError(403, `permissions exceed this key's cap: ${extra.join(", ")}`);
    }
    const mode = b.mode ?? "enforce";
    if (mode !== "enforce" && mode !== "observe" && mode !== "advise") throw new HttpError(400, "`mode` must be enforce, observe or advise");
    // Observe and advise mode let violating calls run, so an agent must not be able to pick them for itself.
    if (mode !== "enforce" && !who.allow_observe) {
      throw new HttpError(403, "this credential may not open observe-mode runs (key option `allow_observe`)");
    }
    const run = reversi.startRun({
      run_id,
      actor: who.name,
      scope: SealedScope.seal(perms as string[]),
      mode: mode as Mode,
      tenant: who.tenant,
      reason: str(b, "reason", { optional: true }),
    });
    const s = run.state();
    return c.json({ run_id: run.run_id, mode: s.mode, scope_seal: s.scope.seal }, 201);
  });

  app.get("/v1/runs", (c) => {
    const who = c.get("who");
    const ids = reversi.runIds().filter((id) => !isAgent(who) || reversi.openRun(id).state().actor === who.name);
    return c.json({ runs: ids });
  });

  app.get("/v1/runs/:id", (c) => {
    const run = openRun(c, c.req.param("id"));
    return c.json({ ...run.state(), unresolved: run.unresolved() });
  });

  // ---- agent plane: journal intent, then outcome ----
  app.post("/v1/runs/:id/intents", async (c) => {
    need(c, "runs:own");
    const run = openRun(c, c.req.param("id"), true);
    const b = await body(c);
    const deps = b.depends_on;
    if (deps !== undefined && (!Array.isArray(deps) || deps.some((d) => !Number.isInteger(d) || d < 0))) {
      throw new HttpError(400, "`depends_on` must be an array of step numbers");
    }
    const r = await run.begin({
      tool: str(b, "tool") as string,
      args: b.args,
      reason: str(b, "reason") as string,
      depends_on: deps as number[] | undefined,
    });
    return c.json(r);
  });

  app.post("/v1/runs/:id/steps/:n/outcome", async (c) => {
    need(c, "runs:own");
    const run = openRun(c, c.req.param("id"), true);
    const n = stepParam(c);
    const b = await body(c);
    const status = b.status;
    let outcome: Outcome;
    if (status === "succeeded") outcome = { status, result: b.result };
    else if (status === "failed" || status === "uncertain") {
      outcome = { status, error: typeof b.error === "string" ? b.error : undefined };
    } else throw new HttpError(400, "`status` must be succeeded, failed or uncertain");
    return c.json(run.complete(n, outcome));
  });

  // ---- read plane (auditor and up) ----
  app.get("/v1/runs/:id/plan", (c) => {
    need(c, "read");
    return c.json(openRun(c, c.req.param("id")).plan());
  });

  app.get("/v1/runs/:id/export", (c) => {
    need(c, "read");
    openRun(c, c.req.param("id"));
    return c.body(toJsonl(reversi.ledger.forRun(c.req.param("id"))), 200, { "Content-Type": "application/x-ndjson" });
  });

  app.get("/v1/runs/:id/report", (c) => {
    need(c, "read");
    openRun(c, c.req.param("id"));
    return c.html(runReport(c.req.param("id")));
  });

  app.get("/v1/runs/:id/bundle", (c) => {
    need(c, "read");
    openRun(c, c.req.param("id"));
    return c.json(evidenceBundle(c.req.param("id")));
  });

  app.get("/v1/ledger/bundle", (c) => {
    need(c, "read");
    return c.json(evidenceBundle(null));
  });

  app.get("/v1/ledger/verify", (c) => {
    need(c, "read");
    return c.json(reversi.ledger.verify());
  });

  app.get("/v1/evidence/key", (c) => {
    need(c, "read");
    if (!opts.signing_key) throw new HttpError(404, "signed bundles are not enabled on this server");
    return c.json({ alg: "ed25519", key_id: keyId(opts.signing_key.public_pem), public_key_pem: opts.signing_key.public_pem });
  });

  app.get("/v1/status", (c) => {
    need(c, "read");
    return c.json({ halted: reversi.halted(), environment: reversi.environment, runs: reversi.runIds().length, pending_approvals: approvals.list({ status: "pending" }).length });
  });

  // ---- approvals ----
  app.get("/v1/approvals", (c) => {
    need(c, "read");
    const status = c.req.query("status");
    if (status && !["pending", "approved", "denied", "consumed", "expired"].includes(status)) throw new HttpError(400, "unknown status");
    return c.json({ approvals: approvals.list({ status: status as never, run_id: c.req.query("run_id") }) });
  });

  const identityOf = (p: Principal) => ({ roles: p.roles as string[], groups: p.groups ?? [] });
  for (const decision of ["approve", "deny"] as const) {
    app.post(`/v1/approvals/:id/${decision}`, async (c) => {
      need(c, "approve");
      const b = c.req.header("content-length") === "0" ? {} : await body(c).catch(() => ({}));
      const note = typeof b.note === "string" && b.note.trim() ? b.note : undefined;
      const who = c.get("who");
      try {
        return c.json(
          decision === "approve"
            ? approvals.approve(c.req.param("id"), who.name, note, identityOf(who))
            : approvals.deny(c.req.param("id"), who.name, note, identityOf(who)),
        );
      } catch (e) {
        if (e instanceof ApprovalError) throw new HttpError(/not found/.test(e.message) ? 404 : /needs an approver|cannot decide|already decided/.test(e.message) ? 403 : 409, e.message);
        throw e;
      }
    });
  }

  /** Emergency override of an approval: admin only, with a mandatory reason and evidence reference. */
  app.post("/v1/approvals/:id/break-glass", async (c) => {
    need(c, "halt");
    const b = await body(c);
    const who = c.get("who");
    try {
      return c.json(approvals.breakGlass(c.req.param("id"), who.name, { reason: String(b.reason ?? ""), evidence: String(b.evidence ?? "") }, identityOf(who)));
    } catch (e) {
      if (e instanceof ApprovalError) throw new HttpError(/not found/.test(e.message) ? 404 : /needs the admin/.test(e.message) ? 403 : /needs a (reason|reference)/.test(e.message) ? 400 : 409, e.message);
      throw e;
    }
  });

  // ---- delegation: hand your approval authority to someone for a while ----
  app.get("/v1/delegations", (c) => {
    need(c, "read");
    if (!opts.delegations) throw new HttpError(404, "delegation is not enabled on this server");
    return c.json({ delegations: opts.delegations.list() });
  });
  app.post("/v1/delegations", async (c) => {
    need(c, "approve");
    if (!opts.delegations) throw new HttpError(404, "delegation is not enabled on this server");
    const b = await body(c);
    const who = c.get("who");
    // You delegate your own authority. An admin may delegate on behalf of someone else.
    const from = typeof b.from === "string" && b.from !== who.name ? (can(who, "halt") ? b.from : (() => { throw new HttpError(403, "you can only delegate your own approval authority"); })()) : who.name;
    const hours = Number(b.hours);
    if (!Number.isFinite(hours) || hours <= 0) throw new HttpError(400, "`hours` must be a positive number");
    try {
      return c.json(
        opts.delegations.grant({ from, to: str(b, "to") as string, until_ms: now() + hours * 3_600_000, groups: Array.isArray(b.groups) ? (b.groups as string[]) : undefined, reason: str(b, "reason") as string }),
        201,
      );
    } catch (e) {
      throw new HttpError(400, e instanceof Error ? e.message : "invalid delegation");
    }
  });
  app.delete("/v1/delegations/:id", (c) => {
    need(c, "approve");
    if (!opts.delegations) throw new HttpError(404, "delegation is not enabled on this server");
    const d = opts.delegations.list().find((x) => x.id === c.req.param("id"));
    if (!d) throw new HttpError(404, "delegation not found");
    if (d.from !== c.get("who").name && !can(c.get("who"), "halt")) throw new HttpError(403, "only the delegator or an admin can revoke it");
    opts.delegations.revoke(d.id);
    return c.json({ ok: true });
  });

  /** Pre-approve a tool in a run, for any arguments (counts down per use). */
  app.post("/v1/runs/:id/approvals", async (c) => {
    need(c, "approve");
    const run = openRun(c, c.req.param("id"));
    const b = await body(c);
    const kind = b.kind ?? "call";
    if (kind !== "call" && kind !== "compensation") throw new HttpError(400, "`kind` must be call or compensation");
    const count = b.count ?? 1;
    if (!Number.isInteger(count) || (count as number) < 1 || (count as number) > 100) throw new HttpError(400, "`count` must be 1..100");
    approvals.add(run.run_id, kind, str(b, "tool") as string, count as number, c.get("who").name);
    return c.json({ ok: true }, 201);
  });

  // ---- rollback and reconciliation (operator and up) ----
  app.post("/v1/runs/:id/steps/:n/compensation", async (c) => {
    need(c, "rollback");
    const run = openRun(c, c.req.param("id"));
    return c.json(await run.beginCompensation(stepParam(c), { actor: c.get("who").name }));
  });

  app.post("/v1/runs/:id/steps/:n/compensation/outcome", async (c) => {
    need(c, "rollback");
    const run = openRun(c, c.req.param("id"));
    const b = await body(c);
    if (b.status === "compensated") run.completeCompensation(stepParam(c), { status: "compensated" }, { actor: c.get("who").name });
    else if (b.status === "failed") {
      run.completeCompensation(
        stepParam(c),
        { status: "failed", error: typeof b.error === "string" ? b.error : undefined },
        { actor: c.get("who").name },
      );
    } else throw new HttpError(400, "`status` must be compensated or failed");
    return c.json({ ok: true });
  });

  /** Settle a step whose outcome was unknown, after checking the downstream system. */
  app.post("/v1/runs/:id/steps/:n/resolve", async (c) => {
    need(c, "rollback");
    const run = openRun(c, c.req.param("id"));
    const b = await body(c);
    if (b.status !== "succeeded" && b.status !== "failed") throw new HttpError(400, "`status` must be succeeded or failed");
    const outcome: Outcome = b.status === "succeeded" ? { status: "succeeded", result: b.result } : { status: "failed", error: typeof b.error === "string" ? b.error : undefined };
    return c.json(run.resolve(stepParam(c), outcome, { actor: c.get("who").name, note: str(b, "note") as string }));
  });

  // ---- kill switch (admin) ----
  app.post("/v1/halt", async (c) => {
    need(c, "halt");
    const b = await body(c);
    const scope: Record<string, string> = {};
    for (const k of ["tool", "actor", "tenant", "environment"]) {
      if (b[k] !== undefined) {
        if (typeof b[k] !== "string" || !b[k]) throw new HttpError(400, `\`${k}\` must be a non-empty string`);
        scope[k] = b[k] as string;
      }
    }
    const h = reversi.halt(`${str(b, "reason")} (by ${c.get("who").name})`, scope, c.get("who").name);
    return c.json({ halted: reversi.halted(), halt: h });
  });
  app.get("/v1/halts", (c) => {
    need(c, "read");
    return c.json({ halts: reversi.halts() });
  });
  app.post("/v1/resume", async (c) => {
    need(c, "halt");
    const b = c.req.header("content-length") === "0" || !c.req.header("content-type") ? {} : await body(c).catch(() => ({}));
    const lifted = reversi.resume(typeof b.id === "string" ? b.id : undefined);
    return c.json({ halted: reversi.halted(), lifted });
  });

  const extras = mountExtras(app, { opts, ring, now, need, body, str, identityOf });

  const openRole = opts.console?.role ?? "operator";
  if (opts.console?.mode === "open" && openRole === "admin") throw new Error("the open console never runs as admin: use operator, or log in");
  mountConsole(app as unknown as Hono, {
    reversi,
    approvals,
    authenticate: authenticateToken,
    byFingerprint: (fp) => ring.byFingerprint(fp),
    session_secret: opts.session_secret ?? randomBytes(32).toString("hex"),
    secure_cookies: opts.secure_cookies ?? false,
    session_ttl_ms: 8 * 3600_000,
    signing_available: !!opts.signing_key,
    report: runReport,
    bundle: evidenceBundle,
    now,
    mode: opts.console?.mode ?? "off",
    open_role: openRole,
    opts,
    extras,
    ring,
  });

  app.notFound((c) => c.json({ error: "not found" }, 404));
  app.onError((e, c) => {
    if (e instanceof HttpError || e instanceof ApiError) return c.json({ error: e.message }, e.status);
    if (e instanceof LedgerError) return c.json({ error: "ledger unavailable; request refused" }, 503);
    if (e instanceof ReversiError) return c.json({ error: e.message }, 409);
    if (e instanceof Error && /^invalid run id/.test(e.message)) return c.json({ error: e.message }, 400);
    console.error(e);
    return c.json({ error: "internal error" }, 500);
  });

  return app as unknown as Hono;
}
