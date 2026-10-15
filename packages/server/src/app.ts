import { createHash, timingSafeEqual } from "node:crypto";
import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import {
  LedgerError,
  RUN_ID_PATTERN,
  Reversi,
  ReversiError,
  SealedScope,
  toJsonl,
  type Approver,
  type Mode,
  type Outcome,
} from "@multimindlab/reversi";

export type Role = "agent" | "operator";

export interface ApiKey {
  /** Identifies the caller. For agent keys this is the `actor` recorded in the ledger. */
  name: string;
  role: Role;
  /** Plain key. Prefer `key_sha256` in files you keep around. */
  key?: string;
  /** Lowercase hex SHA-256 of the key. */
  key_sha256?: string;
  /** Agent keys only: the most permissions a run opened with this key may request. Omit for no cap. */
  max_permissions?: string[];
}

export interface AppOptions {
  /** The engine's approver is replaced by the server's grant mechanism; do not pass one in `reversi`. */
  reversi: Reversi;
  keys: ApiKey[];
  grants: Grants;
  maxBodyBytes?: number;
}

/** Operator-issued, single-use approvals. In memory by design: a restart revokes them (fails safe). */
export class Grants {
  private readonly counts = new Map<string, number>();
  private k(run: string, kind: string, tool: string) {
    return JSON.stringify([run, kind, tool]);
  }
  add(run: string, kind: "call" | "compensation", tool: string, count = 1): void {
    const k = this.k(run, kind, tool);
    this.counts.set(k, (this.counts.get(k) ?? 0) + count);
  }
  /** Consume one grant if present. */
  take(run: string, kind: string, tool: string): boolean {
    const k = this.k(run, kind, tool);
    const n = this.counts.get(k) ?? 0;
    if (n <= 0) return false;
    if (n === 1) this.counts.delete(k);
    else this.counts.set(k, n - 1);
    return true;
  }
  asApprover(): Approver {
    return (r) => this.take(r.run_id, r.kind, r.tool);
  }
}

const sha = (s: string) => createHash("sha256").update(s).digest();

interface Principal {
  name: string;
  role: Role;
  max_permissions?: string[];
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

export function createApp(opts: AppOptions): Hono {
  const { reversi, grants } = opts;
  const keys = opts.keys.map((k) => {
    if (!k.key && !k.key_sha256) throw new Error(`key \`${k.name}\` needs \`key\` or \`key_sha256\``);
    return { ...k, digest: k.key_sha256 ? Buffer.from(k.key_sha256, "hex") : sha(k.key as string) };
  });
  for (const k of keys) if (k.digest.length !== 32) throw new Error(`key \`${k.name}\`: key_sha256 must be 64 hex chars`);

  const authenticate = (header: string | undefined): Principal | null => {
    const m = /^Bearer (.+)$/.exec(header ?? "");
    if (!m) return null;
    const d = sha(m[1] as string);
    let found: Principal | null = null;
    for (const k of keys) {
      // Compare every key so timing does not reveal which one matched.
      if (timingSafeEqual(d, k.digest) && !found) found = { name: k.name, role: k.role, max_permissions: k.max_permissions };
    }
    return found;
  };

  const app = new Hono<{ Variables: { who: Principal } }>();

  app.get("/healthz", (c) => c.json({ ok: true }));

  app.use("/v1/*", bodyLimit({ maxSize: opts.maxBodyBytes ?? 1_000_000, onError: (c) => c.json({ error: "body too large" }, 413) }));
  app.use("/v1/*", async (c, next) => {
    const who = authenticate(c.req.header("authorization"));
    if (!who) return c.json({ error: "missing or invalid API key" }, 401, { "WWW-Authenticate": "Bearer" });
    c.set("who", who);
    await next();
  });

  const operatorOnly = (c: Context<{ Variables: { who: Principal } }>) => {
    if (c.get("who").role !== "operator") throw new HttpError(403, "operator key required");
  };

  /** Agents may only touch runs they opened; operators may touch any. */
  const openRun = (c: Context<{ Variables: { who: Principal } }>, id: string) => {
    let run;
    try {
      run = reversi.openRun(id);
    } catch {
      throw new HttpError(404, `run \`${id}\` not found`);
    }
    const who = c.get("who");
    if (who.role === "agent" && run.state().actor !== who.name) throw new HttpError(404, `run \`${id}\` not found`);
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

  // ---- runs ----
  app.post("/v1/runs", async (c) => {
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
    if (mode !== "enforce" && mode !== "observe") throw new HttpError(400, "`mode` must be enforce or observe");
    const run = reversi.startRun({
      run_id,
      actor: who.name,
      scope: SealedScope.seal(perms as string[]),
      mode: mode as Mode,
      reason: str(b, "reason", { optional: true }),
    });
    const s = run.state();
    return c.json({ run_id: run.run_id, mode: s.mode, scope_seal: s.scope.seal }, 201);
  });

  app.get("/v1/runs", (c) => {
    const who = c.get("who");
    const ids = reversi.runIds().filter((id) => who.role === "operator" || reversi.openRun(id).state().actor === who.name);
    return c.json({ runs: ids });
  });

  app.get("/v1/runs/:id", (c) => {
    const run = openRun(c, c.req.param("id"));
    return c.json({ ...run.state(), unresolved: run.unresolved() });
  });

  // ---- agent plane: journal intent, then outcome ----
  app.post("/v1/runs/:id/intents", async (c) => {
    const run = openRun(c, c.req.param("id"));
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
    const run = openRun(c, c.req.param("id"));
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

  // ---- operator plane ----
  app.get("/v1/runs/:id/plan", (c) => {
    operatorOnly(c);
    return c.json(openRun(c, c.req.param("id")).plan());
  });

  app.post("/v1/runs/:id/approvals", async (c) => {
    operatorOnly(c);
    const run = openRun(c, c.req.param("id"));
    const b = await body(c);
    const kind = b.kind ?? "call";
    if (kind !== "call" && kind !== "compensation") throw new HttpError(400, "`kind` must be call or compensation");
    const count = b.count ?? 1;
    if (!Number.isInteger(count) || (count as number) < 1 || (count as number) > 100) throw new HttpError(400, "`count` must be 1..100");
    grants.add(run.run_id, kind, str(b, "tool") as string, count as number);
    return c.json({ ok: true }, 201);
  });

  app.post("/v1/runs/:id/steps/:n/compensation", async (c) => {
    operatorOnly(c);
    const run = openRun(c, c.req.param("id"));
    return c.json(await run.beginCompensation(stepParam(c), { actor: c.get("who").name }));
  });

  app.post("/v1/runs/:id/steps/:n/compensation/outcome", async (c) => {
    operatorOnly(c);
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

  app.get("/v1/runs/:id/export", (c) => {
    operatorOnly(c);
    openRun(c, c.req.param("id"));
    return c.body(toJsonl(reversi.ledger.forRun(c.req.param("id"))), 200, { "Content-Type": "application/x-ndjson" });
  });

  app.get("/v1/ledger/verify", (c) => {
    operatorOnly(c);
    return c.json(reversi.ledger.verify());
  });

  app.notFound((c) => c.json({ error: "not found" }, 404));
  app.onError((e, c) => {
    if (e instanceof HttpError) return c.json({ error: e.message }, e.status);
    if (e instanceof LedgerError) return c.json({ error: "ledger unavailable; request refused" }, 503);
    if (e instanceof ReversiError) return c.json({ error: e.message }, 409);
    if (e instanceof Error && /^invalid run id/.test(e.message)) return c.json({ error: e.message }, 400);
    console.error(e);
    return c.json({ error: "internal error" }, 500);
  });

  return app as unknown as Hono;
}
