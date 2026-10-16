/**
 * The rest of the HTTP API: search, impact, simulation, alerts, holds, retention, anchors, the manifest and policy
 * registries, key management, rollback execution, reports, and the Slack approval callback. Each route needs the engine
 * services to be configured (`engine` in the app options); without them the route answers 404 "not enabled".
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Context, Hono } from "hono";
import { parse as parseYaml } from "yaml";
import {
  ApprovalError,
  ManifestRegistry,
  PolicyVersions,
  anchorLedger,
  applyRetention,
  buildPeriodReport,
  can,
  evaluateAlerts,
  parsePolicy,
  planRetention,
  previewImpact,
  renderPeriodHtml,
  renderPeriodMarkdown,
  renderReportPdf,
  replayRun,
  searchRecords,
  searchRuns,
  simulatePolicy,
  speculate,
  sha256Hex,
  type ApiKey,
  type ArgChange,
  type CompensationCall,
  type EngineHandle,
  type KeyRing,
  type LedgerEvent,
  type McpToolInfo,
  type PlanInput,
  type PolicyDoc,
  type Principal,
  type Role,
  type RunStatus,
  type RollbackReport,
  ROLES,
} from "@multimindlab/reversi";
import type { Capability } from "@multimindlab/reversi";

export interface ConnectorInfo {
  name: string;
  kind: string;
  healthy: boolean;
  tools: number;
  classified: number;
  unclassified: number;
  credential?: "set" | "missing" | "n/a";
  detail?: string;
}

export interface ExtraOptions {
  engine?: EngineHandle;
  registry_dir?: string;
  policy_dir?: string;
  compensator?: (call: CompensationCall) => Promise<void>;
  verifier?: (tool: string, args: Record<string, unknown>) => unknown | Promise<unknown>;
  connectors?: () => Promise<ConnectorInfo[]>;
  /** The tools the upstream MCP server offers right now (the gateway supplies it), for drafting manifests. */
  upstream_tools?: () => Promise<McpToolInfo[]>;
  health?: () => Promise<Array<{ name: string; ok: boolean }>>;
  keys_file?: string;
  slack?: { signing_secret: string; users: Record<string, { name: string; roles?: Role[]; groups?: string[] }> };
}

export class ApiError extends Error {
  constructor(
    readonly status: 400 | 401 | 403 | 404 | 409 | 413,
    message: string,
  ) {
    super(message);
  }
}

export interface ExtraDeps {
  opts: ExtraOptions;
  ring: KeyRing;
  now: () => number;
  need: (c: Context<{ Variables: { who: Principal } }>, cap: Capability) => void;
  body: (c: Context) => Promise<Record<string, unknown>>;
  str: (o: Record<string, unknown>, k: string, opt?: { optional?: boolean }) => string | undefined;
  identityOf: (p: Principal) => { roles: string[]; groups: string[] };
}

type Env = { Variables: { who: Principal } };

const sinceOf = (v: string | undefined, now: number): number | undefined => {
  if (!v) return undefined;
  const m = /^(\d+)(m|h|d)$/.exec(v);
  if (m) return now - Number(m[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "m"];
  const t = Date.parse(v);
  if (!Number.isFinite(t)) throw new ApiError(400, `cannot read "${v}" as a time (use 7d, 12h, 30m or an ISO date)`);
  return t;
};

export interface Extras {
  rollbackStatus: (run: string) => RollbackState | undefined;
  startRollback: (run: string, by: string, o: { approve_compensations?: boolean }) => RollbackState;
  keys: {
    list: () => Array<{ index: number; name: string; roles: string[]; groups: string[]; tenant?: string; expires_at?: string | number; not_before?: string | number; disabled: boolean; allow_observe: boolean; max_permissions?: string[]; fingerprint: string }>;
    enabled: () => boolean;
    create: (o: { name: string; roles: Role[]; groups?: string[]; tenant?: string; max_permissions?: string[]; expires_in_days?: number }) => string;
    disable: (i: number, disabled: boolean) => void;
    remove: (i: number) => void;
  };
}

export function mountExtras(app: Hono<Env>, d: ExtraDeps): Extras {
  const { opts, need, body, str } = d;
  const engine = (): EngineHandle => {
    if (!opts.engine) throw new ApiError(404, "this feature needs the engine services, which are not enabled on this server");
    return opts.engine;
  };
  const rv = () => engine().reversi;

  // ---- search ----
  app.get("/v1/search/runs", (c) => {
    need(c, "read");
    const q = c.req.query();
    return c.json(searchRuns(rv(), { actor: q.actor, tenant: q.tenant, tool: q.tool, status: q.status as RunStatus | undefined, mode: q.mode, since_ms: sinceOf(q.since, d.now()), until_ms: sinceOf(q.until, d.now()), text: q.text, limit: q.limit ? Number(q.limit) : undefined, after: q.after }));
  });
  app.get("/v1/search/records", (c) => {
    need(c, "read");
    const q = c.req.query();
    return c.json(searchRecords(rv(), { run_id: q.run, actor: q.actor, tool: q.tool, event: q.event ? (q.event.split(",") as LedgerEvent[]) : undefined, text: q.text, since_ms: sinceOf(q.since, d.now()), until_ms: sinceOf(q.until, d.now()), limit: q.limit ? Number(q.limit) : undefined, after_seq: q.after_seq ? Number(q.after_seq) : undefined }));
  });

  // ---- reports ----
  app.get("/v1/runs/:id/report.pdf", (c) => {
    need(c, "read");
    const id = c.req.param("id");
    let run;
    try {
      run = rv().openRun(id);
    } catch {
      throw new ApiError(404, `run \`${id}\` not found`);
    }
    const pdf = renderReportPdf({ run: run.state(), records: rv().ledger.forRun(id), plan: run.plan(), ledger_head: rv().ledger.head(), region: engine().egress.region, generated_ms: d.now() });
    return c.body(new Uint8Array(pdf), 200, { "Content-Type": "application/pdf", "Content-Disposition": `inline; filename="reversi-${id}.pdf"` });
  });
  app.get("/v1/report", (c) => {
    need(c, "read");
    const from = sinceOf(c.req.query("since") ?? "7d", d.now()) as number;
    const rep = buildPeriodReport(rv(), engine().approvals, from, d.now());
    const fmt = c.req.query("format") ?? "json";
    if (fmt === "md") return c.text(renderPeriodMarkdown(rep), 200, { "Content-Type": "text/markdown" });
    if (fmt === "html") return c.html(renderPeriodHtml(rep));
    return c.json(rep);
  });

  // ---- impact, simulation, replay, speculation ----
  const policyOf = (text: unknown): PolicyDoc | undefined => {
    if (typeof text !== "string" || !text.trim()) return undefined;
    try {
      return parsePolicy(parseYaml(text));
    } catch (e) {
      throw new ApiError(400, `the policy is not valid: ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  const sandboxCtx = (policyText?: unknown) => ({ registry: rv().registry, policy: policyOf(policyText) ?? rv().policy?.doc, environment: rv().environment });

  app.get("/v1/impact", async (c) => {
    need(c, "read");
    const tool = c.req.query("tool");
    if (!tool) throw new ApiError(400, "`tool` is required");
    let args: unknown;
    if (c.req.query("args")) {
      try {
        args = JSON.parse(c.req.query("args") as string);
      } catch {
        throw new ApiError(400, "`args` must be JSON");
      }
    }
    return c.json(await previewImpact(sandboxCtx(), { tool, args, actor: c.req.query("actor") }));
  });
  app.post("/v1/simulate", async (c) => {
    need(c, "rollback");
    const b = await body(c);
    const cap = engine().capture;
    if (!cap) throw new ApiError(404, "capture is off, so there is no history to simulate against");
    const since = sinceOf(typeof b.since === "string" ? b.since : "7d", d.now());
    const records = cap.list({ run_id: typeof b.run_id === "string" ? b.run_id : undefined, since_ms: b.run_id ? undefined : since });
    return c.json(await simulatePolicy(records, sandboxCtx(b.policy)));
  });
  app.post("/v1/runs/:id/replay", async (c) => {
    need(c, "rollback");
    const b = await body(c);
    const cap = engine().capture;
    if (!cap) throw new ApiError(404, "capture is off, so there is nothing to replay");
    const records = cap.list({ run_id: c.req.param("id") });
    if (!records.length) throw new ApiError(404, "nothing captured for that run");
    const changes = Array.isArray(b.changes) ? (b.changes as ArgChange[]) : [];
    return c.json(await replayRun(records, sandboxCtx(b.policy), changes));
  });
  app.post("/v1/speculate", async (c) => {
    need(c, "read");
    const b = await body(c);
    if (!Array.isArray(b.plans) || !b.plans.length) throw new ApiError(400, "`plans` must be a non-empty list");
    return c.json(await speculate(b.plans as PlanInput[], sandboxCtx(b.policy), { actor: typeof b.actor === "string" ? b.actor : undefined }));
  });

  // ---- alerts ----
  app.get("/v1/alerts", async (c) => {
    need(c, "read");
    const health = opts.health ? await opts.health().catch(() => undefined) : undefined;
    return c.json({ alerts: evaluateAlerts(rv(), engine().approvals, { now: d.now(), health, ...(engine().config.alerts?.denial_spike ? { denial_spike: engine().config.alerts?.denial_spike } : {}) }) });
  });

  // ---- holds and retention ----
  app.get("/v1/holds", (c) => {
    need(c, "read");
    return c.json({ holds: engine().holds.list({ all: c.req.query("all") === "1" }) });
  });
  app.post("/v1/holds", async (c) => {
    need(c, "halt");
    const b = await body(c);
    try {
      return c.json(engine().holds.add({ run_id: str(b, "run_id", { optional: true }), tenant: str(b, "tenant", { optional: true }), actor: str(b, "actor", { optional: true }), tool: str(b, "tool", { optional: true }) }, String(b.reason ?? ""), c.get("who").name), 201);
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(400, e instanceof Error ? e.message : "invalid hold");
    }
  });
  app.delete("/v1/holds/:id", (c) => {
    need(c, "halt");
    if (!engine().holds.release(c.req.param("id"))) throw new ApiError(404, "no active hold with that id");
    return c.json({ ok: true });
  });
  const retentionCfg = () => {
    const doc = rv().policy?.doc.retention;
    if (!doc) throw new ApiError(404, "no retention settings: add a `retention:` section to the policy");
    return doc;
  };
  app.get("/v1/retention/plan", (c) => {
    need(c, "read");
    return c.json({ config: retentionCfg(), runs: planRetention(rv(), retentionCfg(), engine().holds, d.now()) });
  });
  app.post("/v1/retention/apply", async (c) => {
    need(c, "halt");
    const b = await body(c);
    const e = engine();
    return c.json(applyRetention(rv(), retentionCfg(), { holds: e.holds, approvals: e.approvals, capture: e.capture, dry_run: b.dry_run === true, archive_dir: typeof b.archive_dir === "string" ? b.archive_dir : undefined, key: e.signing_key, now: d.now(), actor: c.get("who").name }));
  });

  // ---- anchors ----
  app.post("/v1/anchor", async (c) => {
    need(c, "halt");
    const e = engine();
    const sinks = e.config.anchor?.sinks ?? [];
    if (!sinks.length) throw new ApiError(404, "no anchor sinks are configured");
    const r = await anchorLedger(rv().ledger, sinks, { key: e.signing_key, egress: e.egress });
    return c.json({ anchor: r.anchor, delivered: r.delivered, errors: r.errors }, r.errors.length ? 502 : 200);
  });

  // ---- manifest and policy registries (the API behind `reversi apply`) ----
  const manifestReg = () => {
    if (!opts.registry_dir) throw new ApiError(404, "no manifest registry folder is configured on this server");
    return new ManifestRegistry(opts.registry_dir);
  };
  const policyVer = () => {
    if (!opts.policy_dir) throw new ApiError(404, "no policy versions folder is configured on this server");
    return new PolicyVersions(opts.policy_dir);
  };
  const reloadAfter = async (by: string) => {
    const r = await opts.engine?.reload(by);
    if (r?.error) throw new ApiError(409, `saved, but the new configuration did not load: ${r.error}`);
  };
  app.get("/v1/registry", (c) => {
    need(c, "rollback");
    const reg = manifestReg();
    const manifests = reg.tools().flatMap((t) => {
      const h = reg.history(t);
      const cur = h[h.length - 1];
      return cur ? [{ tool: t, version: cur.version, status: cur.status, checksum: cur.checksum, manifest: reg.get(t, cur.version) }] : [];
    });
    let policy: { version: number | null; checksum: string | null; history: unknown[] } | null = null;
    if (opts.policy_dir) {
      const pv = policyVer();
      const a = pv.activeVersion();
      policy = { version: a, checksum: a === null ? null : (pv.history().find((h) => h.version === a)?.checksum ?? null), history: pv.history() };
    }
    return c.json({ manifests, policy });
  });
  app.post("/v1/registry/manifests", async (c) => {
    const b = await body(c);
    const status = b.status === "draft" ? "draft" : "approved";
    need(c, status === "draft" ? "rollback" : "halt"); // drafts are the operator's; making something enforceable is the admin's
    try {
      const r = manifestReg().publish(b.manifest, { by: c.get("who").name, note: typeof b.note === "string" ? b.note : undefined, status, key: opts.engine?.signing_key });
      if (status === "approved") await reloadAfter(c.get("who").name);
      return c.json(r, 201);
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(400, e instanceof Error ? e.message : "invalid manifest");
    }
  });
  app.post("/v1/registry/manifests/:tool/approve", async (c) => {
    need(c, "halt");
    const b = c.req.header("content-length") === "0" ? {} : await body(c).catch(() => ({}));
    try {
      const r = manifestReg().approve(c.req.param("tool"), { by: c.get("who").name, version: typeof b.version === "number" ? b.version : undefined, key: opts.engine?.signing_key, require_other: b.four_eyes === true });
      await reloadAfter(c.get("who").name);
      return c.json(r);
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(400, e instanceof Error ? e.message : "cannot approve");
    }
  });
  app.post("/v1/registry/manifests/:tool/deprecate", async (c) => {
    need(c, "halt");
    const b = c.req.header("content-length") === "0" ? {} : await body(c).catch(() => ({}));
    try {
      const r = manifestReg().deprecate(c.req.param("tool"), { by: c.get("who").name, replaced_by: typeof b.replaced_by === "string" ? b.replaced_by : undefined, key: opts.engine?.signing_key });
      await reloadAfter(c.get("who").name);
      return c.json(r);
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(400, e instanceof Error ? e.message : "cannot deprecate");
    }
  });
  app.post("/v1/registry/policy", async (c) => {
    need(c, "halt");
    const b = await body(c);
    try {
      const v = policyVer().publish(String(b.text ?? ""), { by: c.get("who").name, note: typeof b.note === "string" ? b.note : undefined, activate: b.activate !== false });
      if (b.activate !== false) await reloadAfter(c.get("who").name);
      return c.json(v, 201);
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(400, e instanceof Error ? e.message : "invalid policy");
    }
  });
  app.post("/v1/registry/policy/:version/activate", async (c) => {
    need(c, "halt");
    try {
      policyVer().activate(Number(c.req.param("version")));
      await reloadAfter(c.get("who").name);
      return c.json({ active: Number(c.req.param("version")) });
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(400, e instanceof Error ? e.message : "cannot activate");
    }
  });
  app.post("/v1/reload", async (c) => {
    need(c, "halt");
    return c.json(await engine().reload(c.get("who").name));
  });

  // ---- API key management ----
  const readKeys = (): ApiKey[] => {
    if (!opts.keys_file) throw new ApiError(404, "key management needs REVERSI_KEYS to point at a writable file");
    return JSON.parse(readFileSync(opts.keys_file, "utf8")) as ApiKey[];
  };
  const writeKeys = (keys: ApiKey[]) => {
    const f = opts.keys_file as string;
    mkdirSync(dirname(f), { recursive: true });
    const tmp = `${f}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(keys, null, 2), { mode: 0o600 });
    renameSync(tmp, f);
    d.ring.replace(keys);
  };
  app.get("/v1/keys", (c) => {
    need(c, "halt");
    return c.json({
      keys: readKeys().map((k, i) => ({ index: i, name: k.name, roles: k.roles ?? (k.role ? [k.role] : []), groups: k.groups ?? [], tenant: k.tenant, expires_at: k.expires_at, not_before: k.not_before, disabled: k.disabled === true, allow_observe: k.allow_observe === true, max_permissions: k.max_permissions, fingerprint: (k.key_sha256 ?? sha256Hex(k.key ?? "")).slice(0, 12) })),
    });
  });
  app.post("/v1/keys", async (c) => {
    need(c, "halt");
    const b = await body(c);
    const name = str(b, "name") as string;
    const roles = (Array.isArray(b.roles) ? b.roles : [b.role]).filter((r): r is Role => ROLES.includes(r as Role));
    if (roles.length === 0) throw new ApiError(400, `\`role\` must be one of ${ROLES.join(", ")}`);
    const days = b.expires_in_days === undefined ? undefined : Number(b.expires_in_days);
    if (days !== undefined && (!Number.isFinite(days) || days <= 0)) throw new ApiError(400, "`expires_in_days` must be positive");
    const secret = `rv_${randomBytes(24).toString("hex")}`;
    const entry: ApiKey = { name, roles, key_sha256: sha256Hex(secret), ...(Array.isArray(b.groups) ? { groups: b.groups as string[] } : {}), ...(typeof b.tenant === "string" ? { tenant: b.tenant } : {}), ...(Array.isArray(b.max_permissions) ? { max_permissions: b.max_permissions as string[] } : {}), ...(days ? { expires_at: new Date(d.now() + days * 86_400_000).toISOString() } : {}) };
    // the ring hashes plain keys with plain SHA-256: key_sha256 above is the same digest
    writeKeys([...readKeys(), entry]);
    return c.json({ name, roles, key: secret, note: "this is the only time the key is shown" }, 201);
  });
  app.patch("/v1/keys/:index", async (c) => {
    need(c, "halt");
    const b = await body(c);
    const keys = readKeys();
    const k = keys[Number(c.req.param("index"))];
    if (!k) throw new ApiError(404, "no such key");
    if (typeof b.disabled === "boolean") k.disabled = b.disabled;
    if (b.expires_at === null) delete k.expires_at;
    else if (typeof b.expires_at === "string") k.expires_at = b.expires_at;
    writeKeys(keys);
    return c.json({ ok: true });
  });
  app.delete("/v1/keys/:index", (c) => {
    need(c, "halt");
    const keys = readKeys();
    const i = Number(c.req.param("index"));
    if (!keys[i]) throw new ApiError(404, "no such key");
    keys.splice(i, 1);
    writeKeys(keys);
    return c.json({ ok: true });
  });

  // ---- connectors ----
  app.get("/v1/connectors", async (c) => {
    need(c, "read");
    return c.json({ connectors: opts.connectors ? await opts.connectors() : [] });
  });

  // ---- rollback execution, with progress ----
  const jobs = new Map<string, RollbackState>();
  const startRollback = (id: string, by: string, o: { approve_compensations?: boolean }): RollbackState => {
    if (!opts.compensator) throw new ApiError(404, "this server has no compensator configured (REVERSI_COMPENSATOR_CMD), so it cannot run rollbacks itself");
    if (jobs.get(id)?.running) throw new ApiError(409, `a rollback of run ${id} is already running`);
    let run;
    try {
      run = rv().openRun(id);
    } catch {
      throw new ApiError(404, `run \`${id}\` not found`);
    }
    if (o.approve_compensations) for (const a of run.plan().actions) if (a.kind === "compensate" && a.needs_approval && a.compensation_tool) engine().approvals.add(id, "compensation", a.compensation_tool, 1, by);
    const job: RollbackState = { run_id: id, running: true, started_ms: d.now(), by };
    jobs.set(id, job);
    void run
      .rollback({ actor: by, retry: { attempts: 3 }, compensate: opts.compensator, verifier: opts.verifier })
      .then((r) => {
        job.report = r;
      })
      .catch((e) => {
        job.error = e instanceof Error ? e.message : String(e);
      })
      .finally(() => {
        job.running = false;
        job.finished_ms = d.now();
      });
    return job;
  };
  app.post("/v1/runs/:id/rollback", async (c) => {
    need(c, "rollback");
    const b = c.req.header("content-length") === "0" ? {} : await body(c).catch(() => ({}));
    const id = c.req.param("id");
    if (b.confirm !== true) {
      let run;
      try {
        run = rv().openRun(id);
      } catch {
        throw new ApiError(404, `run \`${id}\` not found`);
      }
      return c.json({ dry_run: true, plan: run.plan(), executable: !!opts.compensator });
    }
    return c.json(startRollback(id, c.get("who").name, { approve_compensations: b.approve_compensations === true }), 202);
  });
  app.get("/v1/runs/:id/rollback", (c) => {
    need(c, "read");
    const j = jobs.get(c.req.param("id"));
    if (!j) throw new ApiError(404, "no rollback has been started for that run by this server");
    return c.json(j);
  });

  // ---- Slack: approve or deny from the notification's buttons ----
  app.post("/integrations/slack/actions", async (c) => {
    const slack = opts.slack;
    if (!slack) throw new ApiError(404, "Slack approvals are not enabled");
    const raw = await c.req.text();
    const ts = c.req.header("x-slack-request-timestamp") ?? "";
    const sig = c.req.header("x-slack-signature") ?? "";
    if (!/^\d+$/.test(ts) || Math.abs(d.now() / 1000 - Number(ts)) > 300) throw new ApiError(401, "stale or missing timestamp");
    const want = `v0=${createHmac("sha256", slack.signing_secret).update(`v0:${ts}:${raw}`).digest("hex")}`;
    if (sig.length !== want.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(want))) throw new ApiError(401, "bad signature");
    let payload: { user?: { id?: string }; actions?: Array<{ action_id?: string; value?: string }> };
    try {
      payload = JSON.parse(new URLSearchParams(raw).get("payload") ?? "{}");
    } catch {
      throw new ApiError(400, "unreadable payload");
    }
    const person = slack.users[payload.user?.id ?? ""];
    if (!person) return c.json({ response_type: "ephemeral", text: "You are not set up as an approver in Reversi." });
    const act = payload.actions?.[0];
    if (!act?.value || (act.action_id !== "reversi_approve" && act.action_id !== "reversi_deny")) return c.json({ response_type: "ephemeral", text: "Unknown action." });
    const who = { roles: (person.roles ?? ["approver"]) as string[], groups: person.groups ?? [] };
    // Same rule as the HTTP API: deciding needs the approver role or higher, whatever the request's routing says.
    if (!can({ roles: who.roles.filter((r): r is Role => ROLES.includes(r as Role)) } as Principal, "approve")) return c.json({ response_type: "ephemeral", text: "You are not set up as an approver in Reversi." });
    try {
      const rec = act.action_id === "reversi_approve" ? engine().approvals.approve(act.value, person.name, "from Slack", who) : engine().approvals.deny(act.value, person.name, "from Slack", who);
      return c.json({ response_type: "in_channel", replace_original: false, text: `${rec.status === "pending" ? "Recorded your approval; more are needed" : rec.status} by ${person.name}.` });
    } catch (e) {
      return c.json({ response_type: "ephemeral", text: e instanceof ApprovalError ? e.message : "Could not record that." });
    }
  });

  const keysApi = {
    list: () =>
      readKeys().map((k, i) => ({ index: i, name: k.name, roles: k.roles ?? (k.role ? [k.role] : []), groups: k.groups ?? [], tenant: k.tenant, expires_at: k.expires_at, not_before: k.not_before, disabled: k.disabled === true, allow_observe: k.allow_observe === true, max_permissions: k.max_permissions, fingerprint: (k.key_sha256 ?? sha256Hex(k.key ?? "")).slice(0, 12) })),
    enabled: () => !!opts.keys_file,
    create: (o: { name: string; roles: Role[]; groups?: string[]; tenant?: string; max_permissions?: string[]; expires_in_days?: number }) => {
      const secret = `rv_${randomBytes(24).toString("hex")}`;
      const entry: ApiKey = { name: o.name, roles: o.roles, key_sha256: sha256Hex(secret), ...(o.groups?.length ? { groups: o.groups } : {}), ...(o.tenant ? { tenant: o.tenant } : {}), ...(o.max_permissions?.length ? { max_permissions: o.max_permissions } : {}), ...(o.expires_in_days ? { expires_at: new Date(d.now() + o.expires_in_days * 86_400_000).toISOString() } : {}) };
      writeKeys([...readKeys(), entry]);
      return secret;
    },
    disable: (i: number, disabled: boolean) => {
      const keys = readKeys();
      if (!keys[i]) throw new ApiError(404, "no such key");
      (keys[i] as ApiKey).disabled = disabled;
      writeKeys(keys);
    },
    remove: (i: number) => {
      const keys = readKeys();
      if (!keys[i]) throw new ApiError(404, "no such key");
      keys.splice(i, 1);
      writeKeys(keys);
    },
  };
  return { rollbackStatus: (run) => jobs.get(run), startRollback, keys: keysApi };
}

export interface RollbackState {
  run_id: string;
  running: boolean;
  started_ms: number;
  finished_ms?: number;
  by: string;
  report?: RollbackReport;
  error?: string;
}

