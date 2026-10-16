/**
 * The MCP gateway core. One Gateway serves many sessions. Each agent session is one Reversi run:
 * `tools/list` shows the upstream tools plus a few read-only `reversi.*` tools, and every
 * `tools/call` goes through the engine (manifest, scope, policy, content checks, approval, journal)
 * before and after being forwarded. The upstream result is returned unchanged.
 *
 * Operator sessions (separate endpoint, separate credentials) get a different tool set: decide
 * approvals, execute rollbacks through the upstreams, export evidence, flip the kill switch. An
 * agent can never reach these: they are not on its endpoint.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  SealedScope,
  banner,
  can,
  classifyTools,
  createBundle,
  globAny,
  hintsOf,
  previewImpact,
  schemaHash,
  searchRecords,
  searchRuns,
  suggestManifests,
  validateManifest,
  type McpToolInfo,
  type ToolManifest,
  type Approvals,
  type Capability,
  type Outcome,
  type Principal,
  type Reversi,
  type Run,
  type SigningKey,
  toJsonl,
} from "@multimindlab/reversi";
import { validateSchema } from "./schema.js";
import { UnknownToolError, type UpstreamPool } from "./upstream.js";

export const REASON_META_KEY = "reversi/reason";
export const IDEMPOTENCY_META_KEY = "reversi/idempotency_key";

export interface GatewayOptions {
  reversi: Reversi;
  approvals: Approvals;
  pool: UpstreamPool;
  mode: "observe" | "enforce" | "advise";
  /** What to do with a tool that has no manifest but whose server says it only reads. `observe` lets it run and journals it as unclassified; `block` (default) treats it like any unclassified tool. */
  unclassified_reads?: "block" | "observe";
  /** Check arguments and results against the upstream tool's declared schemas. Default true. */
  validate_schemas?: boolean;
  /** Re-reads manifests and policy (the engine's reload); used by the operator tool and the hot reload. */
  reload?: (by: string) => Promise<{ changed: boolean; tools: number; error?: string }>;
  /** Capture store, for the simulate tool. */
  capture?: import("@multimindlab/reversi").CaptureStore;
  environment?: string;
  /** Permissions for each session's scope. Default: every permission named in the manifests. */
  permissions?: string[];
  /** Hide tools from `tools/list` that the allow/deny lists forbid. */
  allow?: string[];
  deny?: string[];
  signing_key?: SigningKey;
}

/** The value compensation arguments (`$result.*`) are resolved from. */
export function resultForHandle(result: object): unknown {
  const r = result as { structuredContent?: unknown; content?: unknown };
  if (r.structuredContent !== undefined) return r.structuredContent;
  const parts = Array.isArray(r.content) ? r.content : [];
  const only = parts.length === 1 ? (parts[0] as { type?: string; text?: unknown }) : undefined;
  if (only?.type === "text" && typeof only.text === "string") {
    try {
      return JSON.parse(only.text);
    } catch {
      /* not JSON: fall through */
    }
  }
  return result;
}

/** Errors that say the call was refused are failures; anything else may have taken effect. */
function outcomeForError(e: unknown, _manifest?: ToolManifest): Outcome {
  const error = e instanceof Error ? e.message : String(e);
  if (e instanceof UnknownToolError) return { status: "failed", error }; // never reached any upstream
  const refused = e instanceof McpError && (e.code === ErrorCode.InvalidParams || e.code === ErrorCode.MethodNotFound);
  return refused ? { status: "failed", error } : { status: "uncertain", error };
}

const text = (v: unknown): string => (typeof v === "string" ? v : JSON.stringify(v, null, 2));
const ok = (v: unknown): CallToolResult => ({
  content: [{ type: "text", text: text(v) }],
  ...(typeof v === "object" && v !== null && !Array.isArray(v) ? { structuredContent: v as Record<string, unknown> } : {}),
});
const fail = (msg: string, extra?: Record<string, unknown>): CallToolResult => ({
  isError: true,
  content: [{ type: "text", text: msg }],
  ...(extra ? { structuredContent: extra } : {}),
});

const obj = (extra: Record<string, object> = {}, required: string[] = []): Tool["inputSchema"] => ({ type: "object", properties: extra, required, additionalProperties: false } as Tool["inputSchema"]);
const RUN_ID = { run_id: { type: "string", description: "Run id" } };

interface ReversiTool {
  name: string;
  description: string;
  inputSchema: Tool["inputSchema"];
  cap: Capability;
  run: (a: Record<string, unknown>, ctx: Ctx) => Promise<CallToolResult> | CallToolResult;
}
interface Ctx {
  who: Principal;
  own_only: boolean;
}

export class Gateway {
  /** Runs being rolled back right now by this process: two concurrent rollbacks would run each compensation twice. */
  private readonly rollingBack = new Set<string>();
  private cache: { at: number; tools: Tool[] } | null = null;
  constructor(readonly o: GatewayOptions) {}

  private visible(name: string): boolean {
    const { allow = [], deny = [] } = this.o;
    return (allow.length === 0 || globAny(allow, name)) && !(deny.length > 0 && globAny(deny, name));
  }

  /**
   * The run for a new agent session. An agent that reconnects (a new process, a dropped connection) can name its
   * run to continue it, so approvals and the rollback plan stay together. Only the principal that opened a run
   * may continue it, and it keeps the mode and scope it was opened with.
   */
  private runFor(principal: Principal, run_id: string | undefined): Run {
    const rv = this.o.reversi;
    if (run_id) {
      let existing: Run | null = null;
      try {
        existing = rv.openRun(run_id);
      } catch {
        existing = null;
      }
      if (existing) {
        if (existing.state().actor !== principal.name) throw new Error(`run \`${run_id}\` belongs to another principal`);
        return existing;
      }
    }
    return rv.startRun({
      run_id,
      actor: principal.name,
      scope: SealedScope.seal(this.scopeFor(principal)),
      mode: this.o.mode,
      reason: "MCP gateway session",
    });
  }

  /** Server-claimed read-only tools without a manifest run in a shadow observe-mode run, so they are journaled and never block. */
  private readRunFor(principal: Principal, main: Run): Run {
    const id = `${main.run_id}-reads`;
    const existing = (() => {
      try {
        return this.o.reversi.openRun(id);
      } catch {
        return null;
      }
    })();
    return (
      existing ??
      this.o.reversi.startRun({ run_id: id, actor: principal.name, scope: SealedScope.seal(this.scopeFor(principal)), mode: "observe", reason: `unclassified reads of ${main.run_id}` })
    );
  }

  private scopeFor(p: Principal): string[] {
    const all = this.o.permissions ?? [...new Set(this.o.reversi.registry.list().map((m) => m.permission))];
    return p.max_permissions ? all.filter((x) => p.max_permissions?.includes(x)) : all;
  }

  // ---- reversi.* tools ----
  private tools(): ReversiTool[] {
    const rv = this.o.reversi;
    const approvals = this.o.approvals;
    const runFor = (a: Record<string, unknown>, ctx: Ctx) => {
      const id = typeof a.run_id === "string" ? a.run_id : "";
      let run: Run;
      try {
        run = rv.openRun(id);
      } catch {
        throw new Error(`run \`${id}\` not found`);
      }
      if (ctx.own_only && run.state().actor !== ctx.who.name) throw new Error(`run \`${id}\` not found`);
      return run;
    };
    const read = { cap: "read" as Capability };
    return [
      { name: "reversi.list_runs", description: "List run ids (your own runs for agents).", inputSchema: obj(), ...read, run: (_a, ctx) => ok({ runs: rv.runIds().filter((id) => !ctx.own_only || rv.openRun(id).state().actor === ctx.who.name) }) },
      { name: "reversi.get_run", description: "State of a run: steps, statuses, unresolved steps.", inputSchema: obj(RUN_ID, ["run_id"]), ...read, run: (a, ctx) => { const r = runFor(a, ctx); return ok({ ...r.state(), unresolved: r.unresolved() }); } },
      { name: "reversi.get_action_trace", description: "The ledger records of a run (hashes, never arguments).", inputSchema: obj(RUN_ID, ["run_id"]), ...read, run: (a, ctx) => ok({ records: rv.ledger.forRun(runFor(a, ctx).run_id) }) },
      { name: "reversi.plan_rollback", description: "What a rollback of this run would do. Executes nothing.", inputSchema: obj(RUN_ID, ["run_id"]), ...read, run: (a, ctx) => ok(runFor(a, ctx).plan()) },
      { name: "reversi.dry_run_rollback", description: "Alias of plan_rollback: a rollback dry run.", inputSchema: obj(RUN_ID, ["run_id"]), ...read, run: (a, ctx) => ok(runFor(a, ctx).plan()) },
      {
        name: "reversi.validate_manifest",
        description: "Validate a tool manifest object.",
        inputSchema: obj({ manifest: { type: "object" } }, ["manifest"]),
        ...read,
        run: (a) => {
          const r = validateManifest(a.manifest);
          return r.ok ? ok({ valid: true, manifest: r.manifest }) : ok({ valid: false, errors: r.errors });
        },
      },
      {
        name: "reversi.preview_impact",
        description: "Before calling a tool: would the call be allowed, need approval or be blocked, and could it be undone? Executes nothing.",
        inputSchema: obj({ tool: { type: "string" }, arguments: { type: "object" } }, ["tool"]),
        ...read,
        run: async (a, ctx) => ok(await previewImpact({ registry: rv.registry, policy: rv.policy?.doc, environment: this.o.environment }, { tool: String(a.tool), args: a.arguments, actor: ctx.who.name, tenant: ctx.who.tenant })),
      },
      {
        name: "reversi.suggest_manifest",
        description: "Draft manifests for upstream tools that have none, from their names, schemas and annotations. A draft needs a person's approval before it is enforced.",
        inputSchema: obj(),
        ...read,
        run: async () => {
          const r = suggestManifests(await this.toolInfos(), { server: "upstream", existing: rv.registry });
          return ok({ suggestions: r.suggestions.map((x) => ({ manifest: x.manifest, confidence: x.confidence, notes: x.notes })), skipped: r.skipped });
        },
      },
      {
        name: "reversi.classification",
        description: "Which upstream tools are classified by a manifest and which are not.",
        inputSchema: obj(),
        ...read,
        run: async () => ok(await this.classification()),
      },
      {
        name: "reversi.search",
        description: "Find runs by actor, tool, status or time, or ledger records by event.",
        inputSchema: obj({ what: { type: "string", enum: ["runs", "records"] }, actor: { type: "string" }, tool: { type: "string" }, status: { type: "string" }, text: { type: "string" }, limit: { type: "number" } }),
        ...read,
        run: (a, ctx) => {
          const limit = typeof a.limit === "number" ? Math.min(a.limit, 200) : 50;
          const actor = ctx.own_only ? ctx.who.name : typeof a.actor === "string" ? a.actor : undefined;
          if (a.what === "records") return ok(searchRecords(rv, { actor, tool: typeof a.tool === "string" ? a.tool : undefined, text: typeof a.text === "string" ? a.text : undefined, limit }));
          return ok(searchRuns(rv, { actor, tool: typeof a.tool === "string" ? a.tool : undefined, status: a.status as never, text: typeof a.text === "string" ? a.text : undefined, limit }));
        },
      },
      // ---- operator only (never listed on the agent endpoint) ----
      {
        name: "reversi.reload",
        description: "Re-read manifests and policy now. A configuration that fails to load is rejected and the old one stays.",
        inputSchema: obj(),
        cap: "halt",
        run: async (_a, ctx) => (this.o.reload ? ok(await this.o.reload(ctx.who.name)) : fail("this gateway has no reloadable configuration")),
      },
      { name: "reversi.list_approvals", description: "Approval requests, optionally by status.", inputSchema: obj({ status: { type: "string", enum: ["pending", "approved", "denied", "consumed", "expired"] } }), ...read, run: (a) => ok({ approvals: approvals.list({ status: a.status as never }) }) },
      {
        name: "reversi.approve_action",
        description: "Approve a pending request. The agent must retry the call afterwards.",
        inputSchema: obj({ id: { type: "string" }, note: { type: "string" } }, ["id"]),
        cap: "approve",
        run: (a, ctx) => ok(approvals.approve(String(a.id), ctx.who.name, typeof a.note === "string" ? a.note : undefined)),
      },
      {
        name: "reversi.deny_action",
        description: "Deny a pending request.",
        inputSchema: obj({ id: { type: "string" }, note: { type: "string" } }, ["id"]),
        cap: "approve",
        run: (a, ctx) => ok(approvals.deny(String(a.id), ctx.who.name, typeof a.note === "string" ? a.note : undefined)),
      },
      {
        name: "reversi.execute_rollback",
        description: "Undo a run by calling each compensation on its upstream, newest first. Without confirm=true this is only a dry run.",
        inputSchema: obj({ ...RUN_ID, confirm: { type: "boolean" }, approve_compensations: { type: "boolean", description: "Also approve compensations that require approval." } }, ["run_id"]),
        cap: "rollback",
        run: async (a, ctx) => {
          const run = runFor(a, ctx);
          const plan = run.plan();
          if (a.confirm !== true) return ok({ dry_run: true, plan });
          if (this.rollingBack.has(run.run_id)) return fail(`a rollback of run ${run.run_id} is already in progress`);
          this.rollingBack.add(run.run_id);
          try {
          if (a.approve_compensations === true) {
            for (const act of plan.actions) if (act.kind === "compensate" && act.needs_approval && act.compensation_tool) approvals.add(run.run_id, "compensation", act.compensation_tool, 1, ctx.who.name);
          }
          const report = await run.rollback({
            actor: ctx.who.name,
            verifier: async (tool, vargs) => {
              const r = await this.o.pool.call(tool, vargs);
              if (r.isError) throw new Error(`read-back ${tool} returned an error`);
              return resultForHandle(r);
            },
            retry: { attempts: 3, base_ms: 250 },
            compensate: async (call) => {
              const r = await this.o.pool.call(call.tool, call.args, { [IDEMPOTENCY_META_KEY]: call.idempotency_key, "reversi/run_id": call.run_id, "reversi/step": call.step });
              if (r.isError) throw new Error(`compensation ${call.tool} returned an error: ${text(r.content).slice(0, 200)}`);
            },
          });
          return ok({ dry_run: false, report });
          } finally {
            this.rollingBack.delete(run.run_id);
          }
        },
      },
      {
        name: "reversi.export_evidence",
        description: "Ledger records for a run (or all), as a signed bundle when the gateway has a signing key.",
        inputSchema: obj({ run_id: { type: "string" } }),
        ...read,
        run: (a, ctx) => {
          const id = typeof a.run_id === "string" ? runFor(a, ctx).run_id : null;
          const records = id ? rv.ledger.forRun(id) : rv.ledger.records();
          if (!this.o.signing_key) return ok({ signed: false, jsonl: toJsonl(records) });
          return ok({ signed: true, bundle: createBundle({ records, ledger_head: rv.ledger.head(), run_id: id, key: this.o.signing_key }) });
        },
      },
      { name: "reversi.halt", description: "Kill switch: block all new calls.", inputSchema: obj({ reason: { type: "string" } }, ["reason"]), cap: "halt", run: (a, ctx) => { rv.halt(`${String(a.reason)} (by ${ctx.who.name})`); return ok({ halted: rv.halted() }); } },
      { name: "reversi.resume", description: "Lift the kill switch.", inputSchema: obj(), cap: "halt", run: () => { rv.resume(); return ok({ halted: rv.halted() }); } },
    ];
  }

  private static readonly AGENT_TOOLS = new Set(["reversi.list_runs", "reversi.get_run", "reversi.get_action_trace", "reversi.plan_rollback", "reversi.dry_run_rollback", "reversi.validate_manifest", "reversi.preview_impact", "reversi.search"]);

  private async upstreamTools(): Promise<Tool[]> {
    if (this.cache && Date.now() - this.cache.at < 5_000) return this.cache.tools;
    const tools = (await this.o.pool.listTools()).filter((t) => this.visible(t.name));
    this.cache = { at: Date.now(), tools };
    return tools;
  }

  /** What the upstream says about each tool, as MCP tool info (annotations, schemas). */
  async toolInfos(): Promise<McpToolInfo[]> {
    return (await this.upstreamTools()) as unknown as McpToolInfo[];
  }

  /** Every tool the upstreams offer, classified against the manifests, with the startup banner text. */
  async classification(): Promise<{ rows: ReturnType<typeof classifyTools>; banner: string }> {
    const rows = classifyTools(this.o.reversi.registry, await this.toolInfos());
    const unclassified = rows.filter((r) => r.class !== "classified").length;
    const next = unclassified
      ? this.o.mode === "enforce"
        ? `${unclassified} tools have no manifest and are blocked. Draft them with: reversi suggest-manifest, review, then reversi manifests publish.`
        : `${unclassified} tools have no manifest. They run (nothing is blocked) and are journaled as unclassified. Draft manifests with: reversi suggest-manifest.`
      : undefined;
    return { rows, banner: banner(rows, { mode: this.o.mode, next }) };
  }

  /** One row per upstream for the console: health, how many of its tools have manifests. */
  async connectors(): Promise<Array<{ name: string; kind: string; healthy: boolean; tools: number; classified: number; unclassified: number; credential: "set" | "missing" | "n/a"; detail?: string }>> {
    const status = await this.o.pool.status();
    await this.upstreamTools().catch(() => undefined);
    const owners = this.o.pool.owners();
    return this.o.pool.entries.map((e) => {
      const mine = [...owners].filter(([, up]) => up === e.name).map(([tool]) => tool);
      const classified = mine.filter((t) => this.o.reversi.registry.get(t)).length;
      return { name: e.name, kind: e.kind, healthy: status.find((x) => x.name === e.name)?.ok ?? false, tools: mine.length, classified, unclassified: mine.length - classified, credential: "n/a" as const };
    });
  }

  /** Call the upstream, with the manifest's timeout, and its retries only when repeating the call is safe (reads and idempotent tools). */
  private async forward(name: string, args: Record<string, unknown> | undefined, manifest: ToolManifest | undefined): Promise<CallToolResult> {
    const safe = manifest?.effect === "read_only" || manifest?.effect === "idempotent";
    const attempts = safe ? Math.max(1, manifest?.retry?.attempts ?? 1) : 1;
    let last: unknown;
    for (let i = 0; i < attempts; i++) {
      try {
        const call = this.o.pool.call(name, args);
        if (!manifest?.timeout_ms) return await call;
        let timer: NodeJS.Timeout | undefined;
        const timeout = new Promise<never>((_r, rej) => {
          timer = setTimeout(() => rej(new Error(`upstream did not answer within ${manifest.timeout_ms} ms`)), manifest.timeout_ms);
        });
        try {
          return await Promise.race([call, timeout]);
        } finally {
          clearTimeout(timer);
          call.catch(() => undefined);
        }
      } catch (e) {
        last = e;
        if (e instanceof UnknownToolError) throw e;
        if (i + 1 < attempts) await new Promise((r) => setTimeout(r, Math.min(manifest?.retry?.max_ms ?? 5000, (manifest?.retry?.base_ms ?? 200) * 2 ** i)));
      }
    }
    throw last;
  }

  /**
   * A new MCP session. `operator: false` is the agent endpoint: one run, upstream tools, read-only
   * reversi tools. `operator: true` exposes only the operator tools, limited by the principal's roles.
   */
  createSession(opts: { principal: Principal; operator: boolean; run_id?: string }): { server: Server; run: Run | null } {
    const { principal } = opts;
    const server = new Server({ name: "reversi-gateway", version: "0.1.0" }, { capabilities: { tools: {} } });
    const rtools = this.tools().filter((t) => (opts.operator ? can(principal, t.cap) : Gateway.AGENT_TOOLS.has(t.name)));
    let readRun: Run | undefined;
    const ctx: Ctx = { who: principal, own_only: !opts.operator };
    const run = opts.operator ? null : this.runFor(principal, opts.run_id);

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [...(opts.operator ? [] : await this.upstreamTools()), ...rtools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema }))],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (req) => {
      const { name, arguments: args, _meta } = req.params;

      const rt = rtools.find((t) => t.name === name);
      if (rt) {
        try {
          return await rt.run(args ?? {}, ctx);
        } catch (e) {
          return fail(e instanceof Error ? e.message : String(e));
        }
      }
      if (name.startsWith("reversi.") || run === null) throw new McpError(ErrorCode.InvalidParams, `unknown tool \`${name}\``);

      const metaReason = _meta?.[REASON_META_KEY];
      const reason = typeof metaReason === "string" && metaReason.trim() ? metaReason : `MCP tools/call ${name}`;

      const infos = await this.toolInfos().catch(() => [] as McpToolInfo[]);
      const info = infos.find((t) => t.name === name);
      const manifest = this.o.reversi.registry.get(name);
      const extra: string[] = [];
      if (this.o.validate_schemas !== false && info?.inputSchema) {
        const problems = validateSchema(info.inputSchema, args ?? {});
        if (problems.length) extra.push(`arguments do not match the tool's input schema: ${problems.slice(0, 5).join("; ")}`);
      }
      if (manifest?.schema_hash && info && schemaHash(info) !== manifest.schema_hash) {
        extra.push("the tool's input schema changed since its manifest was approved: review the manifest again");
      }

      // A tool without a manifest that the server calls read-only may run in a shadow observe run, if the operator allowed that.
      const shadow = !manifest && this.o.unclassified_reads === "observe" && info !== undefined && hintsOf(info).read_only === true && run.state().mode === "enforce";
      const active = shadow ? (readRun ??= this.readRunFor(principal, run)) : run;
      const begin = await active.begin({ tool: name, args, reason, ...(extra.length ? { extra_violations: extra } : {}), ...(shadow ? { extra_notes: ["unclassified read: the server says it is read-only; this is unverified"] } : {}) });
      if (begin.decision === "block") {
        return fail(`Blocked by Reversi: ${begin.reasons.join("; ")}`, { reversi: { blocked: true, reasons: begin.reasons } });
      }

      let result: CallToolResult;
      try {
        result = await this.forward(name, args, manifest);
      } catch (e) {
        active.complete(begin.step, outcomeForError(e, manifest));
        throw e;
      }
      if (result.isError) active.complete(begin.step, { status: "failed", error: "upstream returned isError" });
      else {
        const handle = resultForHandle(result);
        const bad = this.o.validate_schemas !== false && info?.outputSchema && (result as { structuredContent?: unknown }).structuredContent !== undefined ? validateSchema(info.outputSchema, (result as { structuredContent?: unknown }).structuredContent) : [];
        active.complete(begin.step, bad.length ? { status: "succeeded", result: handle, invalid_result: true, notes: [`result does not match the tool's output schema: ${bad.slice(0, 3).join("; ")}`] } : { status: "succeeded", result: handle });
      }
      if (begin.decision === "would_block" && this.o.mode === "advise") {
        return { ...result, content: [...result.content, { type: "text", text: `Reversi advisory (nothing was blocked): ${begin.reasons.join("; ")}` }] };
      }
      return result;
    });

    return { server, run };
  }
}
