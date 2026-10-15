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
  can,
  createBundle,
  globAny,
  validateManifest,
  type Approvals,
  type Capability,
  type Outcome,
  type Principal,
  type Reversi,
  type Run,
  type SigningKey,
  toJsonl,
} from "@multimindlab/reversi";
import type { UpstreamPool } from "./upstream.js";

export const REASON_META_KEY = "reversi/reason";
export const IDEMPOTENCY_META_KEY = "reversi/idempotency_key";

export interface GatewayOptions {
  reversi: Reversi;
  approvals: Approvals;
  pool: UpstreamPool;
  mode: "observe" | "enforce";
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
function outcomeForError(e: unknown): Outcome {
  const error = e instanceof Error ? e.message : String(e);
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
  private cache: { at: number; tools: Tool[] } | null = null;
  constructor(readonly o: GatewayOptions) {}

  private visible(name: string): boolean {
    const { allow = [], deny = [] } = this.o;
    return (allow.length === 0 || globAny(allow, name)) && !(deny.length > 0 && globAny(deny, name));
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
      // ---- operator only (never listed on the agent endpoint) ----
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
          if (a.approve_compensations === true) {
            for (const act of plan.actions) if (act.kind === "compensate" && act.needs_approval && act.compensation_tool) approvals.add(run.run_id, "compensation", act.compensation_tool, 1, ctx.who.name);
          }
          const report = await run.rollback({
            actor: ctx.who.name,
            retry: { attempts: 3, base_ms: 250 },
            compensate: async (call) => {
              const r = await this.o.pool.call(call.tool, call.args, { [IDEMPOTENCY_META_KEY]: call.idempotency_key, "reversi/run_id": call.run_id, "reversi/step": call.step });
              if (r.isError) throw new Error(`compensation ${call.tool} returned an error: ${text(r.content).slice(0, 200)}`);
            },
          });
          return ok({ dry_run: false, report });
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

  private static readonly AGENT_TOOLS = new Set(["reversi.list_runs", "reversi.get_run", "reversi.get_action_trace", "reversi.plan_rollback", "reversi.dry_run_rollback", "reversi.validate_manifest"]);

  private async upstreamTools(): Promise<Tool[]> {
    if (this.cache && Date.now() - this.cache.at < 5_000) return this.cache.tools;
    const tools = (await this.o.pool.listTools()).filter((t) => this.visible(t.name));
    this.cache = { at: Date.now(), tools };
    return tools;
  }

  /**
   * A new MCP session. `operator: false` is the agent endpoint: one run, upstream tools, read-only
   * reversi tools. `operator: true` exposes only the operator tools, limited by the principal's roles.
   */
  createSession(opts: { principal: Principal; operator: boolean; run_id?: string }): { server: Server; run: Run | null } {
    const { principal } = opts;
    const server = new Server({ name: "reversi-gateway", version: "0.1.0" }, { capabilities: { tools: {} } });
    const rtools = this.tools().filter((t) => (opts.operator ? can(principal, t.cap) : Gateway.AGENT_TOOLS.has(t.name)));
    const ctx: Ctx = { who: principal, own_only: !opts.operator };
    const run = opts.operator
      ? null
      : this.o.reversi.startRun({
          run_id: opts.run_id,
          actor: principal.name,
          scope: SealedScope.seal(this.scopeFor(principal)),
          mode: this.o.mode,
          reason: "MCP gateway session",
        });

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
      const begin = await run.begin({ tool: name, args, reason });
      if (begin.decision === "block") {
        return fail(`Blocked by Reversi: ${begin.reasons.join("; ")}`, { reversi: { blocked: true, reasons: begin.reasons } });
      }

      let result: CallToolResult;
      try {
        result = await this.o.pool.call(name, args);
      } catch (e) {
        run.complete(begin.step, outcomeForError(e));
        throw e;
      }
      if (result.isError) run.complete(begin.step, { status: "failed", error: "upstream returned isError" });
      else run.complete(begin.step, { status: "succeeded", result: resultForHandle(result) });
      return result;
    });

    return { server, run };
  }
}
