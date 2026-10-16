/** Build a fully configured engine from files and environment: shared by the server, gateway and CLI. */
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import { Approvals } from "./approvals.js";
import { Delegations } from "./delegations.js";
import { webhookNotifier } from "./notify.js";
import { ContentChecker } from "./content.js";
import { openData, type Data, type DataOptions } from "./data.js";
import { Ledger } from "./ledger.js";
import { loadRegistry } from "./local.js";
import { Reversi } from "./engine.js";
import type { Registry } from "./manifest.js";
import { Policy, mergePolicyDocs, parsePolicy, type PolicyDoc } from "./policy.js";

export interface EngineConfig {
  /** Manifest file or directory. */
  manifests: string;
  data: DataOptions;
  /** Policy file (.yaml/.yml/.json) with rules, limits, tests and an optional `content:` section. */
  policy?: string;
  environment?: string;
  kill_switch_file?: string;
  /** Extra policy rules merged with the policy file (the gateway compiles its allow/deny lists into this). */
  extra_policy?: PolicyDoc;
  /** How long approval requests stay valid. Default one hour. */
  approval_ttl_ms?: number;
  /** Webhook (Slack/Teams incoming-webhook compatible) told about each new approval request. */
  approval_webhook?: string;
  /** Public URL of the console, linked from the notification. */
  console_url?: string;
}

export interface EngineHandle {
  reversi: Reversi;
  approvals: Approvals;
  delegations: Delegations;
  registry: Registry;
  data: Data;
}

export function loadPolicyFile(path: string) {
  const text = readFileSync(path, "utf8");
  const doc = parsePolicy(extname(path).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text));
  return { doc, policy: new Policy(doc), content: doc.content ? new ContentChecker(doc.content) : undefined };
}

export async function openEngine(cfg: EngineConfig): Promise<EngineHandle> {
  const registry = loadRegistry(cfg.manifests);
  const data = await openData(cfg.data);
  const ledger = new Ledger(data.ledger);
  const delegations = new Delegations(data.kv);
  const approvals = new Approvals(data.approvals, {
    delegations,
    on_decision: (rec, decision) => {
      const bg = rec.break_glass;
      const last = rec.decisions?.[rec.decisions.length - 1];
      ledger.append({
        ts_ms: Date.now(),
        run_id: rec.run_id,
        step: rec.step,
        actor: last?.by ?? rec.decided_by ?? "approver",
        tool: rec.tool,
        reason: rec.decision_note || `operator ${decision} request ${rec.id}`,
        event: decision === "approved" ? "approved" : "blocked",
        detail: bg
          ? `BREAK-GLASS: approval ${rec.id} forced by ${bg.by}; evidence: ${bg.evidence}`
          : `approval ${rec.id} ${decision} by ${rec.decided_by}${last?.on_behalf_of ? ` (on behalf of ${last.on_behalf_of})` : ""}${(rec.quorum ?? 1) > 1 ? ` [quorum ${rec.quorum}]` : ""}${decision === "approved" ? "; the call must be retried" : ""}`,
      });
    },
    on_escalate: (rec) =>
      ledger.append({
        ts_ms: Date.now(),
        run_id: rec.run_id,
        step: rec.step,
        actor: "reversi",
        tool: rec.tool,
        reason: `approval ${rec.id} was not answered in time`,
        event: "escalated",
        detail: `escalated to ${(rec.required_roles ?? []).join(", ") || "any approver"}`,
      }),
    ttl_ms: cfg.approval_ttl_ms,
    on_request: cfg.approval_webhook ? webhookNotifier({ url: cfg.approval_webhook, console_url: cfg.console_url }) : undefined,
  });
  const file = cfg.policy ? loadPolicyFile(cfg.policy) : undefined;
  const merged = mergePolicyDocs(file?.doc, cfg.extra_policy);
  const pol = merged ? { policy: new Policy(merged, undefined, data.kv), content: merged.content ? new ContentChecker(merged.content) : undefined } : undefined;
  const reversi = new Reversi({
    registry,
    ledger,
    runs: data.runs,
    approver: approvals.asApprover(),
    policy: pol?.policy,
    content: pol?.content,
    environment: cfg.environment,
    kill_switch_file: cfg.kill_switch_file,
    kv: data.kv,
  });
  return { reversi, approvals, delegations, registry, data };
}

/** Engine settings from the environment (REVERSI_MANIFESTS, REVERSI_POLICY, REVERSI_ENV, REVERSI_KILL_FILE, plus the data variables). */
export function engineConfigFromEnv(env: Record<string, string | undefined>, dataOpts: DataOptions): EngineConfig {
  const manifests = env.REVERSI_MANIFESTS;
  if (!manifests) throw new Error("REVERSI_MANIFESTS is required (a manifest file or directory)");
  return { manifests, data: dataOpts, policy: env.REVERSI_POLICY, environment: env.REVERSI_ENV, kill_switch_file: env.REVERSI_KILL_FILE, approval_webhook: env.REVERSI_APPROVAL_WEBHOOK, console_url: env.REVERSI_CONSOLE_URL };
}
