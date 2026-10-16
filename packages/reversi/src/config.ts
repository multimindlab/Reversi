/**
 * Build a fully configured engine from files and environment: shared by the server, gateway and CLI.
 *
 * `openEngine` wires everything the product does around the core engine: where manifests and policy come from (a folder,
 * a signed registry, a URL), the data store, approvals with routing and notifications, capture, alerts, tracing,
 * anchoring and egress rules. `reload()` re-reads manifests and policy while running; `watch()` does it when they change.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import { parse as parseYaml } from "yaml";
import { AlertManager } from "./alerts.js";
import { anchorLedger, type AnchorSink } from "./anchor.js";
import { Approvals } from "./approvals.js";
import { CaptureStore } from "./capture.js";
import { Notifier, createChannel, type ChannelConfig, type Route } from "./channels.js";
import { ContentChecker } from "./content.js";
import { openData, type Data, type DataOptions } from "./data.js";
import { Delegations } from "./delegations.js";
import { guardedFetch, type EgressConfig } from "./egress.js";
import { Reversi } from "./engine.js";
import type { SigningKey } from "./evidence.js";
import { approvalNotification, attachNotifications } from "./hub.js";
import { Ledger } from "./ledger.js";
import { loadRegistry } from "./local.js";
import { Registry } from "./manifest.js";
import { ManifestRegistry, loadRemoteRegistry } from "./registry.js";
import { webhookNotifier } from "./notify.js";
import { OtelExporter } from "./otel.js";
import { Policy, mergePolicyDocs, parsePolicy, type PolicyDoc } from "./policy.js";
import { PolicyVersions } from "./policyversions.js";
import { LegalHolds } from "./retention.js";
import { findProjectConfig, loadProjectConfig, type ProjectConfig } from "./projectconfig.js";

export interface EngineConfig {
  /** A manifest file or folder, a registry folder, or an http(s) URL of a served registry. Empty with `allow_empty_manifests`. */
  manifests: string;
  /** Start with no manifests (the gateway's observe-first mode). */
  allow_empty_manifests?: boolean;
  data: DataOptions;
  /** Policy file (.yaml/.yml/.json), or a folder of versioned policies. */
  policy?: string;
  environment?: string;
  kill_switch_file?: string;
  /** Extra policy rules merged with the policy file (the gateway compiles its allow/deny lists into this). */
  extra_policy?: PolicyDoc;
  /** How long approval requests stay valid. Default one hour. */
  approval_ttl_ms?: number;
  /** Webhook (Slack/Teams incoming-webhook compatible) told about each new approval request. */
  approval_webhook?: string;
  /** Public URL of the console, linked from notifications. */
  console_url?: string;
  /** PEM file with the public key manifests in a registry must be signed by. */
  manifest_public_key?: string;
  /** PEM file with an Ed25519 private key: signs evidence, anchors and retention archives. */
  signing_key?: string;
  capture?: { enabled: boolean; ttl_ms?: number; redact_pii?: boolean };
  notifications?: { channels: ChannelConfig[]; routes: Route[] };
  otel?: { endpoint: string; headers?: Record<string, string>; service_name?: string };
  anchor?: { sinks: AnchorSink[]; interval_ms?: number };
  egress?: EgressConfig;
  alerts?: { interval_ms?: number; remind_ms?: number; denial_spike?: number };
  /** Where problems and reloads are reported. Default: stderr. */
  log?: (level: "info" | "warn" | "error", msg: string) => void;
}

export interface ReloadResult {
  changed: boolean;
  tools: number;
  policy_checksum: string | null;
  error?: string;
}

export interface EngineHandle {
  reversi: Reversi;
  approvals: Approvals;
  delegations: Delegations;
  holds: LegalHolds;
  registry: Registry;
  data: Data;
  capture?: CaptureStore;
  notifier?: Notifier;
  alerts?: AlertManager;
  otel?: OtelExporter;
  signing_key?: SigningKey;
  egress: EgressConfig;
  config: EngineConfig;
  /** Re-read manifests and policy. A failure keeps the old ones and says why. */
  reload(by?: string): Promise<ReloadResult>;
  /** Reload whenever the manifest or policy files change. */
  watch(intervalMs?: number): void;
  /** Start background work: alerts, anchoring, trace export. */
  start(opts?: { health?: () => Promise<Array<{ name: string; ok: boolean }>> }): void;
  close(): Promise<void>;
}

export function loadPolicyFile(path: string) {
  const text = readFileSync(path, "utf8");
  const doc = parsePolicy(extname(path).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text));
  return { doc, policy: new Policy(doc), content: doc.content ? new ContentChecker(doc.content) : undefined };
}

async function loadManifests(cfg: EngineConfig, egress: EgressConfig): Promise<Registry> {
  if (!cfg.manifests) {
    if (cfg.allow_empty_manifests) return new Registry();
    throw new Error("no manifests: set REVERSI_MANIFESTS, `manifests:` in reversi.config.yaml, or pass --manifests");
  }
  const trusted = cfg.manifest_public_key ? readFileSync(cfg.manifest_public_key, "utf8") : undefined;
  if (/^https?:\/\//.test(cfg.manifests)) return loadRemoteRegistry(cfg.manifests, { trusted_public_pem: trusted, egress });
  if (existsSync(cfg.manifests) && statSync(cfg.manifests).isDirectory() && ManifestRegistry.isRegistry(cfg.manifests)) return new ManifestRegistry(cfg.manifests, { trusted_public_pem: trusted }).load();
  if (trusted) throw new Error("manifest_public_key is set but the manifests are not in a signed registry");
  return loadRegistry(cfg.manifests);
}

function loadPolicyDoc(cfg: EngineConfig): { doc: PolicyDoc | undefined; checksum: string | null } {
  let file: PolicyDoc | undefined;
  let text = "";
  if (cfg.policy) {
    if (existsSync(cfg.policy) && statSync(cfg.policy).isDirectory()) {
      const pv = new PolicyVersions(cfg.policy);
      text = pv.activeText() ?? "";
      if (text) file = parsePolicy(parseYaml(text));
    } else {
      text = readFileSync(cfg.policy, "utf8");
      file = parsePolicy(extname(cfg.policy).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text));
    }
  }
  const merged = mergePolicyDocs(file, cfg.extra_policy);
  return { doc: merged, checksum: merged ? createHash("sha256").update(text + JSON.stringify(cfg.extra_policy ?? null)).digest("hex") : null };
}

/** Modification fingerprint of the files a config depends on. */
function fingerprint(paths: Array<string | undefined>): string {
  const parts: string[] = [];
  const walk = (p: string, depth: number) => {
    try {
      const st = statSync(p);
      parts.push(`${p}:${st.mtimeMs}:${st.size}`);
      if (st.isDirectory() && depth < 4) for (const f of readdirSync(p).slice(0, 2000)) walk(join(p, f), depth + 1);
    } catch {
      parts.push(`${p}:missing`);
    }
  };
  for (const p of paths) if (p && !/^https?:\/\//.test(p)) walk(p, 0);
  return parts.join("|");
}

export async function openEngine(cfg: EngineConfig): Promise<EngineHandle> {
  const egress = cfg.egress ?? {};
  const log = cfg.log ?? ((level, msg) => console.error(`reversi [${level}] ${msg}`));
  const registry = await loadManifests(cfg, egress);
  const data = await openData(cfg.data);
  const ledger = new Ledger(data.ledger);

  const signing_key: SigningKey | undefined = cfg.signing_key
    ? await (async () => {
        const { createPrivateKey, createPublicKey } = await import("node:crypto");
        const private_pem = readFileSync(cfg.signing_key as string, "utf8");
        return { private_pem, public_pem: createPublicKey(createPrivateKey(private_pem)).export({ type: "spki", format: "pem" }).toString() };
      })()
    : undefined;

  // ---- notifications ----
  const onNotifyError = (e: Error, channel: string) => log("warn", `notification to ${channel} failed: ${e.message}`);
  const notifier = cfg.notifications?.channels.length
    ? new Notifier(
        cfg.notifications.channels.map((c) => createChannel(c, { egress })),
        cfg.notifications.routes,
        onNotifyError,
      )
    : undefined;
  const legacyWebhook = cfg.approval_webhook ? webhookNotifier({ url: cfg.approval_webhook, console_url: cfg.console_url, on_error: (e) => log("warn", `approval webhook failed: ${e.message}`) }) : undefined;

  const delegations = new Delegations(data.kv);
  const approvals = new Approvals(data.approvals, {
    delegations,
    ttl_ms: cfg.approval_ttl_ms,
    on_request: (rec) => {
      legacyWebhook?.(rec);
      notifier?.notifyLater(approvalNotification(rec, "requested", cfg.console_url));
    },
    on_progress: (rec) => notifier?.notifyLater(approvalNotification(rec, "progress", cfg.console_url)),
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
      notifier?.notifyLater(approvalNotification(rec, "decided", cfg.console_url));
    },
    on_escalate: (rec) => {
      ledger.append({ ts_ms: Date.now(), run_id: rec.run_id, step: rec.step, actor: "reversi", tool: rec.tool, reason: `approval ${rec.id} was not answered in time`, event: "escalated", detail: `escalated to ${(rec.required_roles ?? []).join(", ") || "any approver"}` });
      notifier?.notifyLater(approvalNotification(rec, "escalated", cfg.console_url));
    },
  });

  const pol = loadPolicyDoc(cfg);
  const capture = cfg.capture?.enabled ? new CaptureStore(data.kv, { enabled: true, ...(cfg.capture.ttl_ms ? { ttl_ms: cfg.capture.ttl_ms } : {}), ...(cfg.capture.redact_pii !== undefined ? { redact_pii: cfg.capture.redact_pii } : {}) }) : undefined;
  const reversi = new Reversi({
    registry,
    ledger,
    runs: data.runs,
    approver: approvals.asApprover(),
    policy: pol.doc ? new Policy(pol.doc, undefined, data.kv) : undefined,
    content: pol.doc?.content ? new ContentChecker(pol.doc.content) : undefined,
    environment: cfg.environment,
    kill_switch_file: cfg.kill_switch_file,
    kv: data.kv,
    capture,
  });
  if (notifier) attachNotifications({ reversi, notifier, console_url: cfg.console_url });

  let currentPolicySum = pol.checksum;
  let currentTools = registry.size;
  const stoppers: Array<() => void> = [];

  const otel = cfg.otel ? new OtelExporter({ endpoint: cfg.otel.endpoint, headers: cfg.otel.headers, service_name: cfg.otel.service_name, environment: cfg.environment, egress, onError: (e) => log("warn", `trace export failed: ${e.message}`) }, reversi) : undefined;
  const alerts = notifier ? new AlertManager(reversi, approvals, data.kv, notifier, { remind_ms: cfg.alerts?.remind_ms, denial_spike: cfg.alerts?.denial_spike, console_url: cfg.console_url }) : undefined;

  const handle: EngineHandle = {
    reversi,
    approvals,
    delegations,
    holds: new LegalHolds(data.kv),
    get registry() {
      return reversi.registry;
    },
    data,
    capture,
    notifier,
    alerts,
    otel,
    signing_key,
    egress,
    config: cfg,

    async reload(by = "reload") {
      try {
        const reg = await loadManifests(cfg, egress);
        const p = loadPolicyDoc(cfg);
        const changed = p.checksum !== currentPolicySum || reg.size !== currentTools || JSON.stringify(reg.list()) !== JSON.stringify(reversi.registry.list());
        if (changed) {
          reversi.reload({ registry: reg, policy: p.doc ? new Policy(p.doc, undefined, data.kv) : undefined, content: p.doc?.content ? new ContentChecker(p.doc.content) : undefined });
          currentPolicySum = p.checksum;
          currentTools = reg.size;
          ledger.append({ ts_ms: Date.now(), run_id: "-", actor: by, tool: "-", reason: "configuration reloaded", event: "reloaded", detail: `${reg.size} manifests; policy ${p.checksum ? p.checksum.slice(0, 8) : "none"}` });
          log("info", `reloaded: ${reg.size} manifests, policy ${p.checksum ? p.checksum.slice(0, 8) : "none"}`);
        }
        return { changed, tools: reg.size, policy_checksum: p.checksum };
      } catch (e) {
        const error = e instanceof Error ? e.message : String(e);
        log("error", `reload failed, keeping the previous manifests and policy: ${error}`);
        return { changed: false, tools: currentTools, policy_checksum: currentPolicySum, error };
      }
    },

    watch(intervalMs = 2000) {
      let last = fingerprint([cfg.manifests, cfg.policy, cfg.manifest_public_key]);
      const t = setInterval(() => {
        const now = fingerprint([cfg.manifests, cfg.policy, cfg.manifest_public_key]);
        if (now !== last) {
          last = now;
          void handle.reload("file watcher");
        }
      }, intervalMs);
      t.unref();
      stoppers.push(() => clearInterval(t));
    },

    start(opts = {}) {
      otel?.start();
      if (alerts) {
        alerts.setHealth(opts.health);
        alerts.start(cfg.alerts?.interval_ms ?? 60_000);
        stoppers.push(() => alerts.stop());
      }
      if (cfg.anchor?.sinks.length) {
        const f = guardedFetch(egress);
        const run = () => {
          void anchorLedger(ledger, cfg.anchor?.sinks ?? [], { key: signing_key, egress, fetch: f }).then((r) => r.errors.forEach((e) => log("warn", `anchor sink failed: ${e}`)));
        };
        run();
        const t = setInterval(run, cfg.anchor.interval_ms ?? 3_600_000);
        t.unref();
        stoppers.push(() => clearInterval(t));
      }
    },

    async close() {
      for (const stop of stoppers.splice(0)) stop();
      await otel?.stop();
      data.close();
    },
  };
  return handle;
}

/** Engine settings from the environment (REVERSI_MANIFESTS, REVERSI_POLICY, ...), over the project file if there is one. */
export function engineConfigFromEnv(env: Record<string, string | undefined>, dataOpts: DataOptions, project?: ProjectConfig): EngineConfig {
  const manifests = env.REVERSI_MANIFESTS ?? project?.manifests;
  if (!manifests) throw new Error("REVERSI_MANIFESTS is required (a manifest file or directory), or set `manifests:` in reversi.config.yaml");
  return {
    manifests,
    data: dataOpts,
    policy: env.REVERSI_POLICY ?? project?.policy,
    environment: env.REVERSI_ENV ?? project?.environment,
    kill_switch_file: env.REVERSI_KILL_FILE ?? project?.kill_switch_file,
    approval_webhook: env.REVERSI_APPROVAL_WEBHOOK ?? project?.approval?.webhook,
    console_url: env.REVERSI_CONSOLE_URL ?? project?.approval?.console_url,
    approval_ttl_ms: project?.approval?.ttl_ms,
    manifest_public_key: env.REVERSI_MANIFEST_PUBLIC_KEY ?? project?.manifest_public_key,
    signing_key: env.REVERSI_SIGNING_KEY ?? project?.signing_key,
    capture: env.REVERSI_CAPTURE === "1" || env.REVERSI_CAPTURE === "on" ? { enabled: true, ttl_ms: env.REVERSI_CAPTURE_TTL_DAYS ? Number(env.REVERSI_CAPTURE_TTL_DAYS) * 86_400_000 : project?.capture?.ttl_ms, redact_pii: project?.capture?.redact_pii } : project?.capture,
    notifications: project?.notifications,
    otel: env.REVERSI_OTLP_ENDPOINT ? { endpoint: env.REVERSI_OTLP_ENDPOINT, headers: project?.otel?.headers } : project?.otel,
    anchor: project?.anchor,
    egress: { ...(project?.egress ?? {}), ...(env.REVERSI_EGRESS_ALLOW ? { allow: env.REVERSI_EGRESS_ALLOW.split(",").map((s) => s.trim()).filter(Boolean) } : {}), ...(env.REVERSI_EGRESS_BLOCK_PRIVATE === "1" ? { block_private: true } : {}), ...(env.REVERSI_REGION ? { region: env.REVERSI_REGION } : {}) },
    alerts: project?.alerts,
  };
}

export { findProjectConfig, loadProjectConfig };
