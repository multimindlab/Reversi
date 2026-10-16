/**
 * Notification channels: Slack, Microsoft Teams, email, PagerDuty, Opsgenie and a signed generic webhook. Every channel
 * sends through the egress guard with a timeout and retries transient failures; a failure is reported to `onError` and
 * never changes what Reversi decided.
 */
import { createHmac } from "node:crypto";
import { guardedFetch, type EgressConfig } from "./egress.js";
import { sendMail } from "./smtp.js";

export type Severity = "info" | "warning" | "critical";
const RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

export interface NotifyMessage {
  /** Machine-readable event name (`approval_requested`, `rollback_failed`, ...). */
  event: string;
  severity: Severity;
  title: string;
  text: string;
  /** Alerts with the same key update one incident instead of opening new ones. */
  dedup_key?: string;
  /** Close the incident named by `dedup_key` (PagerDuty resolve, Opsgenie close). */
  resolve?: boolean;
  link?: string;
  /** Structured details (names and ids, never argument values). */
  data?: Record<string, unknown>;
  /** For interactive approval buttons. */
  approval?: { id: string; run_id: string; tool: string };
}

export type ChannelConfig =
  | { type: "slack"; name: string; url: string; interactive?: boolean }
  | { type: "teams"; name: string; url: string }
  | { type: "email"; name: string; host: string; port: number; secure?: boolean; starttls?: boolean; user?: string; pass?: string; from: string; to: string[]; verify_tls?: boolean }
  | { type: "pagerduty"; name: string; routing_key: string; url?: string }
  | { type: "opsgenie"; name: string; api_key: string; region?: "us" | "eu"; url?: string }
  | { type: "webhook"; name: string; url: string; secret?: string; headers?: Record<string, string> };

export interface Channel {
  name: string;
  type: ChannelConfig["type"];
  send(msg: NotifyMessage): Promise<void>;
}

export interface ChannelDeps {
  fetch?: typeof fetch;
  egress?: EgressConfig;
  /** Pause between retries. */
  sleep?: (ms: number) => Promise<void>;
  attempts?: number;
}

const COLOR: Record<Severity, string> = { info: "0076D7", warning: "FFA500", critical: "D70000" };
const PD_SEV: Record<Severity, string> = { info: "info", warning: "warning", critical: "critical" };
const OG_PRIO: Record<Severity, string> = { info: "P5", warning: "P3", critical: "P1" };

export function createChannel(cfg: ChannelConfig, deps: ChannelDeps = {}): Channel {
  const f = guardedFetch(deps.egress, deps.fetch);
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const attempts = deps.attempts ?? 3;

  /** POST JSON, retrying network errors, 429 and 5xx. 4xx (a wrong URL or key) fails at once. */
  async function post(url: string, body: unknown, headers: Record<string, string> = {}): Promise<void> {
    const text = typeof body === "string" ? body : JSON.stringify(body);
    let last = "";
    for (let i = 1; i <= attempts; i++) {
      try {
        const res = await f(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: text, signal: AbortSignal.timeout(10_000) });
        if (res.ok) return;
        last = `answered ${res.status}`;
        if (res.status < 500 && res.status !== 429) break;
      } catch (e) {
        last = e instanceof Error ? e.message : String(e);
      }
      if (i < attempts) await sleep(200 * 2 ** (i - 1));
    }
    throw new Error(`${cfg.type} ${cfg.name}: ${last.replace(/(key|token|secret)=[^&\s]+/gi, "$1=[redacted]")}`);
  }

  const plain = (m: NotifyMessage) => `${m.title}\n${m.text}${m.link ? `\n${m.link}` : ""}`;

  switch (cfg.type) {
    case "slack":
      return {
        name: cfg.name,
        type: cfg.type,
        send: (m) => {
          const blocks: unknown[] = [
            { type: "header", text: { type: "plain_text", text: m.title.slice(0, 150) } },
            { type: "section", text: { type: "mrkdwn", text: m.text.slice(0, 2900) } },
          ];
          if (m.link) blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: `<${m.link}|Open in the Reversi console>` }] });
          if (cfg.interactive && m.approval) {
            blocks.push({
              type: "actions",
              block_id: "reversi_approval",
              elements: [
                { type: "button", text: { type: "plain_text", text: "Approve" }, style: "primary", action_id: "reversi_approve", value: m.approval.id },
                { type: "button", text: { type: "plain_text", text: "Deny" }, style: "danger", action_id: "reversi_deny", value: m.approval.id },
              ],
            });
          }
          return post(cfg.url, { text: plain(m), blocks });
        },
      };
    case "teams":
      return {
        name: cfg.name,
        type: cfg.type,
        send: (m) =>
          post(cfg.url, {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            summary: m.title,
            themeColor: COLOR[m.severity],
            title: m.title,
            text: m.text,
            ...(m.link ? { potentialAction: [{ "@type": "OpenUri", name: "Open in Reversi", targets: [{ os: "default", uri: m.link }] }] } : {}),
          }),
      };
    case "pagerduty":
      return {
        name: cfg.name,
        type: cfg.type,
        send: (m) =>
          post(cfg.url ?? "https://events.pagerduty.com/v2/enqueue", {
            routing_key: cfg.routing_key,
            event_action: m.resolve ? "resolve" : "trigger",
            dedup_key: m.dedup_key ?? `${m.event}:${m.title}`.slice(0, 255),
            payload: { summary: m.title.slice(0, 1024), source: "reversi", severity: PD_SEV[m.severity], custom_details: { text: m.text, ...m.data } },
            ...(m.link ? { links: [{ href: m.link, text: "Reversi console" }] } : {}),
          }),
      };
    case "opsgenie": {
      const base = cfg.url ?? (cfg.region === "eu" ? "https://api.eu.opsgenie.com" : "https://api.opsgenie.com");
      const auth = { authorization: `GenieKey ${cfg.api_key}` };
      return {
        name: cfg.name,
        type: cfg.type,
        send: (m) => {
          const alias = (m.dedup_key ?? `${m.event}:${m.title}`).slice(0, 512);
          if (m.resolve) return post(`${base}/v2/alerts/${encodeURIComponent(alias)}/close?identifierType=alias`, { note: m.text.slice(0, 25000), source: "reversi" }, auth);
          return post(`${base}/v2/alerts`, { message: m.title.slice(0, 130), alias, description: m.text.slice(0, 15000), priority: OG_PRIO[m.severity], source: "reversi", details: Object.fromEntries(Object.entries(m.data ?? {}).map(([k, v]) => [k, String(v)])) }, auth);
        },
      };
    }
    case "email":
      return {
        name: cfg.name,
        type: cfg.type,
        send: async (m) => {
          let last = "";
          for (let i = 1; i <= attempts; i++) {
            try {
              await sendMail({ host: cfg.host, port: cfg.port, secure: cfg.secure, starttls: cfg.starttls, user: cfg.user, pass: cfg.pass, from: cfg.from, verify_tls: cfg.verify_tls }, { to: cfg.to, subject: `[Reversi ${m.severity}] ${m.title}`, text: plain(m) });
              return;
            } catch (e) {
              last = e instanceof Error ? e.message : String(e);
              if (/^SMTP .*(5\d\d) /.test(last) || /invalid address/.test(last)) break;
              if (i < attempts) await sleep(200 * 2 ** (i - 1));
            }
          }
          throw new Error(`email ${cfg.name}: ${last}`);
        },
      };
    case "webhook":
      return {
        name: cfg.name,
        type: cfg.type,
        send: (m) => {
          const body = JSON.stringify({ event: m.event, ts: new Date().toISOString(), severity: m.severity, title: m.title, text: m.text, link: m.link, dedup_key: m.dedup_key, resolve: m.resolve === true, data: m.data ?? {} });
          const sig: Record<string, string> = cfg.secret ? { "x-reversi-signature": `sha256=${createHmac("sha256", cfg.secret).update(body).digest("hex")}` } : {};
          return post(cfg.url, body, { ...(cfg.headers ?? {}), ...sig, "x-reversi-event": m.event });
        },
      };
  }
}

export function parseChannels(raw: unknown, errors: string[]): ChannelConfig[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    errors.push("`channels` must be a list");
    return [];
  }
  const names = new Set<string>();
  const out: ChannelConfig[] = [];
  raw.forEach((c: unknown, i: number) => {
    const w = `channels[${i}]`;
    const o = c as Record<string, unknown>;
    if (typeof o !== "object" || o === null) return void errors.push(`${w}: must be an object`);
    if (typeof o.name !== "string" || !o.name) errors.push(`${w}: name is required`);
    else if (names.has(o.name)) errors.push(`${w}: duplicate name \`${o.name}\``);
    else names.add(o.name);
    const need = (keys: string[]) => keys.forEach((k) => typeof o[k] !== "string" && errors.push(`${w}: ${k} is required`));
    const url = (k: string) => {
      try {
        const u = new URL(String(o[k]));
        if (u.protocol !== "https:" && u.protocol !== "http:") errors.push(`${w}: ${k} must be http(s)`);
      } catch {
        errors.push(`${w}: ${k} is not a valid URL`);
      }
    };
    switch (o.type) {
      case "slack":
      case "teams":
        need(["url"]);
        if (typeof o.url === "string") url("url");
        break;
      case "webhook":
        need(["url"]);
        if (typeof o.url === "string") url("url");
        break;
      case "pagerduty":
        need(["routing_key"]);
        break;
      case "opsgenie":
        need(["api_key"]);
        if (o.region !== undefined && o.region !== "us" && o.region !== "eu") errors.push(`${w}: region must be us or eu`);
        break;
      case "email":
        need(["host", "from"]);
        if (!Number.isInteger(o.port)) errors.push(`${w}: port is required`);
        if (!Array.isArray(o.to) || o.to.length === 0 || o.to.some((t) => typeof t !== "string")) errors.push(`${w}: to must be a list of addresses`);
        break;
      default:
        errors.push(`${w}: type must be slack, teams, email, pagerduty, opsgenie or webhook`);
    }
    out.push(o as unknown as ChannelConfig);
  });
  return out;
}

export interface Route {
  /** Event names, or `*`. */
  events: string[];
  channels: string[];
  min_severity?: Severity;
}

export class Notifier {
  private readonly byName = new Map<string, Channel>();
  constructor(
    channels: Channel[],
    private readonly routes: Route[],
    private readonly onError: (e: Error, channel: string) => void = (e) => console.error(`notification failed: ${e.message}`),
  ) {
    for (const c of channels) this.byName.set(c.name, c);
    for (const r of routes) for (const n of r.channels) if (!this.byName.has(n)) throw new Error(`route names unknown channel \`${n}\``);
  }

  channelNames(): string[] {
    return [...this.byName.keys()];
  }

  /** Send to every channel a matching route names. Returns once all have finished; never throws. */
  async notify(msg: NotifyMessage): Promise<{ sent: string[]; failed: string[] }> {
    const targets = new Set<string>();
    for (const r of this.routes) {
      if ((r.events.includes("*") || r.events.includes(msg.event)) && RANK[msg.severity] >= RANK[r.min_severity ?? "info"]) r.channels.forEach((c) => targets.add(c));
    }
    const sent: string[] = [];
    const failed: string[] = [];
    await Promise.all(
      [...targets].map(async (n) => {
        try {
          await (this.byName.get(n) as Channel).send(msg);
          sent.push(n);
        } catch (e) {
          failed.push(n);
          this.onError(e instanceof Error ? e : new Error(String(e)), n);
        }
      }),
    );
    return { sent, failed };
  }

  /** Fire and forget, for hooks that must not wait. */
  notifyLater(msg: NotifyMessage): void {
    void this.notify(msg);
  }
}

export function parseRoutes(raw: unknown, channels: ChannelConfig[], errors: string[]): Route[] {
  if (raw === undefined) return channels.length ? [{ events: ["*"], channels: channels.map((c) => c.name), min_severity: "info" }] : [];
  if (!Array.isArray(raw)) {
    errors.push("`routes` must be a list");
    return [];
  }
  const names = new Set(channels.map((c) => c.name));
  return raw.map((r: unknown, i: number) => {
    const o = r as Record<string, unknown>;
    if (!Array.isArray(o?.events) || o.events.length === 0) errors.push(`routes[${i}]: events must be a list (or ["*"])`);
    if (!Array.isArray(o?.channels) || o.channels.length === 0) errors.push(`routes[${i}]: channels must be a list`);
    else for (const c of o.channels as string[]) if (!names.has(c)) errors.push(`routes[${i}]: unknown channel \`${c}\``);
    if (o?.min_severity !== undefined && !["info", "warning", "critical"].includes(o.min_severity as string)) errors.push(`routes[${i}]: min_severity must be info, warning or critical`);
    return o as unknown as Route;
  });
}
