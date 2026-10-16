/** Shared pieces for the console pages: the kit each page group is given, HTML helpers and the page layout. */
import type { Context, Hono } from "hono";
import type { Approvals, KeyRing, Principal, Reversi, Capability, EngineHandle } from "@multimindlab/reversi";
import type { ExtraOptions, Extras } from "./extras.js";

export type ConsoleMode = "off" | "open" | "login";

export const esc = (v: unknown): string =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
export const time = (ms: number): string => new Date(ms).toISOString().replace("T", " ").slice(0, 19) + "Z";
export const P = (c: Context, name: string): string => c.req.param(name) ?? "";

export interface Session {
  name: string;
  roles: string[];
  groups?: string[];
  exp: number;
  sid: string;
  /** API-key sessions: which key, re-validated on every request. */
  fp?: string;
  open?: boolean;
}

export interface ConsoleDeps {
  reversi: Reversi;
  approvals: Approvals;
  authenticate: (token: string) => Promise<Principal | null>;
  /** Re-check an API-key session against the live key ring, so disabling, expiring or demoting a key takes effect now. */
  byFingerprint: (fingerprint: string) => Principal | null;
  session_secret: string;
  secure_cookies: boolean;
  session_ttl_ms: number;
  signing_available: boolean;
  report: (run_id: string) => string;
  bundle: (run_id: string | null) => unknown;
  now: () => number;
  mode: ConsoleMode;
  open_role: string;
  opts: ExtraOptions;
  extras: Extras;
  ring: KeyRing;
}

export interface Kit {
  app: Hono;
  deps: ConsoleDeps;
  rv: Reversi;
  engine: EngineHandle | undefined;
  /** Wrap a page: needs a session, optionally a capability, and for POST a CSRF token. */
  guarded: (opts: { cap?: Capability; post?: boolean }, fn: (c: Context, s: Session, form: FormData | null) => Promise<Response> | Response) => (c: Context) => Promise<Response>;
  render: (c: Context, s: Session, title: string, body: string, status?: number) => Response;
  form: (s: Session, action: string, fields: string, label: string, cls?: string) => string;
  csrf: (s: Session) => string;
  principal: (s: Session) => Principal;
  allowed: (s: Session, cap: Capability) => boolean;
  statusBadge: (st: string) => string;
  redirect: (c: Context, to: string) => Response;
}

export const CSS = `body{font:14px/1.5 system-ui,sans-serif;margin:0;color:#1b1b1f;background:#fafafa}header{background:#1F5FD6;color:#fff;padding:.6rem 1.2rem;display:flex;gap:1.1rem;align-items:center;flex-wrap:wrap}header a{color:#fff;text-decoration:none}header a:hover{text-decoration:underline}header .sp{flex:1}main{max-width:1180px;margin:1.2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%;background:#fff;margin:.6rem 0 1.4rem}th,td{border:1px solid #ddd;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f0f2f6}code,pre{background:#eef;border-radius:3px}code{padding:0 3px}pre{padding:.6rem;overflow:auto;white-space:pre-wrap}.badge{display:inline-block;padding:0 7px;border-radius:9px;background:#ddd;font-size:12px}.bad{background:#fbb}.ok{background:#bfb}.warn{background:#fe9}form.inline{display:inline}button{cursor:pointer;padding:3px 10px}.card{background:#fff;border:1px solid #ddd;padding:.8rem 1rem;margin:.6rem 0 1.2rem}input[type=text],input[type=password],input[type=number],select{padding:3px 6px}textarea{width:100%;font:12px/1.4 ui-monospace,monospace;padding:6px;box-sizing:border-box}.muted{color:#666}.add{background:#e6ffe6}.del{background:#ffe6e6}.cols{display:grid;grid-template-columns:1fr 1fr;gap:1rem}@media(max-width:800px){.cols{grid-template-columns:1fr}}`;

export function layout(o: { title: string; session: Session | null; body: string; nav?: { pending: number; critical: number }; csrf?: string; halted?: string | null; mode: ConsoleMode; can: (cap: Capability) => boolean }): string {
  const { session: s } = o;
  const nav = s
    ? `<a href="/console/runs">Runs</a><a href="/console/approvals">Approvals${o.nav?.pending ? ` <span class="badge warn">${o.nav.pending}</span>` : ""}</a><a href="/console/alerts">Alerts${o.nav?.critical ? ` <span class="badge bad">${o.nav.critical}</span>` : ""}</a><a href="/console/manifests">Manifests</a><a href="/console/policy">Policy</a><a href="/console/tools">Tools</a><a href="/console/connectors">Connectors</a><a href="/console/evidence">Evidence</a><a href="/console/settings">Settings</a><span class="sp"></span><span>${esc(s.name)} (${esc(s.roles.join(", "))})${s.open ? " - open console, no login" : ""}</span>${s.open ? "" : `<form class="inline" method="post" action="/console/logout"><input type="hidden" name="csrf" value="${esc(o.csrf ?? "")}"><button>Log out</button></form>`}`
    : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(o.title)} · Reversi Console</title><style>${CSS}</style></head><body><header><strong>Reversi Console</strong>${nav}</header><main>${o.halted ? `<div class="card" style="border-color:#c33"><strong>Kill switch active:</strong> ${esc(o.halted)}. Matching new tool calls are blocked.</div>` : ""}<h1>${esc(o.title)}</h1>${o.body}</main></body></html>`;
}
