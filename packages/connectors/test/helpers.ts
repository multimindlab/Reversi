import { Ledger, Registry, Reversi, SealedScope } from "@multimindlab/reversi";
import type { Connector } from "../src/index.js";

export interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}
export interface FakeReply {
  status?: number;
  json?: unknown;
  text?: string;
}

export function fakeFetch(handler: (c: Call, n: number) => FakeReply | Promise<FakeReply>) {
  const calls: Call[] = [];
  const f = (async (url: string | URL | Request, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
    const call: Call = { url: String(url), method: init?.method ?? "GET", headers, body: String(init?.body ?? "") };
    calls.push(call);
    const r = await handler(call, calls.length);
    const body = r.text ?? (r.json === undefined ? "" : JSON.stringify(r.json));
    return new Response(r.status === 204 ? null : body, { status: r.status ?? 200 });
  }) as typeof fetch;
  return { fetch: f, calls };
}

export function failingFetch(message: string) {
  return (async () => {
    throw new TypeError(message);
  }) as typeof fetch;
}

/** A real Reversi engine wired to the connectors' manifests, with every permission granted. */
export function engine(connectors: Connector[]) {
  const registry = Registry.from(connectors.flatMap((c) => c.manifests));
  const permissions = registry.list().map((m) => m.permission);
  const reversi = new Reversi({ registry, ledger: new Ledger(), approver: () => true });
  const run = reversi.startRun({ actor: "test", scope: SealedScope.seal(permissions), reason: "connector test" });
  const handlers = Object.assign({}, ...connectors.map((c) => c.tools)) as Connector["tools"];
  const call = (tool: string, args: Record<string, unknown>) =>
    run.call({
      tool,
      args,
      reason: "test",
      execute: (a) => handlers[tool]!(a as Record<string, unknown>, {}),
    });
  return { reversi, run, registry, call };
}
