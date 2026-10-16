import { expect } from "vitest";
import { createSlackConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";

export const TOKEN = "xoxb-SECRET-SLACK-TOKEN";
export const CH = "C0123ABCDE";
const TS = "1700000000.000001";

export function fakeSlack() {
  const messages = new Map<string, Set<string>>();
  let n = 1;
  const b = httpBackend({
    state: () => ({ messages: [...messages].map(([ts, r]) => [ts, [...r].sort()]) }),
    handle: (c) => {
      const method = new URL(c.url).pathname.replace("/api/", "");
      const body = c.body ? JSON.parse(c.body) : {};
      switch (method) {
        case "chat.postMessage": {
          const ts = `1700000000.${String(++n).padStart(6, "0")}`;
          messages.set(ts, new Set());
          return { json: { ok: true, channel: body.channel, ts } };
        }
        case "chat.delete":
          return messages.delete(body.ts) ? { json: { ok: true } } : { json: { ok: false, error: "message_not_found" } };
        case "reactions.add": {
          const m = messages.get(body.timestamp);
          if (!m) return { json: { ok: false, error: "message_not_found" } };
          if (m.has(body.name)) return { json: { ok: false, error: "already_reacted" } };
          m.add(body.name);
          return { json: { ok: true } };
        }
        case "reactions.remove": {
          const m = messages.get(body.timestamp);
          if (!m) return { json: { ok: false, error: "message_not_found" } };
          return m.delete(body.name) ? { json: { ok: true } } : { json: { ok: false, error: "no_reaction" } };
        }
        case "conversations.list":
          return { json: { ok: true, channels: [{ id: CH, name: "general", is_private: false }], response_metadata: { next_cursor: "" } } };
      }
      return { status: 404 };
    },
  });
  return Object.assign(b, { messages });
}
type FakeSlack = ReturnType<typeof fakeSlack>;
const sl = (b: Backend) => b as FakeSlack;
const seed = (b: Backend) => void sl(b).messages.set(TS, new Set());

export const subject: Subject = {
  name: "slack",
  secrets: [TOKEN],
  make: (o) => {
    const backend = fakeSlack();
    return { backend, connector: createSlackConnector({ token: TOKEN, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
  faultBody: (_s, secret) => ({ json: { ok: false, error: `invalid_auth ${secret}` } }),
};

export const scenarios: Scenario[] = [
  { tool: "list_channels", args: { limit: 10 }, expect: (r) => expect(r).toMatchObject({ channels: [{ id: CH }] }) },
  { tool: "post_message", args: { channel: CH, text: "hi" }, expect: (r) => expect(r).toMatchObject({ channel: CH, ts: "1700000000.000002" }) },
  { tool: "delete_message", args: { channel: CH, ts: TS }, setup: seed },
  { tool: "add_reaction", args: { channel: CH, timestamp: TS, name: "eyes" }, setup: seed },
  { tool: "remove_reaction", args: { channel: CH, timestamp: TS, name: "eyes" }, setup: (b) => void sl(b).messages.set(TS, new Set(["eyes"])) },
];
