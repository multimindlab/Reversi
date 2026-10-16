import { expect } from "vitest";
import { createTeamsConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";

export const TOKEN = "eyJ0eXAi.TEAMS-SECRET-GRAPH-TOKEN.sig";
export const TEAM = "11111111-2222-3333-4444-555555555555";
export const CHANNEL = "19:abc123@thread.tacv2";

export function fakeTeams() {
  const messages = new Map<string, { content: string; deleted: boolean }>();
  let n = 0;
  const b = httpBackend({
    state: () => ({ messages: [...messages] }),
    handle: (c) => {
      const p = decodeURIComponent(new URL(c.url).pathname).replace("/v1.0", "");
      const base = `/teams/${TEAM}/channels`;
      if (c.method === "GET" && p === base) {
        return { json: { value: [{ id: CHANNEL, displayName: "General", membershipType: "standard" }], "@odata.nextLink": null } };
      }
      if (c.method === "POST" && p === `${base}/${CHANNEL}/messages`) {
        const id = String(1700000000000 + ++n);
        messages.set(id, { content: JSON.parse(c.body).body.content, deleted: false });
        return { status: 201, json: { id, webUrl: `https://teams.example/${id}` } };
      }
      const m = p.match(new RegExp(`^${base}/${CHANNEL}/messages/(\\d+)/softDelete$`));
      if (c.method === "POST" && m) {
        const msg = messages.get(m[1]!);
        if (!msg || msg.deleted) return { status: 404, json: { error: { code: "NotFound", message: "Message not found" } } };
        msg.deleted = true;
        return { status: 204 };
      }
      return { status: 500, json: { error: { message: `unexpected ${c.method} ${c.url}` } } };
    },
  });
  return Object.assign(b, { messages });
}
type FakeTeams = ReturnType<typeof fakeTeams>;
const tm = (b: Backend) => b as FakeTeams;

export const subject: Subject = {
  name: "teams",
  secrets: [TOKEN],
  make: (o) => {
    const backend = fakeTeams();
    return { backend, connector: createTeamsConnector({ token: TOKEN, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
  faultBody: (_status, secret) => ({ json: { error: { code: "Forbidden", message: `denied ${secret}` } } }),
};

export const scenarios: Scenario[] = [
  { tool: "list_channels", args: { team_id: TEAM }, expect: (r) => expect(r).toMatchObject({ channels: [{ id: CHANNEL, display_name: "General" }] }) },
  {
    tool: "post_message",
    args: { team_id: TEAM, channel_id: CHANNEL, content: "hello" },
    expect: (r) => expect(r).toMatchObject({ message_id: "1700000000001" }),
    // a soft-deleted message stays in the channel as a placeholder
    restored: (_b, after) => expect((after as { messages: Array<[string, { deleted: boolean }]> }).messages.every(([, m]) => m.deleted)).toBe(true),
  },
  {
    tool: "delete_message",
    args: { team_id: TEAM, channel_id: CHANNEL, message_id: "1700000000099" },
    setup: (b) => void tm(b).messages.set("1700000000099", { content: "x", deleted: false }),
  },
];
