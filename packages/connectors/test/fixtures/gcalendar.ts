import { expect } from "vitest";
import { createGcalendarConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";

export const TOKEN = "ya29.SECRET-GOOGLE-CALENDAR-TOKEN";

type Ev = Record<string, any>;

function merge(target: Ev, patch: Ev): void {
  for (const [k, v] of Object.entries(patch)) {
    if (v === null) delete target[k];
    else if (typeof v === "object" && !Array.isArray(v) && typeof target[k] === "object" && target[k] !== null) merge(target[k], v);
    else target[k] = typeof v === "object" ? JSON.parse(JSON.stringify(v, (_k, x) => (x === null ? undefined : x))) : v;
  }
}

export function fakeCalendar() {
  const events = new Map<string, Ev>();
  let n = 0;
  const b = httpBackend({
    state: () => ({ events: [...events].sort() }),
    handle: (c) => {
      const u = new URL(c.url);
      const p = u.pathname.replace("/calendar/v3/calendars/primary/events", "");
      if ((c.method === "POST" || c.method === "PATCH" || c.method === "DELETE") && u.searchParams.get("sendUpdates") !== "none") {
        return { status: 400, json: { error: { message: "writes must pass sendUpdates=none" } } };
      }
      if (c.method === "POST" && p === "") {
        const id = `ev${++n}`;
        const ev = { id, ...JSON.parse(c.body) };
        events.set(id, ev);
        return { json: { id, htmlLink: `https://calendar.example/${id}` } };
      }
      if (c.method === "GET" && p === "") {
        return { json: { items: [...events.values()].map((e) => ({ id: e.id, summary: e.summary, start: e.start, end: e.end, status: "confirmed" })), nextPageToken: undefined } };
      }
      const m = p.match(/^\/([A-Za-z0-9_-]+)$/);
      if (m) {
        const ev = events.get(m[1]!);
        if (!ev) return { status: 404, json: { error: { code: 404, message: "Not Found" } } };
        if (c.method === "GET") return { json: ev };
        if (c.method === "PATCH") {
          merge(ev, JSON.parse(c.body));
          return { json: ev };
        }
        if (c.method === "DELETE") {
          events.delete(m[1]!);
          return { status: 204 };
        }
      }
      return { status: 500, json: { error: { message: `unexpected ${c.method} ${c.url}` } } };
    },
  });
  return Object.assign(b, { events });
}
type FakeCal = ReturnType<typeof fakeCalendar>;
const cal = (b: Backend) => b as FakeCal;
const seed = (b: Backend) =>
  void cal(b).events.set("ev9", {
    id: "ev9",
    summary: "Standup",
    start: { dateTime: "2026-05-01T09:00:00Z" },
    end: { dateTime: "2026-05-01T09:15:00Z" },
  });

export const subject: Subject = {
  name: "gcalendar",
  secrets: [TOKEN],
  make: (o) => {
    const backend = fakeCalendar();
    return { backend, connector: createGcalendarConnector({ token: TOKEN, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
  faultBody: (_s, secret) => ({ json: { error: { code: 403, message: `forbidden ${secret}` } } }),
};

export const scenarios: Scenario[] = [
  { tool: "list_events", args: { time_min: "2026-05-01T00:00:00Z", max_results: 10 }, setup: seed, expect: (r) => expect((r as { events: unknown[] }).events).toHaveLength(1) },
  {
    tool: "create_event",
    args: { summary: "Lunch", start: "2026-05-02T12:00:00+02:00", end: "2026-05-02T13:00:00+02:00", time_zone: "Europe/Berlin", location: "Cafe" },
    expect: (r) => expect(r).toMatchObject({ calendar_id: "primary", event_id: "ev1" }),
  },
  { tool: "delete_event", args: { event_id: "ev9" }, setup: seed },
  {
    tool: "update_event",
    args: { event_id: "ev9", summary: "Planning", location: "Room 1", start: "2026-05-01T10:00:00Z", end: "2026-05-01T10:30:00Z" },
    setup: seed,
    expect: (r) =>
      expect(r).toMatchObject({
        event_id: "ev9",
        previous: { summary: "Standup", location: null, start: { dateTime: "2026-05-01T09:00:00Z" }, end: { dateTime: "2026-05-01T09:15:00Z" } },
      }),
  },
  {
    tool: "restore_event",
    args: { event_id: "ev9", previous: { summary: "Standup", location: null } },
    setup: (b) => void cal(b).events.set("ev9", { id: "ev9", summary: "Planning", location: "Room 1" }),
  },
];
