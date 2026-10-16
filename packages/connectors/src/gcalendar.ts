import {
  HttpError,
  asRecord,
  defineConnector,
  matches,
  optMatches,
  optPosInt,
  optStr,
  send,
  snippet,
  str,
  type Connector,
  type Fetch,
} from "./common.js";

export interface GcalendarConfig {
  token: string;
  fetch?: Fetch;
  baseUrl?: string;
  timeoutMs?: number;
}

const CALENDAR_ID = /^[A-Za-z0-9._@%+-]{1,256}$/;
const EVENT_ID = /^[A-Za-z0-9_-]{1,1024}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/;
const FIELDS = ["summary", "description", "location", "start", "end"] as const;

export function createGcalendarConnector(cfg: GcalendarConfig): Connector {
  if (!cfg.token) throw new Error("gcalendar connector needs a `token`");
  const f = cfg.fetch ?? fetch;
  const base = (cfg.baseUrl ?? "https://www.googleapis.com/calendar/v3").replace(/\/+$/, "");
  const secrets = [cfg.token];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  async function api(
    method: "GET" | "POST" | "PATCH" | "DELETE",
    p: string,
    opts: { body?: unknown; tolerate?: number[] } = {},
  ): Promise<{ status: number; json: Record<string, unknown> }> {
    const label = `Google Calendar ${method} ${p.split("?")[0]}`;
    const res = await send(
      f,
      base + p,
      {
        method,
        headers: {
          Authorization: `Bearer ${cfg.token}`,
          Accept: "application/json",
          ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      },
      { label, mutating: method !== "GET", secrets, timeoutMs },
    );
    if (!res.ok && !(opts.tolerate ?? []).includes(res.status)) {
      throw new HttpError(`${label} failed with status ${res.status}: ${snippet(res, secrets)}`, res.status);
    }
    return { status: res.status, json: asRecord(res.json) };
  }

  const calendarOf = (args: Record<string, unknown>) =>
    optMatches(args, "calendar_id", CALENDAR_ID, "calendar id") ?? "primary";
  const calPath = (id: string) => `/calendars/${encodeURIComponent(id)}/events`;

  /** `2026-05-01` is an all-day date; anything else must be an RFC 3339 date-time. */
  function when(args: Record<string, unknown>, key: "start" | "end", zone: string | undefined): Record<string, string> {
    const v = str(args, key, { max: 64 });
    if (DATE.test(v)) return { date: v };
    if (!DATE_TIME.test(v)) throw new Error(`\`${key}\` must be a date (2026-05-01) or an RFC 3339 date-time`);
    return zone ? { dateTime: v, timeZone: zone } : { dateTime: v };
  }

  /** PATCH merges nested objects, so the unused date/dateTime key must be cleared explicitly. */
  const exclusive = (t: unknown): unknown => {
    if (typeof t !== "object" || t === null || Array.isArray(t)) return t;
    const r = t as Record<string, unknown>;
    if (typeof r.dateTime === "string") return { ...r, date: null };
    if (typeof r.date === "string") return { ...r, dateTime: null };
    return t;
  };

  const cal = { type: "string", description: "Calendar ID; default primary" };
  const eventId = { type: "string" };
  const timeProps = {
    start: { type: "string", description: "Date or RFC 3339 date-time" },
    end: { type: "string", description: "Date or RFC 3339 date-time" },
    time_zone: { type: "string", description: "IANA zone such as Europe/Berlin" },
  };

  return defineConnector("gcalendar", [
    {
      name: "list_events",
      description: "List events, optionally within a time window.",
      effect: "read_only",
      permission: "gcalendar:events:read",
      properties: {
        calendar_id: cal,
        time_min: { type: "string", description: "RFC 3339" },
        time_max: { type: "string", description: "RFC 3339" },
        max_results: { type: "integer", minimum: 1, maximum: 250 },
        page_token: { type: "string" },
      },
      handler: async (args) => {
        const q = new URLSearchParams({ singleEvents: "true", orderBy: "startTime" });
        const tmin = optMatches(args, "time_min", DATE_TIME, "RFC 3339 date-time");
        const tmax = optMatches(args, "time_max", DATE_TIME, "RFC 3339 date-time");
        const max = optPosInt(args, "max_results");
        if (max !== undefined && max > 250) throw new Error("`max_results` must be at most 250");
        const token = optStr(args, "page_token", { max: 2048 });
        if (tmin) q.set("timeMin", tmin);
        if (tmax) q.set("timeMax", tmax);
        if (max) q.set("maxResults", String(max));
        if (token) q.set("pageToken", token);
        const { json } = await api("GET", `${calPath(calendarOf(args))}?${q.toString()}`);
        const events = (Array.isArray(json.items) ? json.items : []).map((e) => {
          const r = asRecord(e);
          return { event_id: r.id, summary: r.summary ?? null, start: r.start, end: r.end, status: r.status };
        });
        return { events, next_page_token: typeof json.nextPageToken === "string" ? json.nextPageToken : null };
      },
    },
    {
      name: "create_event",
      description:
        "Create an event. No invitation emails are sent (sendUpdates=none). Rollback deletes the event.",
      effect: "reversible",
      permission: "gcalendar:events:write",
      compensation: {
        tool: "delete_event",
        argument_map: { calendar_id: "$result.calendar_id", event_id: "$result.event_id" },
      },
      properties: {
        calendar_id: cal,
        summary: { type: "string" },
        description: { type: "string" },
        location: { type: "string" },
        ...timeProps,
      },
      required: ["summary", "start", "end"],
      handler: async (args) => {
        const calendar_id = calendarOf(args);
        const zone = optStr(args, "time_zone", { max: 64 });
        const body: Record<string, unknown> = {
          summary: str(args, "summary", { max: 1024 }),
          start: when(args, "start", zone),
          end: when(args, "end", zone),
        };
        const description = optStr(args, "description", { max: 8192 });
        const location = optStr(args, "location", { max: 1024 });
        if (description !== undefined) body.description = description;
        if (location !== undefined) body.location = location;
        const { json } = await api("POST", `${calPath(calendar_id)}?sendUpdates=none`, { body });
        if (typeof json.id !== "string") throw new Error("Google Calendar response had no event id");
        return { calendar_id, event_id: json.id, html_link: json.htmlLink ?? null };
      },
    },
    {
      name: "delete_event",
      description: "Delete an event without notifying attendees. An event that is already gone counts as success.",
      effect: "idempotent",
      permission: "gcalendar:events:delete",
      properties: { calendar_id: cal, event_id: eventId },
      required: ["event_id"],
      handler: async (args) => {
        const calendar_id = calendarOf(args);
        const id = matches(args, "event_id", EVENT_ID, "event id");
        const r = await api("DELETE", `${calPath(calendar_id)}/${encodeURIComponent(id)}?sendUpdates=none`, {
          tolerate: [404, 410],
        });
        return { calendar_id, event_id: id, deleted: r.status !== 404 && r.status !== 410 };
      },
    },
    {
      name: "update_event",
      description:
        "Change summary, description, location, start or end of an event (no notifications). The event is read first; the previous values of exactly the changed fields are returned so rollback can patch them back.",
      effect: "reversible",
      permission: "gcalendar:events:write",
      compensation: {
        tool: "restore_event",
        argument_map: {
          calendar_id: "$result.calendar_id",
          event_id: "$result.event_id",
          previous: "$result.previous",
        },
      },
      properties: {
        calendar_id: cal,
        event_id: eventId,
        summary: { type: "string" },
        description: { type: "string" },
        location: { type: "string" },
        ...timeProps,
      },
      required: ["event_id"],
      handler: async (args) => {
        const calendar_id = calendarOf(args);
        const id = matches(args, "event_id", EVENT_ID, "event id");
        const zone = optStr(args, "time_zone", { max: 64 });
        const patch: Record<string, unknown> = {};
        for (const k of ["summary", "description", "location"] as const) {
          const v = optStr(args, k, { max: k === "summary" || k === "location" ? 1024 : 8192 });
          if (v !== undefined) patch[k] = v;
        }
        if (args.start !== undefined) patch.start = exclusive(when(args, "start", zone));
        if (args.end !== undefined) patch.end = exclusive(when(args, "end", zone));
        if (Object.keys(patch).length === 0) throw new Error("nothing to update: give at least one field");
        const p = `${calPath(calendar_id)}/${encodeURIComponent(id)}`;
        const current = (await api("GET", p)).json;
        const previous: Record<string, unknown> = {};
        for (const k of Object.keys(patch)) previous[k] = current[k] ?? null;
        await api("PATCH", `${p}?sendUpdates=none`, { body: patch });
        return { calendar_id, event_id: id, previous };
      },
    },
    {
      name: "restore_event",
      description:
        "Patch an event back to previously saved field values (a null removes the field). Safe to repeat. Used to undo update_event.",
      effect: "idempotent",
      permission: "gcalendar:events:write",
      properties: {
        calendar_id: cal,
        event_id: eventId,
        previous: { type: "object", description: "Field values saved by update_event" },
      },
      required: ["event_id", "previous"],
      handler: async (args) => {
        const calendar_id = calendarOf(args);
        const id = matches(args, "event_id", EVENT_ID, "event id");
        const prev = args.previous;
        if (typeof prev !== "object" || prev === null || Array.isArray(prev)) throw new Error("`previous` must be an object");
        const body: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(prev)) {
          if (!(FIELDS as readonly string[]).includes(k)) throw new Error(`\`previous.${k}\` is not a restorable field`);
          body[k] = k === "start" || k === "end" ? exclusive(v) : v;
        }
        if (Object.keys(body).length === 0) throw new Error("`previous` has no fields");
        await api("PATCH", `${calPath(calendar_id)}/${encodeURIComponent(id)}?sendUpdates=none`, { body });
        return { calendar_id, event_id: id, restored: Object.keys(body) };
      },
    },
  ]);
}
