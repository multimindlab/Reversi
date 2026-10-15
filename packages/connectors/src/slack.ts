import {
  HttpError,
  asRecord,
  defineConnector,
  matches,
  optMatches,
  optPosInt,
  optStr,
  redact,
  send,
  snippet,
  str,
  type Connector,
  type Fetch,
} from "./common.js";

export interface SlackConfig {
  token: string;
  fetch?: Fetch;
  baseUrl?: string;
  timeoutMs?: number;
}

const CHANNEL = /^[CGD][A-Z0-9]{2,40}$/;
const TS = /^\d{1,12}\.\d{1,9}$/;
const EMOJI = /^[a-z0-9_+'-]{1,100}$/;

export function createSlackConnector(cfg: SlackConfig): Connector {
  if (!cfg.token) throw new Error("slack connector needs a `token`");
  const f = cfg.fetch ?? fetch;
  const base = (cfg.baseUrl ?? "https://slack.com/api").replace(/\/+$/, "");
  const secrets = [cfg.token];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  /** Slack answers 200 with {ok:false,error}; `tolerate` lists errors that mean the goal is already met. */
  async function call(
    method: string,
    payload: Record<string, unknown>,
    o: { mutating: boolean; tolerate?: string[]; query?: boolean },
  ): Promise<{ json: Record<string, unknown>; tolerated?: string }> {
    const label = `Slack ${method}`;
    const headers: Record<string, string> = { Authorization: `Bearer ${cfg.token}` };
    let url = `${base}/${method}`;
    const init: RequestInit = { method: o.query ? "GET" : "POST", headers };
    if (o.query) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(payload)) if (v !== undefined) q.set(k, String(v));
      if ([...q].length) url += `?${q.toString()}`;
    } else {
      headers["Content-Type"] = "application/json; charset=utf-8";
      init.body = JSON.stringify(payload);
    }
    const res = await send(f, url, init, { label, mutating: o.mutating, secrets, timeoutMs });
    if (!res.ok) throw new HttpError(`${label} failed with status ${res.status}: ${snippet(res, secrets)}`, res.status);
    const json = asRecord(res.json);
    if (json.ok !== true) {
      const err = typeof json.error === "string" ? json.error : "unknown_error";
      if (o.tolerate?.includes(err)) return { json, tolerated: err };
      throw new Error(redact(`${label} failed: ${err}`, secrets));
    }
    return { json };
  }

  const channel = { type: "string", description: "Channel ID such as C0123456789" };
  const tsProp = { type: "string", description: "Message timestamp such as 1712345678.000100" };
  const emoji = { type: "string", description: "Emoji name without colons" };

  return defineConnector("slack", [
    {
      name: "list_channels",
      description: "List channels the bot can see.",
      effect: "read_only",
      permission: "slack:channels:read",
      properties: {
        limit: { type: "integer", minimum: 1, maximum: 1000 },
        cursor: { type: "string" },
        types: { type: "string", description: "Comma-separated, e.g. public_channel,private_channel" },
      },
      handler: async (args) => {
        const limit = optPosInt(args, "limit");
        if (limit !== undefined && limit > 1000) throw new Error("`limit` must be at most 1000");
        const types = optMatches(args, "types", /^[a-z_]+(,[a-z_]+)*$/, "channel type list");
        const { json } = await call(
          "conversations.list",
          { limit, cursor: optStr(args, "cursor", { max: 512 }), types },
          { mutating: false, query: true },
        );
        const channels = (Array.isArray(json.channels) ? json.channels : []).map((c) => {
          const r = asRecord(c);
          return { id: r.id, name: r.name, is_private: r.is_private === true, is_archived: r.is_archived === true };
        });
        const next = asRecord(json.response_metadata).next_cursor;
        return { channels, next_cursor: typeof next === "string" && next ? next : null };
      },
    },
    {
      name: "post_message",
      description: "Post a message. Rollback deletes it (the bot can only delete its own messages).",
      effect: "reversible",
      permission: "slack:messages:write",
      compensation: {
        tool: "delete_message",
        argument_map: { channel: "$result.channel", ts: "$result.ts" },
      },
      properties: { channel, text: { type: "string" }, thread_ts: tsProp },
      required: ["channel", "text"],
      handler: async (args) => {
        const payload: Record<string, unknown> = {
          channel: matches(args, "channel", CHANNEL, "channel ID"),
          text: str(args, "text", { max: 40000 }),
        };
        const thread = optMatches(args, "thread_ts", TS, "message timestamp");
        if (thread) payload.thread_ts = thread;
        const { json } = await call("chat.postMessage", payload, { mutating: true });
        if (typeof json.ts !== "string" || typeof json.channel !== "string") {
          throw new Error("Slack response had no message timestamp");
        }
        return { channel: json.channel, ts: json.ts };
      },
    },
    {
      name: "delete_message",
      description: "Delete a message. A message that is already gone counts as success.",
      effect: "idempotent",
      permission: "slack:messages:delete",
      properties: { channel, ts: tsProp },
      required: ["channel", "ts"],
      handler: async (args) => {
        const channelId = matches(args, "channel", CHANNEL, "channel ID");
        const ts = matches(args, "ts", TS, "message timestamp");
        const r = await call("chat.delete", { channel: channelId, ts }, { mutating: true, tolerate: ["message_not_found"] });
        return { channel: channelId, ts, deleted: r.tolerated === undefined };
      },
    },
    {
      name: "add_reaction",
      description: "React to a message. Rollback removes the reaction.",
      effect: "reversible",
      permission: "slack:reactions:write",
      compensation: {
        tool: "remove_reaction",
        argument_map: { channel: "$args.channel", timestamp: "$args.timestamp", name: "$args.name" },
      },
      properties: { channel, timestamp: tsProp, name: emoji },
      required: ["channel", "timestamp", "name"],
      handler: async (args) => {
        const payload = {
          channel: matches(args, "channel", CHANNEL, "channel ID"),
          timestamp: matches(args, "timestamp", TS, "message timestamp"),
          name: matches(args, "name", EMOJI, "emoji name"),
        };
        const r = await call("reactions.add", payload, { mutating: true, tolerate: ["already_reacted"] });
        return { ...payload, added: r.tolerated === undefined };
      },
    },
    {
      name: "remove_reaction",
      description: "Remove the bot's reaction. A reaction or message that is already gone counts as success.",
      effect: "idempotent",
      permission: "slack:reactions:write",
      properties: { channel, timestamp: tsProp, name: emoji },
      required: ["channel", "timestamp", "name"],
      handler: async (args) => {
        const payload = {
          channel: matches(args, "channel", CHANNEL, "channel ID"),
          timestamp: matches(args, "timestamp", TS, "message timestamp"),
          name: matches(args, "name", EMOJI, "emoji name"),
        };
        const r = await call("reactions.remove", payload, {
          mutating: true,
          tolerate: ["no_reaction", "message_not_found"],
        });
        return { ...payload, removed: r.tolerated === undefined };
      },
    },
  ]);
}
