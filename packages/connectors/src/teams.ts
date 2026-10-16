import {
  HttpError,
  asRecord,
  defineConnector,
  matches,
  optPosInt,
  optMatches,
  send,
  snippet,
  str,
  type Connector,
  type Fetch,
} from "./common.js";

export interface TeamsConfig {
  /** A Microsoft Graph access token (delegated for sending and deleting messages). */
  token: string;
  fetch?: Fetch;
  baseUrl?: string;
  timeoutMs?: number;
}

const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const CHANNEL = /^19:[A-Za-z0-9_.@=-]{1,200}$/;
const MESSAGE = /^\d{8,20}$/;

export function createTeamsConnector(cfg: TeamsConfig): Connector {
  if (!cfg.token) throw new Error("teams connector needs a `token`");
  const f = cfg.fetch ?? fetch;
  const base = (cfg.baseUrl ?? "https://graph.microsoft.com/v1.0").replace(/\/+$/, "");
  const secrets = [cfg.token];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  async function api(
    method: "GET" | "POST",
    p: string,
    opts: { body?: unknown; tolerate?: number[] } = {},
  ): Promise<{ status: number; json: Record<string, unknown> }> {
    const label = `Graph ${method} ${p}`;
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

  const channelPath = (args: Record<string, unknown>) => {
    const team = matches(args, "team_id", GUID, "team ID (GUID)");
    const channel = matches(args, "channel_id", CHANNEL, "channel ID such as 19:...@thread.tacv2");
    return { team, channel, p: `/teams/${team}/channels/${encodeURIComponent(channel)}` };
  };

  const team = { type: "string", description: "Team (group) ID, a GUID" };
  const channel = { type: "string", description: "Channel ID such as 19:abc@thread.tacv2" };

  return defineConnector("teams", [
    {
      name: "list_channels",
      description: "List the channels of a team. Needs Channel.ReadBasic.All.",
      effect: "read_only",
      permission: "teams:channels:read",
      properties: { team_id: team, top: { type: "integer", minimum: 1, maximum: 999 } },
      required: ["team_id"],
      handler: async (args) => {
        const teamId = matches(args, "team_id", GUID, "team ID (GUID)");
        const top = optPosInt(args, "top");
        if (top !== undefined && top > 999) throw new Error("`top` must be at most 999");
        const { json } = await api("GET", `/teams/${teamId}/channels${top ? `?$top=${top}` : ""}`);
        const channels = (Array.isArray(json.value) ? json.value : []).map((c) => {
          const r = asRecord(c);
          return { id: r.id, display_name: r.displayName, membership_type: r.membershipType ?? null };
        });
        const next = json["@odata.nextLink"];
        return { channels, next_link: typeof next === "string" ? next : null };
      },
    },
    {
      name: "post_message",
      description:
        "Post a message to a channel as the signed-in user. Needs the delegated ChannelMessage.Send permission. Rollback soft-deletes it.",
      effect: "reversible",
      permission: "teams:messages:write",
      compensation: {
        tool: "delete_message",
        argument_map: { team_id: "$args.team_id", channel_id: "$args.channel_id", message_id: "$result.message_id" },
      },
      properties: {
        team_id: team,
        channel_id: channel,
        content: { type: "string" },
        content_type: { type: "string", enum: ["text", "html"] },
      },
      required: ["team_id", "channel_id", "content"],
      handler: async (args) => {
        const { p, team: t, channel: c } = channelPath(args);
        const contentType = optMatches(args, "content_type", /^(text|html)$/, "content type (text or html)") ?? "text";
        const { json } = await api("POST", `${p}/messages`, {
          body: { body: { contentType, content: str(args, "content", { max: 28000 }) } },
        });
        if (typeof json.id !== "string") throw new Error("Graph response had no message id");
        return { team_id: t, channel_id: c, message_id: json.id, web_url: json.webUrl ?? null };
      },
    },
    {
      name: "delete_message",
      description:
        "Soft-delete a channel message (POST .../softDelete). Needs the delegated ChannelMessage.ReadWrite permission and only works on messages the signed-in user may delete. A message that is already gone counts as success.",
      effect: "idempotent",
      permission: "teams:messages:delete",
      properties: { team_id: team, channel_id: channel, message_id: { type: "string" } },
      required: ["team_id", "channel_id", "message_id"],
      handler: async (args) => {
        const { p } = channelPath(args);
        const id = matches(args, "message_id", MESSAGE, "message ID");
        const r = await api("POST", `${p}/messages/${id}/softDelete`, { tolerate: [404] });
        return { message_id: id, deleted: r.status !== 404 };
      },
    },
  ]);
}
