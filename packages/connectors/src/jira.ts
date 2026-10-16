import {
  HttpError,
  asRecord,
  defineConnector,
  matches,
  optStr,
  redact,
  send,
  snippet,
  str,
  type Connector,
  type Fetch,
} from "./common.js";

export interface JiraConfig {
  /** Site root such as https://yourco.atlassian.net */
  baseUrl: string;
  email: string;
  apiToken: string;
  fetch?: Fetch;
  timeoutMs?: number;
}

const ISSUE_KEY = /^[A-Z][A-Z0-9_]{1,9}-\d{1,9}$/;
const PROJECT_KEY = /^[A-Z][A-Z0-9_]{1,9}$/;
const NUMERIC_ID = /^\d{1,18}$/;

/** Atlassian Document Format for plain text: one paragraph per line. */
function adf(text: string): unknown {
  return {
    type: "doc",
    version: 1,
    content: text.split("\n").map((line) => ({
      type: "paragraph",
      content: line ? [{ type: "text", text: line }] : [],
    })),
  };
}

export function createJiraConnector(cfg: JiraConfig): Connector {
  if (!cfg.baseUrl) throw new Error("jira connector needs a `baseUrl`");
  if (!cfg.email) throw new Error("jira connector needs an `email`");
  if (!cfg.apiToken) throw new Error("jira connector needs an `apiToken`");
  const f = cfg.fetch ?? fetch;
  const base = cfg.baseUrl.replace(/\/+$/, "");
  let parsed: URL;
  try {
    parsed = new URL(base);
  } catch {
    throw new Error("jira `baseUrl` must be an http(s) URL");
  }
  if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error("jira `baseUrl` must be an http(s) URL without credentials");
  }
  const basic = Buffer.from(`${cfg.email}:${cfg.apiToken}`).toString("base64");
  const secrets = [cfg.apiToken, basic];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  async function api(
    method: "GET" | "POST" | "DELETE",
    p: string,
    opts: { body?: unknown; tolerate?: number[] } = {},
  ): Promise<{ status: number; json: Record<string, unknown> }> {
    const label = `Jira ${method} ${p.split("?")[0]}`;
    const res = await send(
      f,
      `${base}/rest/api/3${p}`,
      {
        method,
        headers: {
          Authorization: `Basic ${basic}`,
          Accept: "application/json",
          ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      },
      { label, mutating: method !== "GET", secrets, timeoutMs },
    );
    if (!res.ok && !(opts.tolerate ?? []).includes(res.status)) {
      let msg = snippet(res, secrets);
      const messages = asRecord(res.json).errorMessages;
      if (Array.isArray(messages) && messages.length > 0) msg = redact(String(messages[0]), secrets).slice(0, 200);
      throw new HttpError(`${label} failed with status ${res.status}: ${msg}`, res.status);
    }
    return { status: res.status, json: asRecord(res.json) };
  }

  const keyProp = { type: "string", description: "Issue key such as PROJ-123" };
  const statusOf = (issue: Record<string, unknown>) => {
    const s = asRecord(asRecord(issue.fields).status);
    return { id: typeof s.id === "string" ? s.id : null, name: typeof s.name === "string" ? s.name : null };
  };

  return defineConnector("jira", [
    {
      name: "get_issue",
      description: "Read an issue's summary and status.",
      effect: "read_only",
      permission: "jira:issues:read",
      properties: { issue_key: keyProp },
      required: ["issue_key"],
      handler: async (args) => {
        const key = matches(args, "issue_key", ISSUE_KEY, "issue key");
        const { json } = await api("GET", `/issue/${key}?fields=summary,status`);
        const st = statusOf(json);
        return { issue_key: key, summary: asRecord(json.fields).summary ?? null, status: st.name, status_id: st.id };
      },
    },
    {
      name: "create_issue",
      description: "Create an issue. Rollback deletes it.",
      effect: "reversible",
      permission: "jira:issues:write",
      compensation: { tool: "delete_issue", argument_map: { issue_key: "$result.issue_key" } },
      properties: {
        project_key: { type: "string" },
        summary: { type: "string" },
        issue_type: { type: "string", description: "Issue type name, default Task" },
        description: { type: "string", description: "Plain text" },
      },
      required: ["project_key", "summary"],
      handler: async (args) => {
        const fields: Record<string, unknown> = {
          project: { key: matches(args, "project_key", PROJECT_KEY, "project key") },
          summary: str(args, "summary", { max: 255 }),
          issuetype: { name: optStr(args, "issue_type", { max: 60 }) ?? "Task" },
        };
        const description = optStr(args, "description", { max: 32000 });
        if (description !== undefined) fields.description = adf(description);
        const { json } = await api("POST", "/issue", { body: { fields } });
        if (typeof json.key !== "string") throw new Error("Jira response had no issue key");
        return { issue_key: json.key, issue_id: json.id ?? null };
      },
    },
    {
      name: "delete_issue",
      description:
        "Delete an issue permanently (subtasks are not deleted, Jira refuses if there are any). An issue that is already gone counts as success. Used to undo create_issue; deletion cannot be undone, so withhold this permission from agents.",
      effect: "idempotent",
      permission: "jira:issues:delete",
      properties: { issue_key: keyProp },
      required: ["issue_key"],
      handler: async (args) => {
        const key = matches(args, "issue_key", ISSUE_KEY, "issue key");
        const r = await api("DELETE", `/issue/${key}?deleteSubtasks=false`, { tolerate: [404] });
        return { issue_key: key, deleted: r.status !== 404 };
      },
    },
    {
      name: "add_comment",
      description: "Comment on an issue. Rollback deletes the comment.",
      effect: "reversible",
      permission: "jira:comments:write",
      compensation: {
        tool: "delete_comment",
        argument_map: { issue_key: "$args.issue_key", comment_id: "$result.comment_id" },
      },
      properties: { issue_key: keyProp, body: { type: "string", description: "Plain text" } },
      required: ["issue_key", "body"],
      handler: async (args) => {
        const key = matches(args, "issue_key", ISSUE_KEY, "issue key");
        const { json } = await api("POST", `/issue/${key}/comment`, { body: { body: adf(str(args, "body", { max: 32000 })) } });
        if (typeof json.id !== "string") throw new Error("Jira response had no comment id");
        return { comment_id: json.id };
      },
    },
    {
      name: "delete_comment",
      description: "Delete a comment. A comment that is already gone counts as success.",
      effect: "idempotent",
      permission: "jira:comments:write",
      properties: { issue_key: keyProp, comment_id: { type: "string" } },
      required: ["issue_key", "comment_id"],
      handler: async (args) => {
        const key = matches(args, "issue_key", ISSUE_KEY, "issue key");
        const id = matches(args, "comment_id", NUMERIC_ID, "comment id");
        const r = await api("DELETE", `/issue/${key}/comment/${id}`, { tolerate: [404] });
        return { comment_id: id, deleted: r.status !== 404 };
      },
    },
    {
      name: "transition_issue",
      description:
        "Move an issue through a workflow transition (by transition id or name, or the name of the status it leads to). The previous status is read first and returned; rollback transitions back to it if the workflow allows that.",
      effect: "compensable",
      permission: "jira:issues:transition",
      compensation: {
        tool: "restore_status",
        argument_map: { issue_key: "$args.issue_key", status_id: "$result.previous_status_id" },
      },
      properties: {
        issue_key: keyProp,
        transition: { type: "string", description: "Transition id, transition name, or target status name" },
      },
      required: ["issue_key", "transition"],
      handler: async (args) => {
        const key = matches(args, "issue_key", ISSUE_KEY, "issue key");
        const wanted = str(args, "transition", { max: 100 });
        const before = statusOf((await api("GET", `/issue/${key}?fields=status`)).json);
        if (before.id === null) throw new Error("Jira response had no status");
        const list = (await api("GET", `/issue/${key}/transitions`)).json.transitions;
        const options = (Array.isArray(list) ? list : []).map(asRecord);
        const lower = wanted.toLowerCase();
        const match =
          options.find((t) => t.id === wanted) ??
          options.find((t) => String(t.name ?? "").toLowerCase() === lower) ??
          options.find((t) => String(asRecord(t.to).name ?? "").toLowerCase() === lower);
        if (!match || typeof match.id !== "string") {
          throw new Error(`no transition \`${wanted}\` is available from status ${before.name ?? before.id}`);
        }
        await api("POST", `/issue/${key}/transitions`, { body: { transition: { id: match.id } } });
        const to = asRecord(match.to);
        return {
          issue_key: key,
          previous_status: before.name,
          previous_status_id: before.id,
          status: to.name ?? null,
          status_id: to.id ?? null,
        };
      },
    },
    {
      name: "restore_status",
      description:
        "Move an issue back to a status by finding a transition that leads to it. Succeeds without changes if the issue is already there; fails if the workflow has no such transition. Used to undo transition_issue.",
      effect: "idempotent",
      permission: "jira:issues:transition",
      properties: { issue_key: keyProp, status_id: { type: "string" } },
      required: ["issue_key", "status_id"],
      handler: async (args) => {
        const key = matches(args, "issue_key", ISSUE_KEY, "issue key");
        const statusId = matches(args, "status_id", NUMERIC_ID, "status id");
        const now = statusOf((await api("GET", `/issue/${key}?fields=status`)).json);
        if (now.id === statusId) return { issue_key: key, status_id: statusId, moved: false };
        const list = (await api("GET", `/issue/${key}/transitions`)).json.transitions;
        const match = (Array.isArray(list) ? list : []).map(asRecord).find((t) => asRecord(t.to).id === statusId);
        if (!match || typeof match.id !== "string") {
          throw new Error(`the workflow has no transition from status ${now.name ?? now.id} back to status ${statusId}`);
        }
        await api("POST", `/issue/${key}/transitions`, { body: { transition: { id: match.id } } });
        return { issue_key: key, status_id: statusId, moved: true };
      },
    },
  ]);
}
