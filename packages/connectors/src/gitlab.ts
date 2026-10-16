import {
  HttpError,
  asRecord,
  defineConnector,
  matches,
  optStr,
  optStrList,
  posInt,
  send,
  snippet,
  str,
  type Connector,
  type Fetch,
} from "./common.js";

export interface GitlabConfig {
  token: string;
  fetch?: Fetch;
  /** Instance root such as https://gitlab.example.com (self-hosted). Default https://gitlab.com. `/api/v4` is added. */
  baseUrl?: string;
  timeoutMs?: number;
}

const PROJECT = /^(\d{1,20}|[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)+)$/;

function branchName(args: Record<string, unknown>, key: string): string {
  const v = str(args, key, { max: 250 });
  if (
    !/^[A-Za-z0-9._/-]+$/.test(v) ||
    v.includes("..") ||
    v.includes("//") ||
    v.startsWith("/") ||
    v.endsWith("/") ||
    v.endsWith(".lock") ||
    v.endsWith(".") ||
    v.startsWith("-")
  ) {
    throw new Error(`\`${key}\` is not a valid branch name`);
  }
  return v;
}

export function createGitlabConnector(cfg: GitlabConfig): Connector {
  if (!cfg.token) throw new Error("gitlab connector needs a `token`");
  const f = cfg.fetch ?? fetch;
  let base = (cfg.baseUrl ?? "https://gitlab.com").replace(/\/+$/, "");
  if (!base.endsWith("/api/v4")) base += "/api/v4";
  const secrets = [cfg.token];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  async function api(
    method: "GET" | "POST" | "PUT" | "DELETE",
    p: string,
    opts: { body?: unknown; tolerate?: number[] } = {},
  ): Promise<{ status: number; json: Record<string, unknown> }> {
    const label = `GitLab ${method} ${p}`;
    const res = await send(
      f,
      base + p,
      {
        method,
        headers: {
          "PRIVATE-TOKEN": cfg.token,
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

  const projectOf = (args: Record<string, unknown>) => {
    const project = matches(args, "project", PROJECT, "project id or path");
    if (project.split("/").some((s) => s === "." || s === "..")) throw new Error("`project` is not a valid project id or path");
    return { project, p: `/projects/${encodeURIComponent(project)}` };
  };

  const target = { project: { type: "string", description: "Numeric project ID or full path such as group/project" } };
  const iid = { type: "integer", minimum: 1, description: "Issue IID (the number shown in the project)" };

  return defineConnector("gitlab", [
    {
      name: "get_issue",
      description: "Read an issue.",
      effect: "read_only",
      permission: "gitlab:issues:read",
      properties: { ...target, issue_iid: iid },
      required: ["project", "issue_iid"],
      handler: async (args) => {
        const { p } = projectOf(args);
        const n = posInt(args, "issue_iid");
        const { json } = await api("GET", `${p}/issues/${n}`);
        return {
          issue_iid: n,
          title: json.title,
          state: json.state,
          description: json.description ?? null,
          labels: Array.isArray(json.labels) ? json.labels : [],
          web_url: json.web_url,
        };
      },
    },
    {
      name: "create_issue",
      description: "Open an issue. Rollback closes it.",
      effect: "reversible",
      permission: "gitlab:issues:write",
      compensation: {
        tool: "close_issue",
        argument_map: { project: "$result.project", issue_iid: "$result.issue_iid" },
      },
      properties: {
        ...target,
        title: { type: "string" },
        description: { type: "string" },
        labels: { type: "array", items: { type: "string" } },
      },
      required: ["project", "title"],
      handler: async (args) => {
        const { project, p } = projectOf(args);
        const body: Record<string, unknown> = { title: str(args, "title", { max: 255 }) };
        const description = optStr(args, "description", { max: 1000000 });
        if (description !== undefined) body.description = description;
        const labels = optStrList(args, "labels");
        if (labels) body.labels = labels.join(",");
        const { json } = await api("POST", `${p}/issues`, { body });
        if (typeof json.iid !== "number") throw new Error("GitLab response had no issue iid");
        return { project, issue_iid: json.iid, web_url: json.web_url, state: json.state };
      },
    },
    {
      name: "close_issue",
      description: "Close an issue. Closing a closed issue succeeds.",
      effect: "idempotent",
      permission: "gitlab:issues:write",
      properties: { ...target, issue_iid: iid },
      required: ["project", "issue_iid"],
      handler: async (args) => {
        const { p } = projectOf(args);
        const n = posInt(args, "issue_iid");
        const { json } = await api("PUT", `${p}/issues/${n}`, { body: { state_event: "close" } });
        return { issue_iid: n, state: json.state ?? "closed" };
      },
    },
    {
      name: "add_note",
      description: "Comment on an issue. Rollback deletes the note.",
      effect: "reversible",
      permission: "gitlab:issues:write",
      compensation: {
        tool: "delete_note",
        argument_map: { project: "$args.project", issue_iid: "$args.issue_iid", note_id: "$result.note_id" },
      },
      properties: { ...target, issue_iid: iid, body: { type: "string" } },
      required: ["project", "issue_iid", "body"],
      handler: async (args) => {
        const { p } = projectOf(args);
        const n = posInt(args, "issue_iid");
        const { json } = await api("POST", `${p}/issues/${n}/notes`, { body: { body: str(args, "body", { max: 1000000 }) } });
        if (typeof json.id !== "number") throw new Error("GitLab response had no note id");
        return { note_id: json.id };
      },
    },
    {
      name: "delete_note",
      description: "Delete an issue note. A note that is already gone counts as success.",
      effect: "idempotent",
      permission: "gitlab:issues:write",
      properties: { ...target, issue_iid: iid, note_id: { type: "integer", minimum: 1 } },
      required: ["project", "issue_iid", "note_id"],
      handler: async (args) => {
        const { p } = projectOf(args);
        const n = posInt(args, "issue_iid");
        const id = posInt(args, "note_id");
        const r = await api("DELETE", `${p}/issues/${n}/notes/${id}`, { tolerate: [404] });
        return { note_id: id, deleted: r.status !== 404 };
      },
    },
    {
      name: "create_branch",
      description: "Create a branch from a branch, tag or commit. Rollback deletes the branch.",
      effect: "reversible",
      permission: "gitlab:branch:write",
      compensation: {
        tool: "delete_branch",
        argument_map: { project: "$args.project", branch: "$args.branch" },
      },
      properties: { ...target, branch: { type: "string" }, ref: { type: "string", description: "Branch, tag or commit SHA to branch from" } },
      required: ["project", "branch", "ref"],
      handler: async (args) => {
        const { p } = projectOf(args);
        const branch = branchName(args, "branch");
        const ref = str(args, "ref", { max: 250 });
        const { json } = await api("POST", `${p}/repository/branches`, { body: { branch, ref } });
        return { branch, commit: asRecord(json.commit).id ?? null };
      },
    },
    {
      name: "delete_branch",
      description:
        "Delete a branch. A branch that is already gone counts as success. Used to undo create_branch; deleting a branch with commits loses them unless you keep the SHA, so withhold this permission from agents.",
      effect: "idempotent",
      permission: "gitlab:branch:delete",
      properties: { ...target, branch: { type: "string" } },
      required: ["project", "branch"],
      handler: async (args) => {
        const { p } = projectOf(args);
        const branch = branchName(args, "branch");
        const r = await api("DELETE", `${p}/repository/branches/${encodeURIComponent(branch)}`, { tolerate: [404] });
        return { branch, deleted: r.status !== 404 };
      },
    },
  ]);
}
