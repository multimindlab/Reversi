import {
  HttpError,
  asRecord,
  defineConnector,
  matches,
  optStr,
  optStrList,
  posInt,
  redact,
  send,
  snippet,
  str,
  strList,
  type Connector,
  type Fetch,
} from "./common.js";

export interface GithubConfig {
  token: string;
  fetch?: Fetch;
  baseUrl?: string;
  timeoutMs?: number;
}

const NAME = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;

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

export function createGithubConnector(cfg: GithubConfig): Connector {
  if (!cfg.token) throw new Error("github connector needs a `token`");
  const f = cfg.fetch ?? fetch;
  const base = (cfg.baseUrl ?? "https://api.github.com").replace(/\/+$/, "");
  const secrets = [cfg.token];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  async function api(
    method: "GET" | "POST" | "PATCH" | "DELETE",
    p: string,
    opts: { body?: unknown; tolerate?: number[] } = {},
  ): Promise<{ status: number; json: Record<string, unknown> }> {
    const label = `GitHub ${method} ${p}`;
    const res = await send(
      f,
      base + p,
      {
        method,
        headers: {
          Authorization: `Bearer ${cfg.token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "reversi-connectors",
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

  const repoOf = (args: Record<string, unknown>) => {
    const owner = matches(args, "owner", NAME, "owner name");
    const repo = matches(args, "repo", NAME, "repository name");
    return { owner, repo, p: `/repos/${owner}/${repo}` };
  };
  const labelNames = (j: unknown): string[] =>
    (Array.isArray(j) ? j : [])
      .map((l) => (typeof l === "string" ? l : asRecord(l).name))
      .filter((n): n is string => typeof n === "string");

  const target = {
    owner: { type: "string" },
    repo: { type: "string" },
  };
  const issueNo = { type: "integer", minimum: 1 };

  return defineConnector("github", [
    {
      name: "get_issue",
      description: "Read an issue.",
      effect: "read_only",
      permission: "github:issues:read",
      properties: { ...target, issue_number: issueNo },
      required: ["owner", "repo", "issue_number"],
      handler: async (args) => {
        const { p } = repoOf(args);
        const n = posInt(args, "issue_number");
        const { json } = await api("GET", `${p}/issues/${n}`);
        return {
          issue_number: n,
          title: json.title,
          state: json.state,
          body: json.body ?? null,
          labels: labelNames(json.labels),
          html_url: json.html_url,
        };
      },
    },
    {
      name: "create_issue",
      description: "Open an issue. Rollback closes it (GitHub issues cannot be deleted through the API).",
      effect: "reversible",
      permission: "github:issues:write",
      compensation: {
        tool: "close_issue",
        argument_map: { owner: "$args.owner", repo: "$args.repo", issue_number: "$result.issue_number" },
      },
      properties: {
        ...target,
        title: { type: "string" },
        body: { type: "string" },
        labels: { type: "array", items: { type: "string" } },
        assignees: { type: "array", items: { type: "string" } },
      },
      required: ["owner", "repo", "title"],
      handler: async (args) => {
        const { p } = repoOf(args);
        const body: Record<string, unknown> = { title: str(args, "title", { max: 256 }) };
        const text = optStr(args, "body", { max: 65536 });
        if (text !== undefined) body.body = text;
        const labels = optStrList(args, "labels");
        if (labels) body.labels = labels;
        const assignees = optStrList(args, "assignees");
        if (assignees) body.assignees = assignees;
        const { json } = await api("POST", `${p}/issues`, { body });
        if (typeof json.number !== "number") throw new Error("GitHub response had no issue number");
        return { issue_number: json.number, html_url: json.html_url, state: json.state };
      },
    },
    {
      name: "close_issue",
      description: "Close an issue. Closing a closed issue succeeds.",
      effect: "idempotent",
      permission: "github:issues:write",
      properties: { ...target, issue_number: issueNo },
      required: ["owner", "repo", "issue_number"],
      handler: async (args) => {
        const { p } = repoOf(args);
        const n = posInt(args, "issue_number");
        const { json } = await api("PATCH", `${p}/issues/${n}`, {
          body: { state: "closed", state_reason: "not_planned" },
        });
        return { issue_number: n, state: json.state ?? "closed" };
      },
    },
    {
      name: "add_comment",
      description: "Comment on an issue or pull request. Rollback deletes the comment.",
      effect: "reversible",
      permission: "github:issues:write",
      compensation: {
        tool: "delete_comment",
        argument_map: { owner: "$args.owner", repo: "$args.repo", comment_id: "$result.comment_id" },
      },
      properties: { ...target, issue_number: issueNo, body: { type: "string" } },
      required: ["owner", "repo", "issue_number", "body"],
      handler: async (args) => {
        const { p } = repoOf(args);
        const n = posInt(args, "issue_number");
        const { json } = await api("POST", `${p}/issues/${n}/comments`, {
          body: { body: str(args, "body", { max: 65536 }) },
        });
        if (typeof json.id !== "number") throw new Error("GitHub response had no comment id");
        return { comment_id: json.id, html_url: json.html_url };
      },
    },
    {
      name: "delete_comment",
      description: "Delete an issue comment. A comment that is already gone counts as success.",
      effect: "idempotent",
      permission: "github:issues:write",
      properties: { ...target, comment_id: { type: "integer", minimum: 1 } },
      required: ["owner", "repo", "comment_id"],
      handler: async (args) => {
        const { p } = repoOf(args);
        const id = posInt(args, "comment_id");
        const r = await api("DELETE", `${p}/issues/comments/${id}`, { tolerate: [404] });
        return { comment_id: id, deleted: r.status !== 404 };
      },
    },
    {
      name: "create_branch",
      description: "Create a branch pointing at an existing commit. Rollback deletes the branch.",
      effect: "reversible",
      permission: "github:branch:write",
      compensation: {
        tool: "delete_branch",
        argument_map: { owner: "$args.owner", repo: "$args.repo", branch: "$args.branch" },
      },
      properties: { ...target, branch: { type: "string" }, sha: { type: "string", description: "Commit SHA" } },
      required: ["owner", "repo", "branch", "sha"],
      handler: async (args) => {
        const { p } = repoOf(args);
        const branch = branchName(args, "branch");
        const sha = matches(args, "sha", /^[0-9a-f]{40}$/i, "40-character commit SHA");
        const { json } = await api("POST", `${p}/git/refs`, { body: { ref: `refs/heads/${branch}`, sha } });
        return { branch, sha: asRecord(json.object).sha ?? sha, ref: json.ref ?? `refs/heads/${branch}` };
      },
    },
    {
      name: "delete_branch",
      description:
        "Delete a branch. A branch that is already gone counts as success. Used to undo create_branch; deleting a branch with commits loses them unless you keep the SHA, so withhold this permission from agents.",
      effect: "idempotent",
      permission: "github:branch:delete",
      properties: { ...target, branch: { type: "string" } },
      required: ["owner", "repo", "branch"],
      handler: async (args) => {
        const { p } = repoOf(args);
        const branch = branchName(args, "branch");
        const ref = branch.split("/").map(encodeURIComponent).join("/");
        const r = await api("DELETE", `${p}/git/refs/heads/${ref}`, { tolerate: [404, 422] });
        if (r.status === 422 && !/does not exist/i.test(String(r.json.message ?? ""))) {
          throw new HttpError(
            `GitHub DELETE ${p}/git/refs/heads/${ref} failed with status 422: ${redact(String(r.json.message ?? ""), secrets)}`,
            422,
          );
        }
        return { branch, deleted: r.status >= 200 && r.status < 300 };
      },
    },
    {
      name: "add_labels",
      description:
        "Add labels to an issue. Only labels that were not already on the issue are reported as `added`, so rollback never removes a label that was there before.",
      effect: "reversible",
      permission: "github:issues:write",
      compensation: {
        tool: "remove_labels",
        argument_map: {
          owner: "$args.owner",
          repo: "$args.repo",
          issue_number: "$args.issue_number",
          labels: "$result.added",
        },
      },
      properties: { ...target, issue_number: issueNo, labels: { type: "array", items: { type: "string" }, minItems: 1 } },
      required: ["owner", "repo", "issue_number", "labels"],
      handler: async (args) => {
        const { p } = repoOf(args);
        const n = posInt(args, "issue_number");
        const labels = strList(args, "labels");
        const current = await api("GET", `${p}/issues/${n}`);
        const existing = new Set(labelNames(current.json.labels));
        const added = [...new Set(labels)].filter((l) => !existing.has(l));
        if (added.length > 0) await api("POST", `${p}/issues/${n}/labels`, { body: { labels: added } });
        return { issue_number: n, added };
      },
    },
    {
      name: "remove_labels",
      description: "Remove labels from an issue. Labels that are not on the issue count as success.",
      effect: "idempotent",
      permission: "github:issues:write",
      properties: { ...target, issue_number: issueNo, labels: { type: "array", items: { type: "string" } } },
      required: ["owner", "repo", "issue_number", "labels"],
      handler: async (args) => {
        const { p } = repoOf(args);
        const n = posInt(args, "issue_number");
        const labels = strList(args, "labels", { allowEmpty: true });
        const removed: string[] = [];
        for (const l of labels) {
          const r = await api("DELETE", `${p}/issues/${n}/labels/${encodeURIComponent(l)}`, { tolerate: [404] });
          if (r.status !== 404) removed.push(l);
        }
        return { issue_number: n, removed };
      },
    },
  ]);
}
