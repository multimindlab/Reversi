import {
  HttpError,
  asRecord,
  defineConnector,
  matches,
  optPosInt,
  optStr,
  redact,
  send,
  snippet,
  str,
  type Connector,
  type Fetch,
} from "./common.js";

export interface LinearConfig {
  /** A personal API key (sent as-is in `Authorization`), or an OAuth token prefixed with `Bearer `. */
  apiKey: string;
  fetch?: Fetch;
  baseUrl?: string;
  timeoutMs?: number;
}

const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const ISSUE_REF = /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z][A-Za-z0-9]{0,9}-\d{1,9})$/;

export function createLinearConnector(cfg: LinearConfig): Connector {
  if (!cfg.apiKey) throw new Error("linear connector needs an `apiKey`");
  const f = cfg.fetch ?? fetch;
  const url = (cfg.baseUrl ?? "https://api.linear.app/graphql").replace(/\/+$/, "");
  const secrets = [cfg.apiKey, cfg.apiKey.replace(/^Bearer\s+/i, "")];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  /** One GraphQL operation. `tolerateNotFound` turns an "Entity not found" error into `notFound: true`. */
  async function gql(
    op: string,
    query: string,
    variables: Record<string, unknown>,
    o: { mutating: boolean; tolerateNotFound?: boolean },
  ): Promise<{ data: Record<string, unknown>; notFound: boolean }> {
    const label = `Linear ${op}`;
    const res = await send(
      f,
      url,
      {
        method: "POST",
        headers: { Authorization: cfg.apiKey, "Content-Type": "application/json" },
        body: JSON.stringify({ query, variables }),
      },
      { label, mutating: o.mutating, secrets, timeoutMs },
    );
    const body = asRecord(res.json);
    const errors = Array.isArray(body.errors) ? body.errors : [];
    if (errors.length > 0) {
      const first = asRecord(errors[0]);
      const message = redact(String(first.message ?? "unknown error"), secrets);
      if (o.tolerateNotFound && /entity not found|not found/i.test(message)) return { data: {}, notFound: true };
      throw new HttpError(`${label} failed with status ${res.status}: ${message}`, res.status);
    }
    if (!res.ok) throw new HttpError(`${label} failed with status ${res.status}: ${snippet(res, secrets)}`, res.status);
    return { data: asRecord(body.data), notFound: false };
  }

  const issueId = { type: "string", description: "Issue UUID" };
  const commentId = { type: "string", description: "Comment UUID" };

  return defineConnector("linear", [
    {
      name: "get_issue",
      description: "Read an issue by UUID or identifier such as ENG-123.",
      effect: "read_only",
      permission: "linear:issues:read",
      properties: { id: { type: "string", description: "Issue UUID or identifier such as ENG-123" } },
      required: ["id"],
      handler: async (args) => {
        const id = matches(args, "id", ISSUE_REF, "issue id or identifier");
        const { data } = await gql(
          "issue",
          "query Issue($id: String!) { issue(id: $id) { id identifier title description url archivedAt state { name } } }",
          { id },
          { mutating: false },
        );
        const i = asRecord(data.issue);
        if (typeof i.id !== "string") throw new Error("Linear response had no issue");
        return {
          issue_id: i.id,
          identifier: i.identifier,
          title: i.title,
          description: i.description ?? null,
          state: asRecord(i.state).name ?? null,
          archived: typeof i.archivedAt === "string",
          url: i.url,
        };
      },
    },
    {
      name: "create_issue",
      description: "Create an issue in a team. Rollback archives it.",
      effect: "reversible",
      permission: "linear:issues:write",
      compensation: { tool: "archive_issue", argument_map: { issue_id: "$result.issue_id" } },
      properties: {
        team_id: { type: "string", description: "Team UUID" },
        title: { type: "string" },
        description: { type: "string" },
        priority: { type: "integer", minimum: 1, maximum: 4, description: "1 urgent, 2 high, 3 normal, 4 low" },
      },
      required: ["team_id", "title"],
      handler: async (args) => {
        const input: Record<string, unknown> = {
          teamId: matches(args, "team_id", UUID, "team UUID"),
          title: str(args, "title", { max: 512 }),
        };
        const description = optStr(args, "description", { max: 100000 });
        if (description !== undefined) input.description = description;
        const priority = optPosInt(args, "priority");
        if (priority !== undefined) {
          if (priority > 4) throw new Error("`priority` must be between 1 and 4");
          input.priority = priority;
        }
        const { data } = await gql(
          "issueCreate",
          "mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url title } } }",
          { input },
          { mutating: true },
        );
        const r = asRecord(data.issueCreate);
        const issue = asRecord(r.issue);
        if (r.success !== true || typeof issue.id !== "string") throw new Error("Linear did not create the issue");
        return { issue_id: issue.id, identifier: issue.identifier, url: issue.url };
      },
    },
    {
      name: "archive_issue",
      description: "Archive an issue (issueArchive). An issue that is already archived or gone counts as success.",
      effect: "idempotent",
      permission: "linear:issues:write",
      properties: { issue_id: issueId },
      required: ["issue_id"],
      handler: async (args) => {
        const id = matches(args, "issue_id", UUID, "issue UUID");
        const cur = await gql(
          "issue",
          "query Issue($id: String!) { issue(id: $id) { id archivedAt } }",
          { id },
          { mutating: false, tolerateNotFound: true },
        );
        if (cur.notFound || typeof asRecord(cur.data.issue).archivedAt === "string") {
          return { issue_id: id, archived: false };
        }
        const { data } = await gql(
          "issueArchive",
          "mutation IssueArchive($id: String!) { issueArchive(id: $id) { success } }",
          { id },
          { mutating: true, tolerateNotFound: true },
        );
        const ok = asRecord(data.issueArchive).success;
        if (ok !== true && Object.keys(data).length > 0) throw new Error("Linear did not archive the issue");
        return { issue_id: id, archived: ok === true };
      },
    },
    {
      name: "add_comment",
      description: "Comment on an issue. Rollback deletes the comment.",
      effect: "reversible",
      permission: "linear:comments:write",
      compensation: { tool: "delete_comment", argument_map: { comment_id: "$result.comment_id" } },
      properties: { issue_id: issueId, body: { type: "string", description: "Markdown" } },
      required: ["issue_id", "body"],
      handler: async (args) => {
        const input = {
          issueId: matches(args, "issue_id", UUID, "issue UUID"),
          body: str(args, "body", { max: 100000 }),
        };
        const { data } = await gql(
          "commentCreate",
          "mutation CommentCreate($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id url } } }",
          { input },
          { mutating: true },
        );
        const r = asRecord(data.commentCreate);
        const c = asRecord(r.comment);
        if (r.success !== true || typeof c.id !== "string") throw new Error("Linear did not create the comment");
        return { comment_id: c.id, url: c.url ?? null };
      },
    },
    {
      name: "delete_comment",
      description: "Delete a comment (commentDelete). A comment that is already gone counts as success.",
      effect: "idempotent",
      permission: "linear:comments:write",
      properties: { comment_id: commentId },
      required: ["comment_id"],
      handler: async (args) => {
        const id = matches(args, "comment_id", UUID, "comment UUID");
        const r = await gql(
          "commentDelete",
          "mutation CommentDelete($id: String!) { commentDelete(id: $id) { success } }",
          { id },
          { mutating: true, tolerateNotFound: true },
        );
        if (r.notFound) return { comment_id: id, deleted: false };
        if (asRecord(r.data.commentDelete).success !== true) throw new Error("Linear did not delete the comment");
        return { comment_id: id, deleted: true };
      },
    },
  ]);
}
