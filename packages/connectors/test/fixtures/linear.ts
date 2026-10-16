import { expect } from "vitest";
import { createLinearConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";

export const KEY = "lin_api_SECRETLINEARKEY0123456789";
export const TEAM = "cccccccc-0000-4000-8000-000000000001";
export const ISSUE = "aaaaaaaa-0000-4000-8000-000000000001";
export const COMMENT = "dddddddd-0000-4000-8000-000000000001";

export function fakeLinear() {
  const issues = new Map<string, { title: string; archived: boolean }>();
  const comments = new Set<string>();
  let n = 0;
  const gen = (prefix: string) => `${prefix}-0000-4000-8000-${String(++n).padStart(12, "0")}`;
  const notFound = { json: { errors: [{ message: "Entity not found: Issue" }] } };
  const b = httpBackend({
    state: () => ({ issues: [...issues], comments: [...comments].sort() }),
    isMutating: (c) => (JSON.parse(c.body || "{}").query ?? "").trim().startsWith("mutation"),
    handle: (c) => {
      const { query, variables } = JSON.parse(c.body) as { query: string; variables: Record<string, any> };
      if (query.includes("issueCreate")) {
        const id = gen("bbbbbbbb");
        issues.set(id, { title: variables.input.title, archived: false });
        return { json: { data: { issueCreate: { success: true, issue: { id, identifier: "ENG-1", url: "https://linear.app/x/ENG-1", title: variables.input.title } } } } };
      }
      if (query.includes("issueArchive")) {
        const i = issues.get(variables.id);
        if (!i) return notFound;
        i.archived = true;
        return { json: { data: { issueArchive: { success: true } } } };
      }
      if (query.includes("commentCreate")) {
        if (!issues.has(variables.input.issueId)) return notFound;
        const id = gen("eeeeeeee");
        comments.add(id);
        return { json: { data: { commentCreate: { success: true, comment: { id, url: "https://linear.app/c" } } } } };
      }
      if (query.includes("commentDelete")) {
        if (!comments.delete(variables.id)) return { json: { errors: [{ message: "Entity not found: Comment" }] } };
        return { json: { data: { commentDelete: { success: true } } } };
      }
      if (query.includes("issue(id")) {
        const i = issues.get(variables.id);
        if (!i) return notFound;
        return {
          json: {
            data: {
              issue: { id: variables.id, identifier: "ENG-1", title: i.title, description: null, url: "https://linear.app/x/ENG-1", archivedAt: i.archived ? "2026-01-01T00:00:00Z" : null, state: { name: "Todo" } },
            },
          },
        };
      }
      return { status: 400, json: { errors: [{ message: "unexpected query" }] } };
    },
  });
  return Object.assign(b, { issues, comments });
}
type FakeLinear = ReturnType<typeof fakeLinear>;
const ln = (b: Backend) => b as FakeLinear;
const seedIssue = (b: Backend) => void ln(b).issues.set(ISSUE, { title: "seed", archived: false });

export const subject: Subject = {
  name: "linear",
  secrets: [KEY],
  make: (o) => {
    const backend = fakeLinear();
    return { backend, connector: createLinearConnector({ apiKey: KEY, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
  faultBody: (_s, secret) => ({ json: { errors: [{ message: `rejected ${secret}` }] } }),
};

export const scenarios: Scenario[] = [
  { tool: "get_issue", args: { id: ISSUE }, setup: seedIssue, expect: (r) => expect(r).toMatchObject({ title: "seed", archived: false }) },
  {
    tool: "create_issue",
    args: { team_id: TEAM, title: "Bug", priority: 2 },
    // an archived issue still exists in Linear; it is hidden, not erased
    restored: (_b, after) => expect((after as { issues: Array<[string, { archived: boolean }]> }).issues.every(([, i]) => i.archived)).toBe(true),
  },
  { tool: "archive_issue", args: { issue_id: ISSUE }, setup: seedIssue },
  { tool: "add_comment", args: { issue_id: ISSUE, body: "note" }, setup: seedIssue },
  { tool: "delete_comment", args: { comment_id: COMMENT }, setup: (b) => void ln(b).comments.add(COMMENT) },
];
