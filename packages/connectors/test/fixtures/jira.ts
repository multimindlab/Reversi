import { expect } from "vitest";
import { createJiraConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";

export const TOKEN = "ATATT3-SECRET-JIRA-API-TOKEN";
export const EMAIL = "bot@example.com";
export const BASIC = Buffer.from(`${EMAIL}:${TOKEN}`).toString("base64");
export const BASE = "https://example.atlassian.net";

const STATUSES: Record<string, string> = { "1": "To Do", "2": "In Progress", "3": "Done" };
const TRANSITIONS: Array<{ id: string; name: string; to: string }> = [
  { id: "11", name: "Reopen", to: "1" },
  { id: "21", name: "Start progress", to: "2" },
  { id: "31", name: "Finish", to: "3" },
];

export function fakeJira() {
  const issues = new Map<string, { summary: string; status: string }>();
  const comments = new Map<string, string>();
  let nIssue = 0;
  let nComment = 10000;
  const gone = { status: 404, json: { errorMessages: ["Issue does not exist or you do not have permission to see it."] } };
  const b = httpBackend({
    state: () => ({ issues: [...issues], comments: [...comments] }),
    handle: (c) => {
      const u = new URL(c.url);
      const p = u.pathname.replace("/rest/api/3", "");
      let m: RegExpMatchArray | null;
      if (c.method === "POST" && p === "/issue") {
        const key = `PROJ-${++nIssue}`;
        issues.set(key, { summary: JSON.parse(c.body).fields.summary, status: "1" });
        return { status: 201, json: { id: String(10000 + nIssue), key } };
      }
      if ((m = p.match(/^\/issue\/([A-Z]+-\d+)$/))) {
        const i = issues.get(m[1]!);
        if (!i) return gone;
        if (c.method === "GET") return { json: { key: m[1], fields: { summary: i.summary, status: { id: i.status, name: STATUSES[i.status] } } } };
        if (c.method === "DELETE") {
          issues.delete(m[1]!);
          for (const [id, k] of [...comments]) if (k === m[1]) comments.delete(id);
          return { status: 204 };
        }
      }
      if ((m = p.match(/^\/issue\/([A-Z]+-\d+)\/comment$/)) && c.method === "POST") {
        if (!issues.has(m[1]!)) return gone;
        const id = String(++nComment);
        comments.set(id, m[1]!);
        return { status: 201, json: { id } };
      }
      if ((m = p.match(/^\/issue\/([A-Z]+-\d+)\/comment\/(\d+)$/)) && c.method === "DELETE") {
        return comments.delete(m[2]!) ? { status: 204 } : { status: 404, json: { errorMessages: ["comment not found"] } };
      }
      if ((m = p.match(/^\/issue\/([A-Z]+-\d+)\/transitions$/))) {
        const i = issues.get(m[1]!);
        if (!i) return gone;
        if (c.method === "GET") {
          return {
            json: {
              transitions: TRANSITIONS.filter((t) => t.to !== i.status).map((t) => ({ id: t.id, name: t.name, to: { id: t.to, name: STATUSES[t.to] } })),
            },
          };
        }
        const t = TRANSITIONS.find((x) => x.id === JSON.parse(c.body).transition.id && x.to !== i.status);
        if (!t) return { status: 400, json: { errorMessages: ["transition not valid"] } };
        i.status = t.to;
        return { status: 204 };
      }
      return { status: 500, json: { errorMessages: [`unexpected ${c.method} ${c.url}`] } };
    },
  });
  return Object.assign(b, { issues, comments });
}
type FakeJira = ReturnType<typeof fakeJira>;
const jr = (b: Backend) => b as FakeJira;
const seed = (b: Backend) => void jr(b).issues.set("PROJ-9", { summary: "seed", status: "1" });
const seedComment = (b: Backend) => {
  seed(b);
  jr(b).comments.set("555", "PROJ-9");
};

export const subject: Subject = {
  name: "jira",
  secrets: [TOKEN, BASIC],
  make: (o) => {
    const backend = fakeJira();
    return {
      backend,
      connector: createJiraConnector({ baseUrl: BASE, email: EMAIL, apiToken: TOKEN, fetch: backend.fetch, timeoutMs: o?.timeoutMs }),
    };
  },
  faultBody: (_s, secret) => ({ json: { errorMessages: [`not allowed ${secret} ${BASIC}`] } }),
};

export const scenarios: Scenario[] = [
  { tool: "get_issue", args: { issue_key: "PROJ-9" }, setup: seed, expect: (r) => expect(r).toMatchObject({ summary: "seed", status: "To Do", status_id: "1" }) },
  { tool: "create_issue", args: { project_key: "PROJ", summary: "New", description: "line one\nline two" }, expect: (r) => expect(r).toMatchObject({ issue_key: "PROJ-1" }) },
  { tool: "delete_issue", args: { issue_key: "PROJ-9" }, setup: seed },
  { tool: "add_comment", args: { issue_key: "PROJ-9", body: "hi" }, setup: seed, expect: (r) => expect(r).toMatchObject({ comment_id: "10001" }) },
  { tool: "delete_comment", args: { issue_key: "PROJ-9", comment_id: "555" }, setup: seedComment },
  {
    tool: "transition_issue",
    args: { issue_key: "PROJ-9", transition: "Start progress" },
    setup: seed,
    expect: (r) => expect(r).toMatchObject({ previous_status: "To Do", previous_status_id: "1", status: "In Progress", status_id: "2" }),
  },
  { tool: "restore_status", args: { issue_key: "PROJ-9", status_id: "1" }, setup: (b) => void jr(b).issues.set("PROJ-9", { summary: "seed", status: "2" }) },
];
