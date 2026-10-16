import { expect } from "vitest";
import { createGitlabConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";

export const TOKEN = "glpat-SECRET-GITLAB-TOKEN-123";
export const PROJECT = "group/proj";

export function fakeGitlab() {
  const issues = new Map<number, { title: string; state: string }>();
  const notes = new Map<number, number>();
  const branches = new Set<string>(["main"]);
  let nextIid = 1;
  let nextNote = 100;
  const b = httpBackend({
    state: () => ({ issues: [...issues], notes: [...notes], branches: [...branches].sort() }),
    handle: (c) => {
      const u = new URL(c.url);
      const p = u.pathname.replace("/api/v4/projects/group%2Fproj", "");
      const body = c.body ? JSON.parse(c.body) : {};
      let m: RegExpMatchArray | null;
      if (c.method === "POST" && p === "/issues") {
        const iid = nextIid++;
        issues.set(iid, { title: body.title, state: "opened" });
        return { status: 201, json: { iid, state: "opened", web_url: `https://gitlab.example/g/p/-/issues/${iid}` } };
      }
      if ((m = p.match(/^\/issues\/(\d+)$/))) {
        const i = issues.get(Number(m[1]));
        if (!i) return { status: 404, json: { message: "404 Not found" } };
        if (c.method === "GET") return { json: { iid: Number(m[1]), title: i.title, state: i.state, description: null, labels: [], web_url: "u" } };
        if (c.method === "PUT") {
          i.state = "closed";
          return { json: { iid: Number(m[1]), state: "closed" } };
        }
      }
      if (c.method === "POST" && (m = p.match(/^\/issues\/(\d+)\/notes$/))) {
        if (!issues.has(Number(m[1]))) return { status: 404, json: { message: "404 Not found" } };
        const id = nextNote++;
        notes.set(id, Number(m[1]));
        return { status: 201, json: { id } };
      }
      if (c.method === "DELETE" && (m = p.match(/^\/issues\/(\d+)\/notes\/(\d+)$/))) {
        return notes.delete(Number(m[2])) ? { status: 204 } : { status: 404, json: { message: "404 Not found" } };
      }
      if (c.method === "POST" && p === "/repository/branches") {
        if (branches.has(body.branch)) return { status: 400, json: { message: "Branch already exists" } };
        branches.add(body.branch);
        return { status: 201, json: { name: body.branch, commit: { id: "abc123" } } };
      }
      if (c.method === "DELETE" && (m = p.match(/^\/repository\/branches\/(.+)$/))) {
        return branches.delete(decodeURIComponent(m[1]!)) ? { status: 204 } : { status: 404, json: { message: "404 Branch Not Found" } };
      }
      return { status: 500, json: { message: `unexpected ${c.method} ${c.url}` } };
    },
  });
  return Object.assign(b, { issues, notes, branches });
}
export type FakeGitlab = ReturnType<typeof fakeGitlab>;
const gl = (b: Backend) => b as FakeGitlab;
const seedIssue = (b: Backend) => void gl(b).issues.set(1, { title: "seed", state: "opened" });
const seedNote = (b: Backend) => {
  seedIssue(b);
  gl(b).notes.set(7, 1);
};

export const subject: Subject = {
  name: "gitlab",
  secrets: [TOKEN],
  make: (o) => {
    const backend = fakeGitlab();
    return { backend, connector: createGitlabConnector({ token: TOKEN, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
};

export const scenarios: Scenario[] = [
  { tool: "get_issue", args: { project: PROJECT, issue_iid: 1 }, setup: seedIssue, expect: (r) => expect(r).toMatchObject({ title: "seed", state: "opened" }) },
  { tool: "create_issue", args: { project: PROJECT, title: "T", labels: ["a", "b"] }, expect: (r) => expect(r).toMatchObject({ project: PROJECT, issue_iid: 1 }),
    restored: (_before, after) => expect((after as { issues: Array<[number, { state: string }]> }).issues[0]![1].state).toBe("closed") },
  { tool: "close_issue", args: { project: PROJECT, issue_iid: 1 }, setup: seedIssue },
  { tool: "add_note", args: { project: PROJECT, issue_iid: 1, body: "hello" }, setup: seedIssue, expect: (r) => expect(r).toMatchObject({ note_id: 100 }) },
  { tool: "delete_note", args: { project: PROJECT, issue_iid: 1, note_id: 7 }, setup: seedNote },
  { tool: "create_branch", args: { project: PROJECT, branch: "feature/x", ref: "main" } },
  { tool: "delete_branch", args: { project: PROJECT, branch: "old" }, setup: (b) => void gl(b).branches.add("old") },
];
