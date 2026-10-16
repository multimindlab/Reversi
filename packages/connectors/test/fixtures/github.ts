import { expect } from "vitest";
import { createGithubConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";

export const TOKEN = "ghp_SECRETGITHUBTOKEN0123456789abcdef";
export const SHA = "a".repeat(40);
const T = { owner: "acme", repo: "app" };

export function fakeGithub() {
  const issues = new Map<number, { title: string; state: string; labels: Set<string> }>();
  const comments = new Map<number, number>();
  const branches = new Set<string>(["main"]);
  let nIssue = 0;
  let nComment = 100;
  const b = httpBackend({
    state: () => ({
      issues: [...issues].map(([n, i]) => [n, i.title, i.state, [...i.labels].sort()]),
      comments: [...comments],
      branches: [...branches].sort(),
    }),
    handle: (c) => {
      const p = new URL(c.url).pathname.replace("/repos/acme/app", "");
      const body = c.body ? JSON.parse(c.body) : {};
      let m: RegExpMatchArray | null;
      if (c.method === "POST" && p === "/issues") {
        const n = ++nIssue;
        issues.set(n, { title: body.title, state: "open", labels: new Set() });
        return { status: 201, json: { number: n, html_url: `https://github.example/${n}`, state: "open" } };
      }
      if ((m = p.match(/^\/issues\/(\d+)$/))) {
        const i = issues.get(Number(m[1]));
        if (!i) return { status: 404, json: { message: "Not Found" } };
        if (c.method === "GET") return { json: { title: i.title, state: i.state, body: null, labels: [...i.labels].map((name) => ({ name })), html_url: "u" } };
        if (c.method === "PATCH") {
          i.state = body.state;
          return { json: { state: i.state } };
        }
      }
      if (c.method === "POST" && (m = p.match(/^\/issues\/(\d+)\/comments$/))) {
        if (!issues.has(Number(m[1]))) return { status: 404, json: { message: "Not Found" } };
        const id = ++nComment;
        comments.set(id, Number(m[1]));
        return { status: 201, json: { id, html_url: `https://github.example/c/${id}` } };
      }
      if (c.method === "DELETE" && (m = p.match(/^\/issues\/comments\/(\d+)$/))) {
        return comments.delete(Number(m[1])) ? { status: 204 } : { status: 404, json: { message: "Not Found" } };
      }
      if (c.method === "POST" && p === "/git/refs") {
        const name = String(body.ref).replace("refs/heads/", "");
        if (branches.has(name)) return { status: 422, json: { message: "Reference already exists" } };
        branches.add(name);
        return { status: 201, json: { ref: body.ref, object: { sha: body.sha } } };
      }
      if (c.method === "DELETE" && (m = p.match(/^\/git\/refs\/heads\/(.+)$/))) {
        return branches.delete(decodeURIComponent(m[1]!).replace(/%2F/g, "/")) ? { status: 204 } : { status: 422, json: { message: "Reference does not exist" } };
      }
      if (c.method === "POST" && (m = p.match(/^\/issues\/(\d+)\/labels$/))) {
        const i = issues.get(Number(m[1]));
        if (!i) return { status: 404, json: { message: "Not Found" } };
        for (const l of body.labels) i.labels.add(l);
        return { json: [...i.labels].map((name) => ({ name })) };
      }
      if (c.method === "DELETE" && (m = p.match(/^\/issues\/(\d+)\/labels\/(.+)$/))) {
        const i = issues.get(Number(m[1]));
        return i?.labels.delete(decodeURIComponent(m[2]!)) ? { json: [] } : { status: 404, json: { message: "Label does not exist" } };
      }
      return { status: 500, json: { message: `unexpected ${c.method} ${c.url}` } };
    },
  });
  return Object.assign(b, { issues, comments, branches });
}
type FakeGithub = ReturnType<typeof fakeGithub>;
const gh = (b: Backend) => b as FakeGithub;
const seed = (b: Backend) => void gh(b).issues.set(1, { title: "seed", state: "open", labels: new Set(["bug"]) });

export const subject: Subject = {
  name: "github",
  secrets: [TOKEN],
  make: (o) => {
    const backend = fakeGithub();
    return { backend, connector: createGithubConnector({ token: TOKEN, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
};

export const scenarios: Scenario[] = [
  { tool: "get_issue", args: { ...T, issue_number: 1 }, setup: seed, expect: (r) => expect(r).toMatchObject({ title: "seed", state: "open", labels: ["bug"] }) },
  {
    tool: "create_issue",
    args: { ...T, title: "Bug", labels: ["bug"] },
    expect: (r) => expect(r).toMatchObject({ issue_number: 1 }),
    // GitHub cannot delete issues: rollback closes it, and it stays visible
    restored: (_b, after) => expect((after as { issues: unknown[][] }).issues.map((i) => i[2])).toEqual(["closed"]),
  },
  { tool: "close_issue", args: { ...T, issue_number: 1 }, setup: seed },
  { tool: "add_comment", args: { ...T, issue_number: 1, body: "hello" }, setup: seed, expect: (r) => expect(r).toMatchObject({ comment_id: 101 }) },
  { tool: "delete_comment", args: { ...T, comment_id: 55 }, setup: (b) => (seed(b), void gh(b).comments.set(55, 1)) },
  { tool: "create_branch", args: { ...T, branch: "feature/x", sha: SHA } },
  { tool: "delete_branch", args: { ...T, branch: "old" }, setup: (b) => void gh(b).branches.add("old") },
  { tool: "add_labels", args: { ...T, issue_number: 1, labels: ["bug", "new"] }, setup: seed, expect: (r) => expect(r).toMatchObject({ added: ["new"] }) },
  { tool: "remove_labels", args: { ...T, issue_number: 1, labels: ["bug"] }, setup: seed },
];
