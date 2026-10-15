import { EffectUncertainError, Registry } from "@multimindlab/reversi";
import { describe, expect, it } from "vitest";
import { HttpError, compensatorFor, createGithubConnector } from "../src/index.js";
import { engine, failingFetch, fakeFetch, type Call, type FakeReply } from "./helpers.js";

const TOKEN = "ghp_SUPERSECRETTOKEN123";
const SHA = "a".repeat(40);
const args = { owner: "acme", repo: "widgets" };

/** A small stateful GitHub: issues, labels, comments and branches. */
function fakeGithub() {
  const issues = new Map<number, { state: string; labels: string[] }>();
  const comments = new Set<number>();
  const branches = new Set<string>(["main"]);
  let nextIssue = 1;
  let nextComment = 100;
  const h = (c: Call): FakeReply => {
    const u = new URL(c.url);
    const p = u.pathname.replace("/repos/acme/widgets", "");
    const body = c.body ? JSON.parse(c.body) : {};
    let m: RegExpMatchArray | null;
    if (c.method === "POST" && p === "/issues") {
      const n = nextIssue++;
      issues.set(n, { state: "open", labels: body.labels ?? [] });
      return { status: 201, json: { number: n, html_url: `https://x/${n}`, state: "open" } };
    }
    if ((m = p.match(/^\/issues\/(\d+)$/))) {
      const i = issues.get(Number(m[1]));
      if (!i) return { status: 404, json: { message: "Not Found" } };
      if (c.method === "PATCH") i.state = body.state;
      return { json: { title: "t", state: i.state, labels: i.labels.map((name) => ({ name })), html_url: "u" } };
    }
    if (c.method === "POST" && (m = p.match(/^\/issues\/(\d+)\/comments$/))) {
      const id = nextComment++;
      comments.add(id);
      return { status: 201, json: { id, html_url: "c" } };
    }
    if ((m = p.match(/^\/issues\/comments\/(\d+)$/)) && c.method === "DELETE") {
      return comments.delete(Number(m[1])) ? { status: 204 } : { status: 404, json: { message: "Not Found" } };
    }
    if (c.method === "POST" && p === "/git/refs") {
      if (branches.has(body.ref.replace("refs/heads/", ""))) {
        return { status: 422, json: { message: "Reference already exists" } };
      }
      branches.add(body.ref.replace("refs/heads/", ""));
      return { status: 201, json: { ref: body.ref, object: { sha: body.sha } } };
    }
    if (c.method === "DELETE" && (m = p.match(/^\/git\/refs\/heads\/(.+)$/))) {
      const b = decodeURIComponent(m[1]!);
      return branches.delete(b) ? { status: 204 } : { status: 422, json: { message: "Reference does not exist" } };
    }
    if (c.method === "POST" && (m = p.match(/^\/issues\/(\d+)\/labels$/))) {
      issues.get(Number(m[1]))!.labels.push(...body.labels);
      return { json: [] };
    }
    if (c.method === "DELETE" && (m = p.match(/^\/issues\/(\d+)\/labels\/(.+)$/))) {
      const i = issues.get(Number(m[1]))!;
      const l = decodeURIComponent(m[2]!);
      if (!i.labels.includes(l)) return { status: 404, json: { message: "Label does not exist" } };
      i.labels = i.labels.filter((x) => x !== l);
      return { json: [] };
    }
    return { status: 500, json: { message: "unexpected " + c.method + " " + p } };
  };
  return { issues, comments, branches, h };
}

function setup(handler?: (c: Call, n: number) => FakeReply) {
  const gh = fakeGithub();
  const f = fakeFetch(handler ?? ((c) => gh.h(c)));
  const connector = createGithubConnector({ token: TOKEN, fetch: f.fetch });
  return { gh, f, connector, t: (n: string, a: Record<string, unknown>, ctx = {}) => connector.tools[`github.${n}`]!(a, ctx) };
}

describe("github manifests", () => {
  it("validate and cross-reference", () => {
    const { connector } = setup();
    const reg = Registry.from(connector.manifests);
    expect(reg.size).toBe(9);
    expect(reg.get("github.delete_branch")).toMatchObject({ effect: "idempotent", permission: "github:branch:delete" });
    expect(Object.keys(connector.tools).sort()).toEqual(reg.list().map((m) => m.tool).sort());
  });
});

describe("github tools", () => {
  it("sends the required headers and bearer token", async () => {
    const { t, f } = setup();
    await t("create_issue", { ...args, title: "Bug" });
    const c = f.calls[0]!;
    expect(c.url).toBe("https://api.github.com/repos/acme/widgets/issues");
    expect(c.headers).toMatchObject({
      authorization: `Bearer ${TOKEN}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
    });
    expect(JSON.parse(c.body)).toEqual({ title: "Bug" });
  });

  it("honours baseUrl", async () => {
    const f = fakeFetch(() => ({ json: { title: "t", state: "open", labels: [] } }));
    const c = createGithubConnector({ token: TOKEN, fetch: f.fetch, baseUrl: "https://ghe.example/api/v3/" });
    await c.tools["github.get_issue"]!({ ...args, issue_number: 3 }, {});
    expect(f.calls[0]!.url).toBe("https://ghe.example/api/v3/repos/acme/widgets/issues/3");
  });

  it("validates arguments strictly", async () => {
    const { t, f } = setup();
    await expect(t("create_issue", { ...args })).rejects.toThrow("`title` must be a non-empty string");
    await expect(t("create_issue", { owner: "a/b", repo: "r", title: "x" })).rejects.toThrow("not a valid owner");
    await expect(t("get_issue", { ...args, issue_number: 0 })).rejects.toThrow("positive integer");
    await expect(t("create_branch", { ...args, branch: "a..b", sha: SHA })).rejects.toThrow("not a valid branch");
    await expect(t("create_branch", { ...args, branch: "ok", sha: "short" })).rejects.toThrow("commit SHA");
    await expect(t("add_labels", { ...args, issue_number: 1, labels: [] })).rejects.toThrow("must not be empty");
    await expect(t("get_issue", { ...args, issue_number: 1, x: 1 })).rejects.toThrow("unknown argument");
    expect(f.calls).toHaveLength(0);
  });

  it("maps HTTP errors with status and never leaks the token", async () => {
    const { t } = setup(() => ({ status: 401, json: { message: `Bad credentials for ${TOKEN}` } }));
    const err = await t("get_issue", { ...args, issue_number: 1 }).catch((e) => e);
    expect(err).toBeInstanceOf(HttpError);
    expect(err.status).toBe(401);
    expect(err.message).toContain("401");
    expect(err.message).not.toContain(TOKEN);
  });

  it("treats a network failure on a mutating call as uncertain, and on a read as a plain error", async () => {
    const c = createGithubConnector({ token: TOKEN, fetch: failingFetch(`socket hang up ${TOKEN}`) });
    const err = await c.tools["github.create_issue"]!({ ...args, title: "x" }, {}).catch((e) => e);
    expect(err).toBeInstanceOf(EffectUncertainError);
    expect(err.message).not.toContain(TOKEN);
    const rd = await c.tools["github.get_issue"]!({ ...args, issue_number: 1 }, {}).catch((e) => e);
    expect(rd).not.toBeInstanceOf(EffectUncertainError);
    expect(rd.message).not.toContain(TOKEN);
  });

  it("idempotent compensation tools succeed when run twice", async () => {
    const { t, gh } = setup();
    const issue = (await t("create_issue", { ...args, title: "x" })) as { issue_number: number };
    await t("close_issue", { ...args, issue_number: issue.issue_number });
    await t("close_issue", { ...args, issue_number: issue.issue_number });
    expect(gh.issues.get(1)!.state).toBe("closed");
    const cm = (await t("add_comment", { ...args, issue_number: 1, body: "hi" })) as { comment_id: number };
    expect(await t("delete_comment", { ...args, comment_id: cm.comment_id })).toMatchObject({ deleted: true });
    expect(await t("delete_comment", { ...args, comment_id: cm.comment_id })).toMatchObject({ deleted: false });
    await t("create_branch", { ...args, branch: "feat/x", sha: SHA });
    expect(await t("delete_branch", { ...args, branch: "feat/x" })).toMatchObject({ deleted: true });
    expect(await t("delete_branch", { ...args, branch: "feat/x" })).toMatchObject({ deleted: false });
    expect(await t("remove_labels", { ...args, issue_number: 1, labels: ["nope"] })).toMatchObject({ removed: [] });
  });

  it("a 422 that is not 'does not exist' is a failure for delete_branch", async () => {
    const { t } = setup(() => ({ status: 422, json: { message: "Validation Failed" } }));
    await expect(t("delete_branch", { ...args, branch: "x" })).rejects.toThrow("422");
  });

  it("add_labels only reports labels that were not already present", async () => {
    const { t, gh } = setup();
    await t("create_issue", { ...args, title: "x", labels: ["bug"] });
    const r = (await t("add_labels", { ...args, issue_number: 1, labels: ["bug", "p1", "p1"] })) as { added: string[] };
    expect(r.added).toEqual(["p1"]);
    expect(gh.issues.get(1)!.labels.sort()).toEqual(["bug", "p1"]);
  });

  it("returns issue details from get_issue", async () => {
    const { t } = setup();
    await t("create_issue", { ...args, title: "x", labels: ["bug"] });
    expect(await t("get_issue", { ...args, issue_number: 1 })).toMatchObject({ issue_number: 1, state: "open", labels: ["bug"] });
  });
});

describe("github end to end", () => {
  it("rolls back a run through a real engine", async () => {
    const { connector, gh, f } = setup();
    const { call, run } = engine([connector]);

    await call("github.create_issue", { ...args, title: "Plan", labels: ["triage"] });
    await call("github.add_comment", { ...args, issue_number: 1, body: "hello" });
    await call("github.add_labels", { ...args, issue_number: 1, labels: ["triage", "urgent"] });
    await call("github.create_branch", { ...args, branch: "feat/y", sha: SHA });
    await call("github.get_issue", { ...args, issue_number: 1 });

    const report = await run.rollback({ compensate: compensatorFor([connector]) });
    expect(report.complete).toBe(true);
    expect(report.compensated).toHaveLength(4);
    expect(gh.issues.get(1)!.state).toBe("closed");
    expect(gh.issues.get(1)!.labels).toEqual(["triage"]); // pre-existing label untouched
    expect(gh.comments.size).toBe(0);
    expect(gh.branches.has("feat/y")).toBe(false);
    const deletes = f.calls.filter((c) => c.method === "DELETE").map((c) => new URL(c.url).pathname);
    expect(deletes).toContain("/repos/acme/widgets/git/refs/heads/feat/y");
    expect(deletes).toContain("/repos/acme/widgets/issues/1/labels/urgent");
  });

  it("a failing compensation (500) is reported and retry succeeds", async () => {
    const gh = fakeGithub();
    let broken = false;
    const f = fakeFetch((c) => (broken && c.method === "DELETE" ? { status: 500, json: { message: "boom" } } : gh.h(c)));
    const connector = createGithubConnector({ token: TOKEN, fetch: f.fetch });
    const { call, run } = engine([connector]);
    await call("github.create_branch", { ...args, branch: "feat/z", sha: SHA });
    broken = true;
    const r1 = await run.rollback({ compensate: compensatorFor([connector]) });
    expect(r1.complete).toBe(false);
    expect(r1.failed[0]?.error).toContain("500");
    expect(r1.failed[0]?.error).not.toContain(TOKEN);
    broken = false;
    const r2 = await run.rollback({ compensate: compensatorFor([connector]) });
    expect(r2.complete).toBe(true);
    expect(gh.branches.has("feat/z")).toBe(false);
  });

  it("a timeout during create_issue leaves the step uncertain, not guessed", async () => {
    const connector = createGithubConnector({ token: TOKEN, fetch: failingFetch("timeout") });
    const { call, run } = engine([connector]);
    await expect(call("github.create_issue", { ...args, title: "x" })).rejects.toBeInstanceOf(EffectUncertainError);
    expect(run.state().steps[0]!.status).toBe("uncertain");
    expect(run.unresolved()).toEqual([0]);
  });
});
