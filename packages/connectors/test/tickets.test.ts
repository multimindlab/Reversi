import { Registry } from "@multimindlab/reversi";
import { describe, expect, it } from "vitest";
import {
  compensatorFor,
  createGcalendarConnector,
  createGitlabConnector,
  createJiraConnector,
  createLinearConnector,
  createTeamsConnector,
} from "../src/index.js";
import { fakeCalendar, TOKEN as CAL_TOKEN } from "./fixtures/gcalendar.js";
import { fakeGitlab, TOKEN as GL_TOKEN, PROJECT } from "./fixtures/gitlab.js";
import { BASE, BASIC, EMAIL, fakeJira, TOKEN as JIRA_TOKEN } from "./fixtures/jira.js";
import { fakeLinear, ISSUE, KEY, TEAM as LIN_TEAM } from "./fixtures/linear.js";
import { CHANNEL, fakeTeams, TEAM, TOKEN as TEAMS_TOKEN } from "./fixtures/teams.js";
import { engine } from "./helpers.js";

describe("gitlab", () => {
  const make = (baseUrl?: string) => {
    const b = fakeGitlab();
    const c = createGitlabConnector({ token: GL_TOKEN, fetch: b.fetch, baseUrl });
    return { b, c, t: (n: string, a: Record<string, unknown>) => c.tools[`gitlab.${n}`]!(a, {}) };
  };

  it("manifests validate and compensations are registered", () => {
    const { c } = make();
    const reg = Registry.from(c.manifests);
    expect(reg.size).toBe(7);
    expect(reg.get("gitlab.create_issue")?.compensation?.tool).toBe("gitlab.close_issue");
    expect(reg.get("gitlab.add_note")?.compensation?.tool).toBe("gitlab.delete_note");
    expect(reg.get("gitlab.create_branch")?.compensation?.tool).toBe("gitlab.delete_branch");
  });

  it("sends the token in PRIVATE-TOKEN and encodes the project path", async () => {
    const { b, t } = make();
    await t("create_issue", { project: PROJECT, title: "T", labels: ["a", "b"] });
    const call = b.calls[0]!;
    expect(call.url).toBe("https://gitlab.com/api/v4/projects/group%2Fproj/issues");
    expect(call.headers["private-token"]).toBe(GL_TOKEN);
    expect(call.headers.authorization).toBeUndefined();
    expect(JSON.parse(call.body)).toEqual({ title: "T", labels: "a,b" });
  });

  it("works against a self-hosted instance", async () => {
    const { b, t } = make("https://git.corp.example/");
    await t("create_branch", { project: PROJECT, branch: "x/y", ref: "main" });
    expect(b.calls[0]!.url).toBe("https://git.corp.example/api/v4/projects/group%2Fproj/repository/branches");
    expect(JSON.parse(b.calls[0]!.body)).toEqual({ branch: "x/y", ref: "main" });
    const { b: b2, t: t2 } = make("https://git.corp.example/api/v4");
    await t2("delete_branch", { project: PROJECT, branch: "x/y" });
    expect(b2.calls[0]!.url).toBe("https://git.corp.example/api/v4/projects/group%2Fproj/repository/branches/x%2Fy");
  });

  it("validates arguments before any request", async () => {
    const { b, t } = make();
    await expect(t("get_issue", { project: "../etc", issue_iid: 1 })).rejects.toThrow("project id or path");
    await expect(t("get_issue", { project: PROJECT, issue_iid: 0 })).rejects.toThrow("positive integer");
    await expect(t("create_branch", { project: PROJECT, branch: "a..b", ref: "main" })).rejects.toThrow("branch name");
    await expect(t("create_branch", { project: PROJECT, branch: "-x", ref: "main" })).rejects.toThrow("branch name");
    await expect(t("close_issue", { project: PROJECT, issue_iid: 1, nope: 1 })).rejects.toThrow("unknown argument");
    expect(b.calls).toHaveLength(0);
  });

  it("closing is the undo for create_issue, and the issue stays visible", async () => {
    const { b, c } = make();
    const { call, run } = engine([c]);
    await call("gitlab.create_issue", { project: PROJECT, title: "T" });
    const r = await run.rollback({ compensate: compensatorFor([c]) });
    expect(r.complete).toBe(true);
    expect([...b.issues.values()]).toEqual([{ title: "T", state: "closed" }]);
    expect(b.calls.at(-1)!.method).toBe("PUT");
  });
});

describe("teams (Microsoft Graph)", () => {
  const make = () => {
    const b = fakeTeams();
    const c = createTeamsConnector({ token: TEAMS_TOKEN, fetch: b.fetch });
    return { b, c, t: (n: string, a: Record<string, unknown>) => c.tools[`teams.${n}`]!(a, {}) };
  };

  it("uses the Graph channel message endpoints with a bearer token", async () => {
    const { b, t } = make();
    const posted = (await t("post_message", { team_id: TEAM, channel_id: CHANNEL, content: "<b>hi</b>", content_type: "html" })) as { message_id: string };
    const post = b.calls[0]!;
    expect(post.method).toBe("POST");
    expect(post.url).toBe(`https://graph.microsoft.com/v1.0/teams/${TEAM}/channels/19%3Aabc123%40thread.tacv2/messages`);
    expect(post.headers.authorization).toBe(`Bearer ${TEAMS_TOKEN}`);
    expect(JSON.parse(post.body)).toEqual({ body: { contentType: "html", content: "<b>hi</b>" } });
    await t("delete_message", { team_id: TEAM, channel_id: CHANNEL, message_id: posted.message_id });
    const del = b.calls[1]!;
    expect(del.method).toBe("POST");
    expect(del.url).toBe(`https://graph.microsoft.com/v1.0/teams/${TEAM}/channels/19%3Aabc123%40thread.tacv2/messages/${posted.message_id}/softDelete`);
    await t("list_channels", { team_id: TEAM, top: 5 });
    expect(b.calls[2]!.url).toBe(`https://graph.microsoft.com/v1.0/teams/${TEAM}/channels?$top=5`);
  });

  it("treats a missing message as already deleted and validates ids", async () => {
    const { t, b } = make();
    expect(await t("delete_message", { team_id: TEAM, channel_id: CHANNEL, message_id: "1700000000555" })).toMatchObject({ deleted: false });
    const n = b.calls.length;
    await expect(t("post_message", { team_id: "nope", channel_id: CHANNEL, content: "x" })).rejects.toThrow("team ID");
    await expect(t("post_message", { team_id: TEAM, channel_id: "general", content: "x" })).rejects.toThrow("channel ID");
    await expect(t("delete_message", { team_id: TEAM, channel_id: CHANNEL, message_id: "../x" })).rejects.toThrow("message ID");
    await expect(t("post_message", { team_id: TEAM, channel_id: CHANNEL, content: "x", content_type: "markdown" })).rejects.toThrow("content type");
    expect(b.calls).toHaveLength(n);
  });

  it("declares the permission each tool needs", () => {
    const { c } = make();
    const reg = Registry.from(c.manifests);
    expect(reg.get("teams.list_channels")?.permission).toBe("teams:channels:read");
    expect(reg.get("teams.post_message")?.permission).toBe("teams:messages:write");
    expect(reg.get("teams.delete_message")?.permission).toBe("teams:messages:delete");
    expect(reg.get("teams.post_message")?.description).toContain("ChannelMessage.Send");
    expect(reg.get("teams.delete_message")?.description).toContain("ChannelMessage.ReadWrite");
    expect(reg.get("teams.list_channels")?.description).toContain("Channel.ReadBasic.All");
  });
});

describe("linear", () => {
  const make = () => {
    const b = fakeLinear();
    const c = createLinearConnector({ apiKey: KEY, fetch: b.fetch });
    return { b, c, t: (n: string, a: Record<string, unknown>) => c.tools[`linear.${n}`]!(a, {}) };
  };
  const body = (b: { calls: Array<{ body: string }> }, i: number) => JSON.parse(b.calls[i]!.body) as { query: string; variables: Record<string, unknown> };

  it("posts GraphQL with the key as the whole Authorization value", async () => {
    const { b, t } = make();
    await t("create_issue", { team_id: LIN_TEAM, title: "Bug", description: "d", priority: 2 });
    const c = b.calls[0]!;
    expect(c.url).toBe("https://api.linear.app/graphql");
    expect(c.headers.authorization).toBe(KEY);
    expect(body(b, 0).query).toContain("issueCreate(input: $input)");
    expect(body(b, 0).variables).toEqual({ input: { teamId: LIN_TEAM, title: "Bug", description: "d", priority: 2 } });
  });

  it("archives with the issueArchive mutation only when the issue is not already archived", async () => {
    const { b, t } = make();
    b.issues.set(ISSUE, { title: "x", archived: false });
    expect(await t("archive_issue", { issue_id: ISSUE })).toMatchObject({ archived: true });
    expect(body(b, 1).query).toContain("issueArchive(id: $id)");
    expect(body(b, 1).variables).toEqual({ id: ISSUE });
    const n = b.calls.length;
    expect(await t("archive_issue", { issue_id: ISSUE })).toMatchObject({ archived: false });
    expect(b.calls.length).toBe(n + 1); // a read, no second mutation
    expect(await t("archive_issue", { issue_id: "ffffffff-0000-4000-8000-000000000009" })).toMatchObject({ archived: false });
  });

  it("surfaces GraphQL errors returned with HTTP 200, without the key", async () => {
    const b = fakeLinear();
    const c = createLinearConnector({
      apiKey: KEY,
      fetch: (async () => new Response(JSON.stringify({ errors: [{ message: `Argument Validation Error ${KEY}` }] }), { status: 200 })) as typeof fetch,
    });
    const err = await c.tools["linear.create_issue"]!({ team_id: LIN_TEAM, title: "x" }, {}).catch((e) => e);
    expect(err.message).toContain("Argument Validation Error");
    expect(err.message).not.toContain(KEY);
    void b;
  });

  it("validates ids and accepts identifiers for reads", async () => {
    const { b, t } = make();
    await expect(t("get_issue", { id: "not an id" })).rejects.toThrow("issue id or identifier");
    await expect(t("add_comment", { issue_id: "ENG-1", body: "x" })).rejects.toThrow("issue UUID");
    await expect(t("create_issue", { team_id: LIN_TEAM, title: "x", priority: 9 })).rejects.toThrow("between 1 and 4");
    expect(b.calls).toHaveLength(0);
    b.issues.set("ENG-1", { title: "viaIdentifier", archived: false });
    expect(await t("get_issue", { id: "ENG-1" })).toMatchObject({ title: "viaIdentifier" });
  });
});

describe("jira", () => {
  const make = () => {
    const b = fakeJira();
    const c = createJiraConnector({ baseUrl: `${BASE}/`, email: EMAIL, apiToken: JIRA_TOKEN, fetch: b.fetch });
    return { b, c, t: (n: string, a: Record<string, unknown>) => c.tools[`jira.${n}`]!(a, {}) };
  };

  it("uses REST v3 with basic auth and sends descriptions as Atlassian Document Format", async () => {
    const { b, t } = make();
    await t("create_issue", { project_key: "PROJ", summary: "S", issue_type: "Bug", description: "a\nb" });
    const c = b.calls[0]!;
    expect(c.url).toBe(`${BASE}/rest/api/3/issue`);
    expect(c.headers.authorization).toBe(`Basic ${BASIC}`);
    expect(JSON.parse(c.body)).toEqual({
      fields: {
        project: { key: "PROJ" },
        summary: "S",
        issuetype: { name: "Bug" },
        description: {
          type: "doc",
          version: 1,
          content: [
            { type: "paragraph", content: [{ type: "text", text: "a" }] },
            { type: "paragraph", content: [{ type: "text", text: "b" }] },
          ],
        },
      },
    });
  });

  it("reads the status first, transitions, and returns the previous status", async () => {
    const { b, t } = make();
    b.issues.set("PROJ-9", { summary: "s", status: "1" });
    for (const [transition, to] of [["21", "In Progress"], ["Finish", "Done"], ["To Do", "To Do"]] as const) {
      const r = await t("transition_issue", { issue_key: "PROJ-9", transition });
      expect(r).toMatchObject({ status: to });
    }
    const first = b.calls.slice(0, 3).map((c) => `${c.method} ${new URL(c.url).pathname.replace("/rest/api/3", "")}`);
    expect(first).toEqual(["GET /issue/PROJ-9", "GET /issue/PROJ-9/transitions", "POST /issue/PROJ-9/transitions"]);
    await expect(t("transition_issue", { issue_key: "PROJ-9", transition: "Teleport" })).rejects.toThrow("no transition");
  });

  it("rolls a transition back to the previous status through a real engine", async () => {
    const { b, c } = make();
    b.issues.set("PROJ-9", { summary: "s", status: "2" });
    const { call, run } = engine([c]);
    await call("jira.transition_issue", { issue_key: "PROJ-9", transition: "Finish" });
    expect(b.issues.get("PROJ-9")!.status).toBe("3");
    const report = await run.rollback({ compensate: compensatorFor([c]) });
    expect(report.complete).toBe(true);
    expect(b.issues.get("PROJ-9")!.status).toBe("2");
  });

  it("restore_status fails clearly when the workflow has no way back", async () => {
    const { b, t } = make();
    b.issues.set("PROJ-9", { summary: "s", status: "1" });
    await expect(t("restore_status", { issue_key: "PROJ-9", status_id: "99" })).rejects.toThrow("no transition");
    expect(await t("restore_status", { issue_key: "PROJ-9", status_id: "1" })).toMatchObject({ moved: false });
  });

  it("validates keys and the base URL", async () => {
    const { b, t } = make();
    await expect(t("get_issue", { issue_key: "proj-1" })).rejects.toThrow("issue key");
    await expect(t("delete_issue", { issue_key: "PROJ-1/../../x" })).rejects.toThrow("issue key");
    await expect(t("delete_comment", { issue_key: "PROJ-1", comment_id: "abc" })).rejects.toThrow("comment id");
    await expect(t("create_issue", { project_key: "p", summary: "x" })).rejects.toThrow("project key");
    expect(b.calls).toHaveLength(0);
    expect(() => createJiraConnector({ baseUrl: "https://u:p@x.atlassian.net", email: "a", apiToken: "b" })).toThrow("without credentials");
    expect(() => createJiraConnector({ baseUrl: "ftp://x", email: "a", apiToken: "b" })).toThrow("http(s)");
    expect(() => createJiraConnector({ baseUrl: BASE, email: "", apiToken: "b" })).toThrow("email");
  });

  it("scrubs both the token and the encoded basic credential from errors", async () => {
    const c = createJiraConnector({
      baseUrl: BASE,
      email: EMAIL,
      apiToken: JIRA_TOKEN,
      fetch: (async () => new Response(JSON.stringify({ errorMessages: [`bad ${JIRA_TOKEN} and ${BASIC}`] }), { status: 400 })) as typeof fetch,
    });
    const err = await c.tools["jira.get_issue"]!({ issue_key: "PROJ-1" }, {}).catch((e) => e);
    expect(err.message).toContain("status 400");
    expect(err.message).not.toContain(JIRA_TOKEN);
    expect(err.message).not.toContain(BASIC);
  });
});

describe("gcalendar", () => {
  const make = () => {
    const b = fakeCalendar();
    const c = createGcalendarConnector({ token: CAL_TOKEN, fetch: b.fetch });
    return { b, c, t: (n: string, a: Record<string, unknown>) => c.tools[`gcalendar.${n}`]!(a, {}) };
  };

  it("never notifies attendees and defaults to the primary calendar", async () => {
    const { b, t } = make();
    await t("create_event", { summary: "Trip", start: "2026-06-01", end: "2026-06-03" });
    const c = b.calls[0]!;
    expect(c.url).toBe("https://www.googleapis.com/calendar/v3/calendars/primary/events?sendUpdates=none");
    expect(c.headers.authorization).toBe(`Bearer ${CAL_TOKEN}`);
    expect(JSON.parse(c.body)).toEqual({ summary: "Trip", start: { date: "2026-06-01" }, end: { date: "2026-06-03" } });
    await t("delete_event", { event_id: "ev1" });
    expect(b.calls[1]!.url).toBe("https://www.googleapis.com/calendar/v3/calendars/primary/events/ev1?sendUpdates=none");
  });

  it("update_event reads first and returns exactly the previous values of the fields it changed", async () => {
    const { b, t } = make();
    b.events.set("ev9", { id: "ev9", summary: "Standup", description: "keep me", start: { dateTime: "2026-05-01T09:00:00Z" }, end: { dateTime: "2026-05-01T09:15:00Z" } });
    const r = await t("update_event", { event_id: "ev9", summary: "Planning", location: "Room 1" });
    expect(r).toMatchObject({ previous: { summary: "Standup", location: null } });
    expect(Object.keys((r as { previous: object }).previous).sort()).toEqual(["location", "summary"]);
    expect(b.calls.map((c) => c.method)).toEqual(["GET", "PATCH"]);
    expect(JSON.parse(b.calls[1]!.body)).toEqual({ summary: "Planning", location: "Room 1" });
    expect(b.events.get("ev9")!.description).toBe("keep me");
    await t("restore_event", { event_id: "ev9", previous: (r as { previous: object }).previous });
    expect(b.events.get("ev9")).toMatchObject({ summary: "Standup", description: "keep me" });
    expect(b.events.get("ev9")!.location).toBeUndefined();
  });

  it("moving between a date-time and an all-day date clears the other key", async () => {
    const { b, t } = make();
    b.events.set("ev9", { id: "ev9", summary: "S", start: { dateTime: "2026-05-01T09:00:00Z" }, end: { dateTime: "2026-05-01T10:00:00Z" } });
    const r = (await t("update_event", { event_id: "ev9", start: "2026-05-02", end: "2026-05-03" })) as { previous: object };
    expect(b.events.get("ev9")).toMatchObject({ start: { date: "2026-05-02" }, end: { date: "2026-05-03" } });
    expect(b.events.get("ev9")!.start.dateTime).toBeUndefined();
    await t("restore_event", { event_id: "ev9", previous: r.previous });
    expect(b.events.get("ev9")).toMatchObject({ start: { dateTime: "2026-05-01T09:00:00Z" }, end: { dateTime: "2026-05-01T10:00:00Z" } });
    expect(b.events.get("ev9")!.start.date).toBeUndefined();
  });

  it("validates arguments", async () => {
    const { b, t } = make();
    await expect(t("create_event", { summary: "x", start: "tomorrow", end: "2026-06-01" })).rejects.toThrow("RFC 3339");
    await expect(t("update_event", { event_id: "ev1" })).rejects.toThrow("nothing to update");
    await expect(t("restore_event", { event_id: "ev1", previous: { attendees: [] } })).rejects.toThrow("not a restorable field");
    await expect(t("restore_event", { event_id: "ev1", previous: {} })).rejects.toThrow("no fields");
    await expect(t("delete_event", { event_id: "a/b" })).rejects.toThrow("event id");
    await expect(t("list_events", { max_results: 999 })).rejects.toThrow("at most 250");
    expect(b.calls).toHaveLength(0);
  });
});
