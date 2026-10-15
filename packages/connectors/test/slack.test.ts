import { EffectUncertainError, Registry } from "@multimindlab/reversi";
import { describe, expect, it } from "vitest";
import { HttpError, compensatorFor, createSlackConnector } from "../src/index.js";
import { engine, failingFetch, fakeFetch, type Call, type FakeReply } from "./helpers.js";

const TOKEN = "xoxb-SECRET-SLACK-TOKEN";
const CH = "C0123ABCDE";

/** A tiny Slack: messages and per-message reactions. */
function fakeSlack() {
  const messages = new Map<string, Set<string>>();
  let n = 0;
  const h = (c: Call): FakeReply => {
    const method = new URL(c.url).pathname.replace("/api/", "");
    const body = c.body ? JSON.parse(c.body) : {};
    switch (method) {
      case "chat.postMessage": {
        const ts = `1700000000.${String(++n).padStart(6, "0")}`;
        messages.set(ts, new Set());
        return { json: { ok: true, channel: body.channel, ts } };
      }
      case "chat.delete":
        return messages.delete(body.ts) ? { json: { ok: true } } : { json: { ok: false, error: "message_not_found" } };
      case "reactions.add": {
        const m = messages.get(body.timestamp);
        if (!m) return { json: { ok: false, error: "message_not_found" } };
        if (m.has(body.name)) return { json: { ok: false, error: "already_reacted" } };
        m.add(body.name);
        return { json: { ok: true } };
      }
      case "reactions.remove": {
        const m = messages.get(body.timestamp);
        if (!m) return { json: { ok: false, error: "message_not_found" } };
        return m.delete(body.name) ? { json: { ok: true } } : { json: { ok: false, error: "no_reaction" } };
      }
      case "conversations.list":
        return { json: { ok: true, channels: [{ id: CH, name: "general", is_private: false }], response_metadata: { next_cursor: "" } } };
    }
    return { status: 404 };
  };
  return { messages, h };
}

function setup(handler?: (c: Call, n: number) => FakeReply) {
  const sl = fakeSlack();
  const f = fakeFetch(handler ?? ((c) => sl.h(c)));
  const connector = createSlackConnector({ token: TOKEN, fetch: f.fetch });
  return { sl, f, connector, t: (n: string, a: Record<string, unknown>) => connector.tools[`slack.${n}`]!(a, {}) };
}

describe("slack manifests", () => {
  it("validate and cross-reference", () => {
    const { connector } = setup();
    const reg = Registry.from(connector.manifests);
    expect(reg.size).toBe(5);
    expect(reg.get("slack.post_message")?.compensation?.argument_map).toEqual({
      channel: "$result.channel",
      ts: "$result.ts",
    });
    expect(Object.keys(connector.tools).sort()).toEqual(reg.list().map((m) => m.tool).sort());
  });
});

describe("slack tools", () => {
  it("posts with bearer auth and JSON body", async () => {
    const { t, f } = setup();
    const r = await t("post_message", { channel: CH, text: "hi" });
    expect(r).toMatchObject({ channel: CH });
    const c = f.calls[0]!;
    expect(c.url).toBe("https://slack.com/api/chat.postMessage");
    expect(c.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(JSON.parse(c.body)).toEqual({ channel: CH, text: "hi" });
  });

  it("treats {ok:false} on HTTP 200 as failure without leaking the token", async () => {
    const { t } = setup(() => ({ json: { ok: false, error: `invalid_auth ${TOKEN}` } }));
    const err = await t("post_message", { channel: CH, text: "hi" }).catch((e) => e);
    expect(err.message).toContain("invalid_auth");
    expect(err.message).not.toContain(TOKEN);
  });

  it("maps HTTP errors with status (rate limiting)", async () => {
    const { t } = setup(() => ({ status: 429, json: { error: "ratelimited" } }));
    const err = await t("post_message", { channel: CH, text: "hi" }).catch((e) => e);
    expect(err).toBeInstanceOf(HttpError);
    expect(err.status).toBe(429);
  });

  it("validates arguments", async () => {
    const { t, f } = setup();
    await expect(t("post_message", { channel: "general", text: "x" })).rejects.toThrow("not a valid channel ID");
    await expect(t("post_message", { channel: CH })).rejects.toThrow("`text`");
    await expect(t("delete_message", { channel: CH, ts: "yesterday" })).rejects.toThrow("message timestamp");
    await expect(t("add_reaction", { channel: CH, timestamp: "1.1", name: ":bad name:" })).rejects.toThrow("emoji");
    await expect(t("post_message", { channel: CH, text: "x", nope: 1 })).rejects.toThrow("unknown argument");
    expect(f.calls).toHaveLength(0);
  });

  it("network failure while posting is uncertain", async () => {
    const c = createSlackConnector({ token: TOKEN, fetch: failingFetch("ECONNRESET") });
    await expect(c.tools["slack.post_message"]!({ channel: CH, text: "x" }, {})).rejects.toBeInstanceOf(
      EffectUncertainError,
    );
  });

  it("delete and reaction compensations are idempotent", async () => {
    const { t, sl } = setup();
    const m = (await t("post_message", { channel: CH, text: "x" })) as { ts: string };
    expect(await t("add_reaction", { channel: CH, timestamp: m.ts, name: "eyes" })).toMatchObject({ added: true });
    expect(await t("add_reaction", { channel: CH, timestamp: m.ts, name: "eyes" })).toMatchObject({ added: false });
    expect(await t("remove_reaction", { channel: CH, timestamp: m.ts, name: "eyes" })).toMatchObject({ removed: true });
    expect(await t("remove_reaction", { channel: CH, timestamp: m.ts, name: "eyes" })).toMatchObject({ removed: false });
    expect(await t("delete_message", { channel: CH, ts: m.ts })).toMatchObject({ deleted: true });
    expect(await t("delete_message", { channel: CH, ts: m.ts })).toMatchObject({ deleted: false });
    expect(await t("remove_reaction", { channel: CH, timestamp: m.ts, name: "eyes" })).toMatchObject({ removed: false });
    expect(sl.messages.size).toBe(0);
  });

  it("lists channels with a query string", async () => {
    const { t, f } = setup();
    const r = (await t("list_channels", { limit: 10, types: "public_channel" })) as { channels: unknown[]; next_cursor: unknown };
    expect(r.channels).toHaveLength(1);
    expect(r.next_cursor).toBeNull();
    expect(f.calls[0]!.method).toBe("GET");
    expect(f.calls[0]!.url).toContain("limit=10");
  });
});

describe("slack end to end", () => {
  it("rolls back a message and reaction through a real engine", async () => {
    const { connector, sl, f } = setup();
    const { call, run } = engine([connector]);
    const posted = await call("slack.post_message", { channel: CH, text: "deploying" });
    const ts = (posted as { result: { ts: string } }).result.ts;
    await call("slack.add_reaction", { channel: CH, timestamp: ts, name: "rocket" });
    await call("slack.list_channels", {});

    const report = await run.rollback({ compensate: compensatorFor([connector]) });
    expect(report.complete).toBe(true);
    expect(sl.messages.size).toBe(0);
    const methods = f.calls.map((c) => new URL(c.url).pathname.replace("/api/", ""));
    expect(methods).toEqual([
      "chat.postMessage",
      "reactions.add",
      "conversations.list",
      "reactions.remove",
      "chat.delete",
    ]);
  });

  it("a Slack error during compensation fails the step, and a retry succeeds", async () => {
    const sl = fakeSlack();
    let broken = true;
    const f = fakeFetch((c) =>
      broken && c.url.endsWith("chat.delete") ? { json: { ok: false, error: "cant_delete_message" } } : sl.h(c),
    );
    const connector = createSlackConnector({ token: TOKEN, fetch: f.fetch });
    const { call, run } = engine([connector]);
    await call("slack.post_message", { channel: CH, text: "x" });
    const r1 = await run.rollback({ compensate: compensatorFor([connector]) });
    expect(r1.complete).toBe(false);
    expect(r1.failed[0]?.error).toContain("cant_delete_message");
    broken = false;
    expect((await run.rollback({ compensate: compensatorFor([connector]) })).complete).toBe(true);
    expect(sl.messages.size).toBe(0);
  });
});
