import { createHmac } from "node:crypto";
import { createServer as createHttp } from "node:http";
import { createServer as createTcp, type Socket } from "node:net";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  AlertManager,
  Approvals,
  Ledger,
  MemoryKvStore,
  Notifier,
  OtelExporter,
  Policy,
  Registry,
  Reversi,
  SealedScope,
  approvalNotification,
  attachNotifications,
  createChannel,
  createLogger,
  describeRecord,
  evaluateAlerts,
  parseChannels,
  parseRoutes,
  sendMail,
  type ChannelConfig,
  type NotifyMessage,
} from "../src/index.js";

const closers: Array<() => void> = [];
afterEach(() => {
  while (closers.length) (closers.pop() as () => void)();
});

async function httpSink(status = 200) {
  const got: Array<{ url: string; headers: Record<string, string | string[] | undefined>; body: any; raw: string }> = [];
  let failNext = 0;
  const server = createHttp((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      got.push({ url: req.url ?? "", headers: req.headers, raw, body: raw ? JSON.parse(raw) : undefined });
      if (failNext > 0) {
        failNext--;
        res.writeHead(503).end("busy");
      } else res.writeHead(status).end("ok");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  closers.push(() => server.close());
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, got, fail: (n: number) => (failNext = n) };
}

const msg = (over: Partial<NotifyMessage> = {}): NotifyMessage => ({ event: "approval_requested", severity: "warning", title: "Approval needed: pay", text: "details here", link: "https://reversi.example.com/console/approvals", dedup_key: "approval:apr_1", approval: { id: "apr_1", run_id: "r1", tool: "pay" }, data: { run_id: "r1" }, ...over });
const noSleep = async () => {};

describe("channels", () => {
  it("slack: text, blocks, and interactive buttons only when asked", async () => {
    const s = await httpSink();
    await createChannel({ type: "slack", name: "s", url: `${s.url}/hook` }).send(msg());
    await createChannel({ type: "slack", name: "s2", url: `${s.url}/hook`, interactive: true }).send(msg());
    expect(s.got[0]?.body.text).toContain("Approval needed: pay");
    expect(s.got[0]?.body.blocks.some((b: any) => b.type === "actions")).toBe(false);
    const actions = s.got[1]?.body.blocks.find((b: any) => b.type === "actions");
    expect(actions.elements.map((e: any) => [e.action_id, e.value])).toEqual([["reversi_approve", "apr_1"], ["reversi_deny", "apr_1"]]);
  });

  it("teams: a MessageCard with a link", async () => {
    const s = await httpSink();
    await createChannel({ type: "teams", name: "t", url: s.url }).send(msg({ severity: "critical" }));
    expect(s.got[0]?.body).toMatchObject({ "@type": "MessageCard", themeColor: "D70000", title: "Approval needed: pay", potentialAction: [{ name: "Open in Reversi" }] });
  });

  it("pagerduty: trigger then resolve with the same dedup key", async () => {
    const s = await httpSink();
    const ch = createChannel({ type: "pagerduty", name: "pd", routing_key: "RK", url: `${s.url}/v2/enqueue` });
    await ch.send(msg({ event: "alert", severity: "critical", title: "Rollback failed", dedup_key: "comp:r1:2" }));
    await ch.send(msg({ event: "alert", severity: "info", title: "Resolved", dedup_key: "comp:r1:2", resolve: true }));
    expect(s.got[0]?.body).toMatchObject({ routing_key: "RK", event_action: "trigger", dedup_key: "comp:r1:2", payload: { severity: "critical", source: "reversi", summary: "Rollback failed" } });
    expect(s.got[1]?.body).toMatchObject({ event_action: "resolve", dedup_key: "comp:r1:2" });
  });

  it("opsgenie: creates with GenieKey and closes by alias", async () => {
    const s = await httpSink();
    const ch = createChannel({ type: "opsgenie", name: "og", api_key: "KEY123", url: s.url });
    await ch.send(msg({ severity: "critical", dedup_key: "a/b" }));
    await ch.send(msg({ resolve: true, dedup_key: "a/b" }));
    expect(s.got[0]?.headers.authorization).toBe("GenieKey KEY123");
    expect(s.got[0]).toMatchObject({ url: "/v2/alerts", body: { alias: "a/b", priority: "P1" } });
    expect(s.got[1]?.url).toBe("/v2/alerts/a%2Fb/close?identifierType=alias");
  });

  it("generic webhook: signed with HMAC-SHA-256 and tagged with the event", async () => {
    const s = await httpSink();
    await createChannel({ type: "webhook", name: "w", url: s.url, secret: "shh", headers: { "x-team": "ops" } }).send(msg());
    const r = s.got[0]!;
    expect(r.headers["x-reversi-signature"]).toBe(`sha256=${createHmac("sha256", "shh").update(r.raw).digest("hex")}`);
    expect(r.headers["x-reversi-event"]).toBe("approval_requested");
    expect(r.headers["x-team"]).toBe("ops");
    expect(r.body).toMatchObject({ event: "approval_requested", severity: "warning", resolve: false });
  });

  it("retries transient failures, gives up on client errors, and never leaks the key", async () => {
    const s = await httpSink();
    s.fail(2);
    await createChannel({ type: "webhook", name: "w", url: s.url }, { sleep: noSleep }).send(msg());
    expect(s.got).toHaveLength(3);
    const bad = await httpSink(404);
    await expect(createChannel({ type: "pagerduty", name: "pd", routing_key: "SECRET-RK", url: `${bad.url}?token=SECRETTOKEN` }, { sleep: noSleep }).send(msg())).rejects.toThrow(/answered 404/);
    expect(bad.got).toHaveLength(1);
    await expect(createChannel({ type: "webhook", name: "w", url: "http://169.254.169.254/x" }, { sleep: noSleep }).send(msg())).rejects.toThrow(/metadata/);
  });

  it("validates channel and route config", () => {
    const errors: string[] = [];
    const ch = parseChannels([{ type: "slack", name: "a", url: "not a url" }, { type: "email", name: "a", host: "h" }, { type: "carrier-pigeon", name: "p" }, { type: "opsgenie", name: "o", api_key: "k", region: "mars" }], errors);
    expect(ch).toHaveLength(4);
    expect(errors.join("\n")).toMatch(/not a valid URL/);
    expect(errors.join("\n")).toMatch(/duplicate name/);
    expect(errors.join("\n")).toMatch(/port is required/);
    expect(errors.join("\n")).toMatch(/to must be a list/);
    expect(errors.join("\n")).toMatch(/type must be slack/);
    expect(errors.join("\n")).toMatch(/region must be us or eu/);
    const e2: string[] = [];
    parseRoutes([{ events: [], channels: ["ghost"] }], [{ type: "webhook", name: "w", url: "http://x" } as ChannelConfig], e2);
    expect(e2.join("\n")).toMatch(/events must be a list/);
    expect(e2.join("\n")).toMatch(/unknown channel `ghost`/);
    expect(parseRoutes(undefined, [{ type: "webhook", name: "w", url: "http://x" } as ChannelConfig], [])[0]).toMatchObject({ events: ["*"], channels: ["w"] });
  });
});

describe("notifier routing", () => {
  it("routes by event and severity, reports failures, and never throws", async () => {
    const a = await httpSink();
    const b = await httpSink();
    const errors: string[] = [];
    const n = new Notifier(
      [createChannel({ type: "webhook", name: "all", url: a.url }), createChannel({ type: "webhook", name: "pager", url: b.url }), createChannel({ type: "webhook", name: "dead", url: "http://127.0.0.1:1/x" }, { sleep: noSleep, attempts: 1 })],
      [{ events: ["*"], channels: ["all"] }, { events: ["rollback_failed"], channels: ["pager", "dead"], min_severity: "critical" }],
      (e, c) => errors.push(`${c}: ${e.message.slice(0, 30)}`),
    );
    expect(await n.notify(msg({ event: "approval_requested" }))).toEqual({ sent: ["all"], failed: [] });
    expect(await n.notify(msg({ event: "rollback_failed", severity: "warning" }))).toEqual({ sent: ["all"], failed: [] }); // below min severity for the pager route
    const r = await n.notify(msg({ event: "rollback_failed", severity: "critical" }));
    expect(r.sent.sort()).toEqual(["all", "pager"]);
    expect(r.failed).toEqual(["dead"]);
    expect(errors).toHaveLength(1);
    expect(() => new Notifier([], [{ events: ["*"], channels: ["nope"] }])).toThrow(/unknown channel/);
  });
});

describe("SMTP", () => {
  function fakeSmtp(opts: { rejectRcpt?: boolean; requireAuth?: boolean } = {}) {
    const session: string[] = [];
    let data = "";
    const server = createTcp((sock: Socket) => {
      let buf = "";
      let inData = false;
      sock.on("error", () => {});
      const reply = (s: string) => sock.write(s + "\r\n");
      reply("220 fake ESMTP");
      sock.on("data", (d) => {
        buf += d.toString();
        let i: number;
        while ((i = buf.indexOf("\r\n")) >= 0) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 2);
          if (inData) {
            if (line === ".") {
              inData = false;
              reply("250 queued");
            } else data += line + "\n";
            continue;
          }
          session.push(line.startsWith("AUTH") ? "AUTH <redacted>" : line);
          if (line.startsWith("EHLO")) {
            sock.write("250-fake\r\n250 AUTH PLAIN\r\n");
          } else if (line.startsWith("AUTH PLAIN")) reply(Buffer.from(line.slice(11), "base64").toString() === "\u0000mailer\u0000pw" ? "235 ok" : "535 bad credentials");
          else if (line.startsWith("MAIL FROM")) reply("250 ok");
          else if (line.startsWith("RCPT TO")) reply(opts.rejectRcpt ? "550 no such user" : "250 ok");
          else if (line === "DATA") {
            inData = true;
            reply("354 go");
          } else if (line === "QUIT") sock.end("221 bye\r\n");
          else reply("500 what");
        }
      });
    });
    return new Promise<{ port: number; session: string[]; data: () => string }>((r) =>
      server.listen(0, "127.0.0.1", () => {
        closers.push(() => server.close());
        r({ port: (server.address() as AddressInfo).port, session, data: () => data });
      }),
    );
  }

  it("sends a message with authentication, base64 body and an encoded subject", async () => {
    const s = await fakeSmtp();
    await sendMail({ host: "127.0.0.1", port: s.port, starttls: false, user: "mailer", pass: "pw", from: "reversi@example.com" }, { to: ["a@example.com", "b@example.com"], subject: "Approval needed: café", text: "Line one\nLine two ✓" });
    expect(s.session).toEqual(["EHLO reversi", "AUTH <redacted>", "MAIL FROM:<reversi@example.com>", "RCPT TO:<a@example.com>", "RCPT TO:<b@example.com>", "DATA", "QUIT"]);
    const d = s.data();
    expect(d).toContain("Subject: =?UTF-8?B?");
    expect(d).toContain("To: a@example.com, b@example.com");
    const body = d.split("\n\n")[1]!.replace(/\n/g, "");
    expect(Buffer.from(body, "base64").toString("utf8")).toBe("Line one\nLine two ✓");
  });

  it("surfaces rejections without leaking the password, and refuses header injection", async () => {
    const s = await fakeSmtp();
    await expect(sendMail({ host: "127.0.0.1", port: s.port, starttls: false, user: "mailer", pass: "wrong", from: "a@example.com" }, { to: ["x@example.com"], subject: "s", text: "t" })).rejects.toThrow(/SMTP AUTH failed: 535 bad credentials/);
    const r = await fakeSmtp({ rejectRcpt: true });
    await expect(sendMail({ host: "127.0.0.1", port: r.port, starttls: false, from: "a@example.com" }, { to: ["x@example.com"], subject: "s", text: "t" })).rejects.toThrow(/550/);
    await expect(sendMail({ host: "127.0.0.1", port: s.port, from: "a@example.com" }, { to: ["x@example.com\r\nBcc: evil@example.com"], subject: "s", text: "t" })).rejects.toThrow(/invalid address/);
    await expect(sendMail({ host: "127.0.0.1", port: 1, from: "a@example.com" }, { to: ["x@example.com"], subject: "s", text: "t" })).rejects.toThrow();
  });

  it("the email channel uses it and does not retry a permanent rejection", async () => {
    const s = await fakeSmtp({ rejectRcpt: true });
    await expect(createChannel({ type: "email", name: "m", host: "127.0.0.1", port: s.port, starttls: false, from: "a@example.com", to: ["x@example.com"] }, { sleep: noSleep }).send(msg())).rejects.toThrow(/550/);
    expect(s.session.filter((l) => l.startsWith("EHLO"))).toHaveLength(1);
    const ok = await fakeSmtp();
    await createChannel({ type: "email", name: "m", host: "127.0.0.1", port: ok.port, starttls: false, from: "a@example.com", to: ["x@example.com"] }).send(msg({ severity: "critical" }));
    expect(ok.data()).toContain("Subject: [Reversi critical] Approval needed: pay");
  });
});

const MANIFESTS = [
  { tool: "pay", effect: "compensable", permission: "p", compensation: { tool: "refund" } },
  { tool: "refund", effect: "idempotent", permission: "p" },
  { tool: "mail", effect: "irreversible", permission: "p" },
];

function engine(over: object = {}) {
  const approvals = new Approvals();
  const rv = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(), approver: approvals.asApprover(), kv: new MemoryKvStore(), ...over });
  return { rv, approvals };
}

describe("event hub", () => {
  it("describes the records a human cares about, and ignores routine ones", async () => {
    const { rv, approvals } = engine();
    const seen: NotifyMessage[] = [];
    const notifier = { notifyLater: (m: NotifyMessage) => seen.push(m) } as unknown as Notifier;
    attachNotifications({ reversi: rv, notifier, console_url: "https://r.example.com" });
    const run = rv.startRun({ run_id: "r1", actor: "agent", scope: SealedScope.seal(["p"]) });
    await run.call({ tool: "unknown", reason: "x", execute: () => 1 });
    approvals.add("r1", "call", "mail", 1, "ops");
    await run.call({ tool: "mail", reason: "x", execute: () => "sent" });
    await run.call({ tool: "pay", reason: "x", execute: () => ({}) });
    await run.rollback({ compensate: () => { throw new Error("gateway timeout"); } });
    expect(seen.map((m) => m.event)).toEqual(["unclassified_mutation", "irreversible_executed", "rollback_failed"]);
    expect(seen[0]).toMatchObject({ severity: "warning", dedup_key: "unclassified:unknown", link: "https://r.example.com/console/runs/r1" });
    expect(seen[2]).toMatchObject({ severity: "critical", dedup_key: "comp:r1:1" });
    expect(seen[2]?.text).toContain("gateway timeout");
  });

  it("builds approval notifications with buttons data and no argument values", () => {
    const rec = { id: "apr_9", run_id: "r1", step: null, kind: "call", tool: "pay", reason: "x", triggers: ["policy `big`"], arg_keys: ["amount"], args_hash: "h", status: "pending", requested_ms: 1, expires_ms: 2, decided_by: null, decided_ms: null, decision_note: null, quorum: 2 } as never;
    const req = approvalNotification(rec, "requested", "https://r.example.com");
    expect(req).toMatchObject({ event: "approval_requested", approval: { id: "apr_9", tool: "pay" }, link: "https://r.example.com/console/approvals" });
    expect(JSON.stringify(req)).not.toMatch(/amount":\s*\d/);
    expect(approvalNotification({ ...(rec as object), status: "approved", decided_by: "alice" } as never, "decided").resolve).toBe(true);
    expect(approvalNotification(rec, "escalated").text).toContain("Nobody answered in time");
  });
});

describe("alerts", () => {
  async function troubled() {
    const { rv, approvals } = engine({ policy: Policy.from({ budgets: [{ id: "daily", match: { tool: "pay" }, metric: "calls", max: 2, window_seconds: 3600, per: "global", warn_at: 0.5 }] }) });
    const run = rv.startRun({ run_id: "r1", actor: "agent", scope: SealedScope.seal(["p"]) });
    await run.call({ tool: "pay", reason: "x", execute: () => ({}) });
    await run.call({ tool: "pay", reason: "x", execute: () => ({}) }); // at 100%: warning recorded
    await run.rollback({ compensate: () => { throw new Error("down"); } });
    for (let i = 0; i < 10; i++) await run.call({ tool: "ghost", reason: "x", execute: () => 1 });
    const b = await run.begin({ tool: "pay", reason: "x" }); // blocked by the budget
    void b;
    approvals.add("r1", "call", "mail", 1);
    await run.call({ tool: "mail", reason: "x", execute: () => "sent" });
    rv.halt("incident", { tool: "pay" });
    return { rv, approvals, run };
  }

  it("finds failed rollbacks, spikes, irreversible actions, budgets, unclassified tools, halts and unhealthy upstreams", async () => {
    const { rv, approvals } = await troubled();
    const alerts = evaluateAlerts(rv, approvals, { health: [{ name: "github", ok: false }, { name: "fs", ok: true }] });
    const kinds = alerts.map((a) => a.kind);
    for (const k of ["compensation_failed", "policy_denial_spike", "irreversible_executed", "budget_threshold", "unclassified_mutation", "halted", "upstream_unhealthy"]) expect(kinds, k).toContain(k);
    expect(alerts[0]?.severity).toBe("critical"); // critical first
    expect(alerts.find((a) => a.kind === "budget_threshold")?.title).toContain("daily");
    expect(new Set(alerts.map((a) => a.id)).size).toBe(alerts.length);
    const quiet = engine();
    expect(evaluateAlerts(quiet.rv, quiet.approvals)).toEqual([]);
  });

  it("flags outcomes unknown for too long and approvals that timed out", async () => {
    const { rv, approvals } = engine();
    const run = rv.startRun({ run_id: "r1", actor: "a", scope: SealedScope.seal(["p"]) });
    const b = await run.begin({ tool: "pay", reason: "x" });
    if (b.decision === "allow") run.complete(b.step, { status: "uncertain", error: "timeout" });
    const later = Date.now() + 2 * 3_600_000;
    expect(evaluateAlerts(rv, approvals, { now: later }).map((a) => a.kind)).toContain("unresolved_outcome");
    expect(evaluateAlerts(rv, approvals, {}).map((a) => a.kind)).not.toContain("unresolved_outcome");
  });

  it("the manager sends once, reminds later, and resolves when the condition clears", async () => {
    const { rv, approvals } = engine();
    const sink = await httpSink();
    const notifier = new Notifier([createChannel({ type: "webhook", name: "w", url: sink.url })], [{ events: ["alert"], channels: ["w"] }]);
    const kv = new MemoryKvStore();
    const mgr = new AlertManager(rv, approvals, kv, notifier, { remind_ms: 1000 });
    const run = rv.startRun({ run_id: "r1", actor: "a", scope: SealedScope.seal(["p"]) });
    await run.call({ tool: "pay", reason: "x", execute: () => ({}) });
    await run.rollback({ compensate: () => { throw new Error("down"); } });
    const t0 = Date.now();
    expect((await mgr.tick(t0)).fired).toEqual(["comp:r1:0"]);
    expect((await mgr.tick(t0 + 10)).fired).toEqual([]); // already told
    expect((await mgr.tick(t0 + 2000)).fired).toEqual(["comp:r1:0"]); // reminder
    expect(sink.got.map((g) => g.body.resolve)).toEqual([false, false]);
    // fixed by a retry
    await run.rollback({ compensate: () => {} });
    const res = await mgr.tick(t0 + 3000);
    expect(res.resolved).toEqual(["comp:r1:0"]);
    expect(sink.got.at(-1)?.body).toMatchObject({ resolve: true, dedup_key: "comp:r1:0", severity: "info" });
    expect((await mgr.tick(t0 + 4000)).resolved).toEqual([]);
    // a second manager sharing the store does not repeat what the first sent
    await run.call({ tool: "pay", reason: "x", execute: () => ({}) });
    await run.rollback({ compensate: () => { throw new Error("down again"); } });
    const other = new AlertManager(rv, approvals, kv, notifier, { remind_ms: 1000 });
    const [a, b] = await Promise.all([mgr.tick(t0 + 5000), other.tick(t0 + 5000)]);
    expect(a.fired.length + b.fired.length).toBe(1);
  });
});

describe("OpenTelemetry export", () => {
  it("exports a span per call and per compensation, with names and ids but no arguments", async () => {
    const s = await httpSink();
    const { rv } = engine();
    const otel = new OtelExporter({ endpoint: s.url, headers: { "x-api-key": "k" }, service_version: "1.2.3", environment: "prod", interval_ms: 60_000 }, rv);
    otel.start();
    const run = rv.startRun({ run_id: "r1", actor: "agent", scope: SealedScope.seal(["p"]) });
    await run.call({ tool: "pay", args: { card: "4111 1111 1111 1111" }, reason: "customer asked", execute: () => ({ id: 1 }) });
    await run.call({ tool: "ghost", reason: "x", execute: () => 1 }); // blocked
    await run.call({ tool: "pay", reason: "x", execute: () => { throw new Error("boom"); } }).catch(() => {});
    await run.rollback({ compensate: () => {} });
    await otel.stop();
    expect(s.got).toHaveLength(1);
    expect(s.got[0]?.url).toBe("/v1/traces");
    expect(s.got[0]?.headers["x-api-key"]).toBe("k");
    const rs = s.got[0]?.body.resourceSpans[0];
    const res = Object.fromEntries(rs.resource.attributes.map((a: any) => [a.key, Object.values(a.value)[0]]));
    expect(res).toMatchObject({ "service.name": "reversi", "service.version": "1.2.3", "deployment.environment": "prod" });
    const spans = rs.scopeSpans[0].spans;
    expect(spans.map((x: any) => x.name)).toEqual(["reversi.call pay", "reversi.call.blocked ghost", "reversi.call pay", "reversi.compensate refund"]);
    expect(spans.map((x: any) => x.status.code)).toEqual([1, 2, 2, 1]);
    expect(spans[0].traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(spans[0].spanId).toMatch(/^[0-9a-f]{16}$/);
    expect(new Set(spans.map((x: any) => x.traceId)).size).toBe(1); // one trace per run
    expect(new Set(spans.map((x: any) => x.spanId)).size).toBe(4);
    expect(BigInt(spans[0].endTimeUnixNano)).toBeGreaterThanOrEqual(BigInt(spans[0].startTimeUnixNano));
    const attrs = Object.fromEntries(spans[0].attributes.map((a: any) => [a.key, Object.values(a.value)[0]]));
    expect(attrs).toMatchObject({ "reversi.run_id": "r1", "reversi.tool": "pay", "reversi.effect": "compensable", "reversi.actor": "agent", "reversi.reason": "customer asked" });
    expect(JSON.stringify(s.got[0]?.body)).not.toContain("4111");
  });

  it("batches, and reports a failing collector without throwing", async () => {
    const s = await httpSink(500);
    const errors: string[] = [];
    const { rv } = engine();
    const otel = new OtelExporter({ endpoint: s.url, batch: 2, onError: (e) => errors.push(e.message) }, rv);
    otel.start();
    const run = rv.startRun({ actor: "a", scope: SealedScope.seal(["p"]) });
    await run.call({ tool: "pay", reason: "x", execute: () => 1 });
    expect(s.got).toHaveLength(0);
    await run.call({ tool: "pay", reason: "x", execute: () => 1 });
    await new Promise((r) => setTimeout(r, 50));
    expect(s.got).toHaveLength(1); // flushed at two spans
    await otel.stop();
    expect(errors[0]).toBe("collector answered 500");
  });
});

describe("structured logger", () => {
  it("writes JSON lines, filters by level, and redacts by key and by value", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "info", write: (l) => lines.push(l), base: { app: "reversi" }, now: () => new Date("2026-10-15T00:00:00Z") });
    log.debug("hidden");
    log.info("request", { path: "/v1/runs", authorization: "Bearer abc", nested: { apiKey: "k", note: "token ghp_" + "a".repeat(36) }, err: new Error("failed with password=hunter2hunter2") });
    log.child({ run: "r1" }).warn("careful", { token: "x" });
    expect(lines).toHaveLength(2);
    const a = JSON.parse(lines[0] as string);
    expect(a).toMatchObject({ level: "info", time: "2026-10-15T00:00:00.000Z", msg: "request", app: "reversi", path: "/v1/runs", authorization: "[REDACTED]", nested: { apiKey: "[REDACTED]", note: "token [REDACTED:github_token]" } });
    expect(a.err.message).toContain("[REDACTED:credential_assignment]");
    expect(JSON.parse(lines[1] as string)).toMatchObject({ level: "warn", run: "r1", token: "[REDACTED]" });
    expect(lines.join("")).not.toContain("hunter2");
  });
});
