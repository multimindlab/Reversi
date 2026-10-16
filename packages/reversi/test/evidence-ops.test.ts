import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  Approvals,
  CaptureStore,
  EgressError,
  Ledger,
  LegalHolds,
  MemoryKvStore,
  Registry,
  Reversi,
  SealedScope,
  anchorLedger,
  applyRetention,
  checkUrl,
  generateSigningKey,
  guardedFetch,
  isMetadataAddress,
  isPrivateAddress,
  parsePolicy,
  planRetention,
  readAnchors,
  renderPdf,
  renderReportPdf,
  searchRecords,
  searchRuns,
  verifyAnchor,
  verifyBundle,
  type EvidenceBundle,
} from "../src/index.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), "rv-ev-"));
  dirs.push(d);
  return d;
};

const MANIFESTS = [
  { tool: "orders.create", effect: "reversible", permission: "p", compensation: { tool: "orders.cancel", argument_map: { id: "$result.id" } } },
  { tool: "orders.cancel", effect: "idempotent", permission: "p" },
  { tool: "mail.send", effect: "irreversible", permission: "p", audit: { evidence_export: "required", retention_days: 400 } },
  { tool: "read", effect: "read_only", permission: "p" },
];

async function world(clock: { t: number }) {
  const kv = new MemoryKvStore();
  const approvals = new Approvals();
  const capture = new CaptureStore(kv, { enabled: true, ttl_ms: 800 * 86_400_000 }, () => clock.t);
  const rv = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(), approver: approvals.asApprover(), kv, capture, now: () => clock.t });
  return { rv, kv, approvals, capture, holds: new LegalHolds(kv, () => clock.t) };
}

describe("search", () => {
  it("filters runs and records, with pagination", async () => {
    const clock = { t: Date.parse("2026-10-01T00:00:00Z") };
    const { rv } = await world(clock);
    const mk = async (id: string, actor: string, tenant: string | undefined, tool: string, fail = false) => {
      const run = rv.startRun({ run_id: id, actor, tenant, scope: SealedScope.seal(["p"]) });
      await run.call({ tool, reason: "x", execute: () => (fail ? Promise.reject(new Error("boom")) : { id: 1 }) }).catch(() => {});
      clock.t += 1000;
      return run;
    };
    const a = await mk("run-a", "alice", "acme", "orders.create");
    await a.rollback({ compensate: () => {} });
    await mk("run-b", "bob", "globex", "read");
    await mk("run-c", "alice", "acme", "mail.send"); // blocked: needs approval; no steps
    const d = rv.startRun({ run_id: "run-d", actor: "bob", scope: SealedScope.seal(["p"]) });
    const bg = await d.begin({ tool: "orders.create", reason: "x" });
    if (bg.decision === "allow") d.complete(bg.step, { status: "uncertain", error: "timeout" });

    const status = (id: string) => searchRuns(rv).runs.find((r) => r.run_id === id)?.status;
    expect(status("run-a")).toBe("rolled_back");
    expect(status("run-b")).toBe("complete");
    expect(status("run-c")).toBe("blocked_only");
    expect(status("run-d")).toBe("needs_attention");
    expect(searchRuns(rv, { actor: "alice" }).runs.map((r) => r.run_id)).toEqual(["run-a", "run-c"]);
    expect(searchRuns(rv, { tenant: "globex" }).runs.map((r) => r.run_id)).toEqual(["run-b"]);
    expect(searchRuns(rv, { tool: "orders.create" }).runs.map((r) => r.run_id)).toEqual(["run-a", "run-d"]);
    expect(searchRuns(rv, { status: "needs_attention" }).runs.map((r) => r.run_id)).toEqual(["run-d"]);
    expect(searchRuns(rv, { since_ms: Date.parse("2026-10-01T00:00:02Z") }).runs.map((r) => r.run_id)).toEqual(["run-c", "run-d"].filter((x) => rv.openRun(x).state().created_ms >= Date.parse("2026-10-01T00:00:02Z")));
    const page1 = searchRuns(rv, { limit: 2 });
    expect(page1.runs).toHaveLength(2);
    expect(searchRuns(rv, { limit: 2, after: page1.next }).runs.map((r) => r.run_id)).toEqual(["run-c", "run-d"]);

    expect(searchRecords(rv, { event: "compensated" }).records).toHaveLength(1);
    expect(searchRecords(rv, { run_id: "run-c", event: ["blocked"] }).records[0]?.detail).toContain("approval required");
    expect(searchRecords(rv, { text: "TIMEOUT" }).records).toHaveLength(1);
    const p = searchRecords(rv, { limit: 3 });
    expect(p.records).toHaveLength(3);
    expect(searchRecords(rv, { limit: 3, after_seq: p.next_seq }).records[0]?.seq).toBe((p.next_seq ?? 0) + 1);
  });
});

describe("retention and legal hold", () => {
  const DAY = 86_400_000;
  it("purges only runs past their retention, never held ones, and records it in the ledger", async () => {
    const clock = { t: Date.parse("2026-01-01T00:00:00Z") };
    const { rv, approvals, capture, holds } = await world(clock);
    for (const id of ["old", "held", "fresh"]) {
      const run = rv.startRun({ run_id: id, actor: "a", tenant: id === "held" ? "acme" : undefined, scope: SealedScope.seal(["p"]) });
      await run.call({ tool: "read", args: { q: id }, reason: "x", execute: () => 1 });
      clock.t += id === "old" ? 60 * DAY : id === "held" ? 40 * DAY : 0;
    }
    holds.add({ tenant: "acme" }, "case 2026-77 litigation", "legal");
    const cfg = { default_days: 30, rules: [] };
    const now = clock.t;
    const plan = planRetention(rv, cfg, holds, now);
    expect(plan.map((p) => [p.run_id, p.due, !!p.held])).toEqual([["old", true, false], ["held", true, true], ["fresh", false, false]]);

    const dry = applyRetention(rv, cfg, { holds, approvals, capture, dry_run: true, now });
    expect(dry).toMatchObject({ dry_run: true, purged: ["old"] });
    expect(rv.runIds()).toHaveLength(3); // dry run changed nothing

    const rep = applyRetention(rv, cfg, { holds, approvals, capture, now });
    expect(rep.purged).toEqual(["old"]);
    expect(rep.skipped).toEqual([{ run_id: "held", reason: expect.stringContaining("legal hold") }]);
    expect(rv.runIds().sort()).toEqual(["fresh", "held"]);
    expect(capture.list({ run_id: "old" })).toEqual([]);
    expect(capture.list({ run_id: "held" })).toHaveLength(1);
    const purged = rv.ledger.records().filter((r) => r.event === "purged");
    expect(purged).toHaveLength(1);
    expect(purged[0]).toMatchObject({ run_id: "old", reason: "retention: older than 30 days" });
    expect(rv.ledger.verify().ok).toBe(true); // the ledger stays intact and keeps every record
    holds.release(holds.list()[0]!.id);
    expect(applyRetention(rv, cfg, { holds, approvals, capture, now }).purged).toEqual(["held"]);
  });

  it("a manifest that requires evidence export keeps the run until an archive and key are given, then archives a verifiable bundle", async () => {
    const clock = { t: Date.parse("2026-01-01T00:00:00Z") };
    const { rv, approvals, capture } = await world(clock);
    const run = rv.startRun({ run_id: "m1", actor: "a", scope: SealedScope.seal(["p"]) });
    const asked = await run.begin({ tool: "mail.send", reason: "x" });
    expect(asked.decision).toBe("block");
    // an approved, executed irreversible call
    const approvals2 = approvals;
    approvals2.add("m1", "call", "mail.send", 1, "ops");
    await run.call({ tool: "mail.send", reason: "x", execute: () => "sent" });
    clock.t += 500 * DAY; // past mail.send's 400-day retention
    const cfg = { default_days: 30, rules: [] };
    expect(applyRetention(rv, cfg, { approvals, capture, now: clock.t }).skipped[0]?.reason).toContain("requires an evidence bundle");
    expect(rv.runIds()).toEqual(["m1"]);
    const dir = tmp();
    const key = generateSigningKey();
    const rep = applyRetention(rv, cfg, { approvals, capture, archive_dir: join(dir, "archive"), key, now: clock.t });
    expect(rep.purged).toEqual(["m1"]);
    const bundle = JSON.parse(readFileSync(rep.exported[0]!.file, "utf8")) as EvidenceBundle;
    expect(verifyBundle(bundle, { trusted_public_pem: key.public_pem })).toMatchObject({ ok: true, chain: "per-record" });
    expect(rv.ledger.records().at(-1)?.detail).toContain("evidence bundle archived");
  });

  it("holds need a scope and a reason", () => {
    const h = new LegalHolds(new MemoryKvStore());
    expect(() => h.add({}, "reason here", "x")).toThrow(/scope/);
    expect(() => h.add({ run_id: "r" }, "hi", "x")).toThrow(/reason/);
    const hold = h.add({ tool: "mail.send" }, "matter 12345", "legal");
    expect(h.list({ all: true })).toHaveLength(1);
    expect(h.release(hold.id)).toBe(true);
    expect(h.release(hold.id)).toBe(false);
    expect(h.list()).toHaveLength(0);
  });

  it("retention config is validated and lives in the policy file", () => {
    expect(parsePolicy({ retention: { default_days: 90, rules: [{ match: { tool: "pay.*" }, days: 400 }] } }).retention?.default_days).toBe(90);
    expect(() => parsePolicy({ retention: { default_days: 0 } })).toThrow(/positive integer/);
    expect(() => parsePolicy({ retention: { default_days: 5, rules: [{ match: { colour: "x" }, days: 1 }] } })).toThrow(/unknown match field/);
  });
});

describe("egress control", () => {
  it("classifies addresses", () => {
    for (const ip of ["10.1.2.3", "127.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.255", "169.254.1.1", "100.64.0.1", "::1", "fd12::1", "fe80::1", "::ffff:10.0.0.1"]) expect(isPrivateAddress(ip), ip).toBe(true);
    for (const ip of ["8.8.8.8", "172.32.0.1", "1.1.1.1", "2606:4700::1111"]) expect(isPrivateAddress(ip), ip).toBe(false);
    expect(isMetadataAddress("169.254.169.254")).toBe(true);
    expect(isMetadataAddress("::ffff:169.254.169.254")).toBe(true);
    expect(isMetadataAddress("8.8.8.8")).toBe(false);
  });

  it("applies the allowlist, the private block and the always-on metadata block", async () => {
    await expect(checkUrl(undefined, "http://169.254.169.254/latest/meta-data")).rejects.toThrow(/metadata/);
    await expect(checkUrl(undefined, "ftp://example.com")).rejects.toThrow(/only http/);
    await expect(checkUrl({ block_private: true }, "http://127.0.0.1:9000/x")).rejects.toThrow(/private or loopback/);
    await expect(checkUrl({ block_private: true }, "http://[::1]/x")).rejects.toThrow(EgressError);
    expect((await checkUrl(undefined, "http://127.0.0.1:9000/x")).port).toBe("9000"); // fine for local development
    await expect(checkUrl({ allow: ["*.eu.example.com"], region: "eu" }, "https://hooks.us.example.com/x")).rejects.toThrow(/not in the egress allowlist \(region eu\)/);
    await expect(checkUrl({ allow: ["*.eu.example.com"] }, "http://127.0.0.1/x")).rejects.toThrow(/allowlist/);
    expect((await checkUrl({ allow: ["127.0.0.1"] }, "http://127.0.0.1:80/x")).hostname).toBe("127.0.0.1");
  });

  it("guardedFetch checks redirects too", async () => {
    const seen: string[] = [];
    const f = (async (url: URL | string) => {
      seen.push(String(url));
      return String(url).includes("start") ? new Response(null, { status: 302, headers: { location: "http://169.254.169.254/steal" } }) : new Response("ok");
    }) as unknown as typeof fetch;
    await expect(guardedFetch(undefined, f)("http://127.0.0.1/start")).rejects.toThrow(/metadata/);
    expect(seen).toEqual(["http://127.0.0.1/start"]);
    const ok = await guardedFetch(undefined, (async () => new Response("fine")) as unknown as typeof fetch)("http://127.0.0.1/a");
    expect(await ok.text()).toBe("fine");
  });
});

describe("external anchoring", () => {
  async function ledgerWith(n: number) {
    const l = new Ledger();
    for (let i = 0; i < n; i++) l.append({ ts_ms: i, run_id: "r", actor: "a", tool: "t", reason: `e${i}`, event: "run_started" });
    return l;
  }

  it("writes signed anchors to a file and a webhook, and proves later that history is unchanged", async () => {
    const dir = tmp();
    const key = generateSigningKey();
    const l = await ledgerWith(3);
    const posts: Array<{ body: string; sig?: string }> = [];
    const server = createServer((req, res) => {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        posts.push({ body: b, sig: req.headers["x-reversi-signature"] as string });
        res.end("ok");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/anchor`;
    try {
      const file = join(dir, "anchors.jsonl");
      const out = await anchorLedger(l, [{ type: "file", path: file }, { type: "webhook", url, secret: "s3" }], { key, egress: { region: "eu-west-1" }, now: 5 });
      expect(out.errors).toEqual([]);
      expect(out.delivered).toHaveLength(2);
      expect(out.anchor).toMatchObject({ records: 3, head: l.head(), region: "eu-west-1" });
      expect(posts[0]?.sig).toMatch(/^sha256=[0-9a-f]{64}$/);
      const stored = readAnchors(file)[0]!;
      expect(verifyAnchor(l, stored, key.public_pem)).toEqual({ ok: true, records: 3, signed: true });

      // the ledger grows: the old anchor still verifies
      l.append({ ts_ms: 9, run_id: "r", actor: "a", tool: "t", reason: "more", event: "run_started" });
      expect(verifyAnchor(l, stored)).toMatchObject({ ok: true });
      // truncation and rewrites are caught
      const truncated = await ledgerWith(2);
      expect(verifyAnchor(truncated, stored)).toMatchObject({ ok: false, error: expect.stringContaining("truncated") });
      const rewritten = new Ledger();
      for (let i = 0; i < 3; i++) rewritten.append({ ts_ms: i, run_id: "r", actor: "a", tool: "t", reason: `different${i}`, event: "run_started" });
      expect(verifyAnchor(rewritten, stored)).toMatchObject({ ok: false, error: expect.stringContaining("rewritten") });
      // a forged signature is rejected when a trusted key is required
      expect(verifyAnchor(l, { ...stored, head: stored.head }, generateSigningKey().public_pem)).toMatchObject({ ok: false, error: expect.stringContaining("signature") });
      expect(verifyAnchor(l, { ...stored, signature: undefined }, key.public_pem)).toMatchObject({ ok: false, error: expect.stringContaining("unsigned") });
    } finally {
      server.close();
    }
  });

  it("reports sink failures without losing the anchor, and honours egress rules", async () => {
    const l = await ledgerWith(1);
    const out = await anchorLedger(l, [{ type: "webhook", url: "http://169.254.169.254/x" }, { type: "file", path: "/nonexistent-dir/a.jsonl" }]);
    expect(out.delivered).toEqual([]);
    expect(out.errors).toHaveLength(2);
    expect(out.errors[0]).toContain("metadata");
    expect(existsSync("/nonexistent-dir")).toBe(false);
  });
});

describe("PDF report", () => {
  function parsePdf(buf: Buffer) {
    const text = buf.toString("latin1");
    const startxref = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(text)?.[1]);
    expect(text.slice(startxref, startxref + 4)).toBe("xref");
    const entries = [...text.slice(startxref).matchAll(/(\d{10}) \d{5} n /g)].map((m) => Number(m[1]));
    entries.forEach((off, i) => expect(text.slice(off, off + `${i + 1} 0 obj`.length), `object ${i + 1}`).toBe(`${i + 1} 0 obj`));
    const pages = [...text.matchAll(/\/Type \/Page \//g)].length;
    const kids = /\/Kids \[([^\]]*)\]/.exec(text)?.[1]?.match(/\d+ 0 R/g) ?? [];
    for (const k of kids) {
      const n = Number(k.split(" ")[0]);
      expect(text.slice(entries[n - 1]).split("endobj")[0]).toContain("/Type /Page ");
    }
    // stream lengths are right
    for (const m of text.matchAll(/\/Length (\d+) >>\nstream\n([\s\S]*?)\nendstream/g)) expect(Buffer.byteLength(m[2] as string, "latin1")).toBe(Number(m[1]));
    return { text, pages, kids: kids.length, entries: entries.length };
  }

  it("writes a structurally valid multi-page PDF with wrapped text and escaped characters", () => {
    const lines = Array.from({ length: 200 }, (_, i) => `line ${i} (parens) back\\slash ünïcode ✓ ${"x".repeat(i % 3 === 0 ? 200 : 5)}`);
    const pdf = renderPdf(["# Title", ...lines], "Test (doc)");
    expect(pdf.subarray(0, 8).toString()).toBe("%PDF-1.4");
    const info = parsePdf(pdf);
    expect(info.pages).toBeGreaterThan(2);
    expect(info.kids).toBe(info.pages);
    expect(info.text).toContain("\\(parens\\)");
    expect(info.text).toContain("back\\\\slash");
    expect(info.text).toContain("\\(doc\\)");
    expect(parsePdf(renderPdf([], "empty")).pages).toBe(1);
  });

  it("renders a run report", async () => {
    const clock = { t: Date.parse("2026-10-01T00:00:00Z") };
    const { rv } = await world(clock);
    const run = rv.startRun({ run_id: "rep-1", actor: "agent", scope: SealedScope.seal(["p"]) });
    await run.call({ tool: "orders.create", reason: "customer asked", execute: () => ({ id: 1 }) });
    const pdf = renderReportPdf({ run: run.state(), records: rv.ledger.forRun("rep-1"), plan: run.plan(), ledger_head: rv.ledger.head(), region: "eu-west-1", generated_ms: clock.t });
    const { text } = parsePdf(pdf);
    expect(text).toContain("Reversi report: run rep-1");
    expect(text).toContain("orders.create");
    expect(text).toContain("Data region: eu-west-1");
    expect(text).toContain("customer asked");
  });
});
