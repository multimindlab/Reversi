import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  GENESIS_HASH,
  JsonlLedgerStore,
  Ledger,
  LedgerError,
  SealedScope,
  ScopeError,
  parseJsonl,
  toJsonl,
  verifyRecords,
  type LedgerRecord,
} from "../src/index.js";

const dirs: string[] = [];
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), "reversi-test-"));
  dirs.push(d);
  return d;
};
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

function sample(): Ledger {
  const l = new Ledger();
  const base = { run_id: "run-1", actor: "agent-a" };
  l.append({ ...base, ts_ms: 1, step: 0, tool: "create_order", payload: { sku: "A1" }, reason: "customer asked", event: "intended" });
  l.append({ ...base, ts_ms: 2, step: 0, tool: "create_order", payload: { id: 9 }, reason: "customer asked", event: "succeeded" });
  l.append({ ...base, ts_ms: 3, step: null, tool: "send_email", payload: {}, reason: "confirmation", event: "blocked", detail: "needs approval" });
  return l;
}

describe("Ledger", () => {
  it("a fresh ledger verifies and starts from the genesis hash", () => {
    const l = sample();
    const v = l.verify();
    expect(v).toEqual({ ok: true, records: 3, head: l.head() });
    expect(l.records()[0]?.prev_hash).toBe(GENESIS_HASH);
  });

  it("an empty ledger verifies with the genesis head", () => {
    expect(new Ledger().head()).toBe(GENESIS_HASH);
    expect(new Ledger().verify()).toMatchObject({ ok: true, records: 0 });
  });

  it("rejects an empty or whitespace reason", () => {
    const l = new Ledger();
    expect(() =>
      l.append({ ts_ms: 1, run_id: "r", actor: "a", tool: "t", reason: "   ", event: "intended" }),
    ).toThrow(LedgerError);
    expect(l.records()).toHaveLength(0);
  });

  it("detects an edited record", () => {
    const recs = structuredClone(sample().records()) as LedgerRecord[];
    (recs[1] as LedgerRecord).tool = "refund";
    expect(verifyRecords(recs)).toMatchObject({ ok: false, seq: 1 });
  });

  it("detects a deleted record", () => {
    const recs = structuredClone(sample().records()) as LedgerRecord[];
    recs.splice(1, 1);
    expect(verifyRecords(recs).ok).toBe(false);
  });

  it("detects reordering", () => {
    const recs = structuredClone(sample().records()) as LedgerRecord[];
    [recs[0], recs[1]] = [recs[1] as LedgerRecord, recs[0] as LedgerRecord];
    expect(verifyRecords(recs).ok).toBe(false);
  });

  it("a record rewritten and re-hashed still breaks the next record", () => {
    const l = sample();
    const recs = structuredClone(l.records()) as LedgerRecord[];
    const forged = { ...(recs[0] as LedgerRecord), reason: "forged" };
    // Re-hash the forged record the way the ledger does.
    const { hash: _old, ...body } = forged;
    const probe = new Ledger();
    probe.append({ ts_ms: body.ts_ms, run_id: body.run_id, step: body.step, actor: body.actor, tool: body.tool, payload: { sku: "A1" }, reason: "forged", event: body.event });
    recs[0] = { ...forged, hash: (probe.records()[0] as LedgerRecord).hash, payload_hash: (probe.records()[0] as LedgerRecord).payload_hash };
    const v = verifyRecords(recs);
    expect(v.ok).toBe(false);
  });

  it("rejects malformed records instead of crashing", () => {
    expect(verifyRecords([{ seq: 0 } as unknown as LedgerRecord]).ok).toBe(false);
    expect(verifyRecords([null as unknown as LedgerRecord]).ok).toBe(false);
  });

  it("hashes payloads and never stores them", () => {
    const l = new Ledger();
    l.append({ ts_ms: 1, run_id: "r", actor: "a", tool: "login", payload: { password: "hunter2-secret" }, reason: "sign in", event: "intended" });
    const text = toJsonl(l.records());
    expect(text).not.toContain("hunter2-secret");
    expect(text).not.toContain("password");
  });

  it("JSONL round-trips and still verifies", () => {
    const l = sample();
    const back = parseJsonl(toJsonl(l.records()));
    expect(verifyRecords(back)).toMatchObject({ ok: true, head: l.head() });
  });

  it("parseJsonl names the offending line", () => {
    expect(() => parseJsonl('{"ok":1}\nnot json\n')).toThrow(/line 2/);
  });

  it("filters records by run", () => {
    const l = sample();
    l.append({ ts_ms: 4, run_id: "run-2", actor: "a", tool: "t", reason: "r", event: "run_started" });
    expect(l.forRun("run-2")).toHaveLength(1);
    expect(l.forRun("run-1")).toHaveLength(3);
  });
});

describe("JsonlLedgerStore", () => {
  it("persists across reopen and keeps the chain intact", () => {
    const path = join(tmp(), "ledger.jsonl");
    const a = new Ledger(new JsonlLedgerStore(path));
    a.append({ ts_ms: 1, run_id: "r", actor: "a", tool: "t", reason: "first", event: "run_started" });
    a.append({ ts_ms: 2, run_id: "r", actor: "a", tool: "t", reason: "second", event: "intended", step: 0 });
    const b = new Ledger(new JsonlLedgerStore(path));
    expect(b.records()).toHaveLength(2);
    b.append({ ts_ms: 3, run_id: "r", actor: "a", tool: "t", reason: "third", event: "succeeded", step: 0 });
    const c = new Ledger(new JsonlLedgerStore(path));
    expect(c.verify()).toMatchObject({ ok: true, records: 3 });
    expect(readFileSync(path, "utf8").trim().split("\n")).toHaveLength(3);
  });

  it("refuses to open a tampered file", () => {
    const path = join(tmp(), "ledger.jsonl");
    const a = new Ledger(new JsonlLedgerStore(path));
    a.append({ ts_ms: 1, run_id: "r", actor: "a", tool: "pay", reason: "x", event: "intended", step: 0 });
    writeFileSync(path, readFileSync(path, "utf8").replace('"pay"', '"refund"'));
    expect(() => new Ledger(new JsonlLedgerStore(path))).toThrow(/corrupt/);
  });

  it("starts empty when the file does not exist", () => {
    const path = join(tmp(), "nope.jsonl");
    expect(new Ledger(new JsonlLedgerStore(path)).records()).toHaveLength(0);
    expect(existsSync(path)).toBe(false);
  });
});

describe("SealedScope", () => {
  it("checks permissions and verifies its seal", () => {
    const s = SealedScope.seal(["orders:read", "orders:write"]);
    expect(s.has("orders:read")).toBe(true);
    expect(s.has("mail:send")).toBe(false);
    expect(s.verify()).toBe(true);
  });

  it("the seal is order independent, content sensitive and de-duplicated", () => {
    const a = SealedScope.seal(["x", "y"]);
    expect(SealedScope.seal(["y", "x"]).seal).toBe(a.seal);
    expect(SealedScope.seal(["x", "x", "y"]).seal).toBe(a.seal);
    expect(SealedScope.seal(["x", "y", "z"]).seal).not.toBe(a.seal);
  });

  it("concatenated permissions cannot collide", () => {
    expect(SealedScope.seal(["ab", "c"]).seal).not.toBe(SealedScope.seal(["a", "bc"]).seal);
  });

  it("attenuation narrows, records the parent seal, and never widens", () => {
    const parent = SealedScope.seal(["orders:read", "orders:write"]);
    const child = parent.attenuate(["orders:read"]);
    expect(child.parentSeal).toBe(parent.seal);
    expect(child.verify()).toBe(true);
    expect(child.has("orders:write")).toBe(false);
    expect(() => parent.attenuate(["mail:send"])).toThrow(ScopeError);
    // The same permission set sealed standalone differs from the attenuated one: lineage is part of the seal.
    expect(child.seal).not.toBe(SealedScope.seal(["orders:read"]).seal);
  });

  it("restore accepts matching data and rejects tampered permissions", () => {
    const s = SealedScope.seal(["a"]);
    expect(SealedScope.restore(["a"], s.seal, null).has("a")).toBe(true);
    expect(() => SealedScope.restore(["a", "b"], s.seal, null)).toThrow(ScopeError);
    const child = s.attenuate(["a"]);
    expect(SealedScope.restore(["a"], child.seal, s.seal).verify()).toBe(true);
    expect(() => SealedScope.restore(["a"], child.seal, null)).toThrow(ScopeError);
  });

  it("returned permission lists are copies", () => {
    const s = SealedScope.seal(["a"]);
    s.permissions().push("b");
    expect(s.has("b")).toBe(false);
    expect(s.verify()).toBe(true);
  });
});
