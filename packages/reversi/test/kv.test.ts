import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { FileKvStore, KvConflictError, MemoryKvStore, kvUpdate, type KvStore } from "../src/index.js";
import { openSqliteStores } from "../src/sqlite.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), "rv-kv-"));
  dirs.push(d);
  return d;
};

function suite(name: string, make: () => { kv: KvStore; close?: () => void }) {
  describe(`KvStore: ${name}`, () => {
    it("stores, versions, lists by prefix and deletes", () => {
      const { kv, close } = make();
      expect(kv.get("n", "a")).toBeUndefined();
      kv.put("n", "a", { x: 1 });
      expect(kv.get("n", "a")).toEqual({ key: "a", value: { x: 1 }, version: 1 });
      kv.put("n", "a", { x: 2 });
      expect(kv.get("n", "a")?.version).toBe(2);
      kv.put("n", "ab/1", 1);
      kv.put("n", "b", 2);
      kv.put("other", "a", 3);
      expect(kv.list("n").map((e) => e.key)).toEqual(["a", "ab/1", "b"]);
      expect(kv.list("n", "a").map((e) => e.key)).toEqual(["a", "ab/1"]);
      expect(kv.delete("n", "a")).toBe(true);
      expect(kv.delete("n", "a")).toBe(false);
      expect(kv.get("other", "a")?.value).toBe(3);
      close?.();
    });

    it("compare-and-set only succeeds with the expected version", () => {
      const { kv, close } = make();
      expect(kv.cas("n", "k", "first", 0)).toBe(true);
      expect(kv.cas("n", "k", "again", 0)).toBe(false); // already exists
      expect(kv.cas("n", "k", "stale", 5)).toBe(false);
      expect(kv.cas("n", "k", "second", 1)).toBe(true);
      expect(kv.get("n", "k")).toMatchObject({ value: "second", version: 2 });
      close?.();
    });

    it("kvUpdate retries until its write lands, even when another writer interleaves", () => {
      const { kv, close } = make();
      let interfered = false;
      const out = kvUpdate<number>(kv, "n", "counter", (cur) => {
        if (!interfered) {
          interfered = true;
          kv.put("n", "counter", 100); // someone else writes between our read and write
        }
        return (cur ?? 0) + 1;
      });
      expect(out).toBe(101);
      expect(kv.get("n", "counter")?.value).toBe(101);
      close?.();
    });

    it("kvUpdate gives up with a clear error under endless contention", () => {
      const { kv, close } = make();
      expect(() => kvUpdate<number>(kv, "n", "k", (c) => { kv.put("n", "k", Math.random()); return (c ?? 0) + 1; }, 3)).toThrow(KvConflictError);
      close?.();
    });
  });
}

suite("memory", () => ({ kv: new MemoryKvStore() }));
suite("file", () => ({ kv: new FileKvStore(join(tmp(), "nested", "settings.json")) }));
suite("sqlite", () => {
  const s = openSqliteStores(join(tmp(), "r.db"));
  return { kv: s.kv, close: () => s.db.close() };
});

describe("file KvStore shared by two instances", () => {
  it("sees each other's writes", () => {
    const f = join(tmp(), "s.json");
    const a = new FileKvStore(f);
    const b = new FileKvStore(f);
    a.put("n", "k", 1);
    expect(b.get("n", "k")?.value).toBe(1);
    expect(b.cas("n", "k", 2, 1)).toBe(true);
    expect(a.get("n", "k")?.version).toBe(2);
  });
});

const pgUrl = process.env.REVERSI_TEST_PG;
describe.skipIf(!pgUrl)("KvStore: postgres", () => {
  it("behaves like the others", async () => {
    const { SyncPg, openPostgresStores } = await import("../src/postgres.js");
    const schema = `rv_kv_${randomBytes(5).toString("hex")}`;
    const admin = new SyncPg(pgUrl as string);
    admin.query(`CREATE SCHEMA ${schema}`);
    admin.close();
    const u = new URL(pgUrl as string);
    u.searchParams.set("options", `-c search_path=${schema}`);
    const s = openPostgresStores(u.toString());
    s.kv.put("n", "a", { x: 1 });
    expect(s.kv.cas("n", "a", { x: 2 }, 1)).toBe(true);
    expect(s.kv.cas("n", "a", { x: 3 }, 1)).toBe(false);
    expect(s.kv.cas("n", "new", 1, 0)).toBe(true);
    expect(s.kv.list("n").map((e) => e.key)).toEqual(["a", "new"]);
    expect(s.kv.delete("n", "a")).toBe(true);
    s.pg.close();
  });
});
