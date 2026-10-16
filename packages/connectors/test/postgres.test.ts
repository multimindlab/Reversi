import { EffectUncertainError, Registry } from "@multimindlab/reversi";
import { describe, expect, it } from "vitest";
import { compensatorFor, createPostgresConnector } from "../src/index.js";
import { fakePg, PASSWORD, URL_SECRET } from "./fixtures/postgres.js";
import { engine } from "./helpers.js";

function setup(opts: { connect?: boolean; timeoutMs?: number; maxRows?: number } = {}) {
  const pg = fakePg();
  const connector = createPostgresConnector({
    pool: opts.connect ? pg.withConnect : pg.pg,
    secrets: [URL_SECRET, PASSWORD],
    timeoutMs: opts.timeoutMs,
    maxRows: opts.maxRows,
  });
  const t = (n: string, a: Record<string, unknown>) => connector.tools[`postgres.${n}`]!(a, {});
  const sql = () => pg.calls.map((c) => c.url);
  const log = () => pg.calls.map((c) => [c.url, JSON.parse(c.body)]);
  return { pg, connector, t, sql, log };
}

const HOSTILE = `x'); DROP TABLE users; --`;

describe("postgres manifests", () => {
  it("validate, and every compensation is a registered idempotent tool", () => {
    const { connector } = setup();
    const reg = Registry.from(connector.manifests);
    expect(reg.size).toBe(5);
    expect(reg.get("postgres.query")?.effect).toBe("read_only");
    expect(reg.get("postgres.insert_row")?.compensation?.tool).toBe("postgres.delete_row");
    expect(reg.get("postgres.update_row")?.compensation?.tool).toBe("postgres.restore_row");
    expect(reg.get("postgres.delete_row")?.effect).toBe("idempotent");
    expect(reg.get("postgres.restore_row")?.effect).toBe("idempotent");
  });
});

describe("postgres emits exact parameterized SQL", () => {
  it("insert_row", async () => {
    const { t, log } = setup();
    expect(await t("insert_row", { table: "users", values: { name: HOSTILE, age: 41, data: { a: [1, 2] }, note: null } })).toEqual({
      table: "users",
      schema: null,
      key_column: "id",
      key: 1,
    });
    expect(log()).toEqual([
      ['INSERT INTO "users" ("name","age","data","note") VALUES ($1,$2,$3,$4) RETURNING "id"', [HOSTILE, 41, '{"a":[1,2]}', null]],
    ]);
  });

  it("insert_row with a schema and a custom key column", async () => {
    const { pg, t, sql } = setup();
    pg.tables.set("users", []);
    await expect(t("insert_row", { table: "users", schema: "app", key_column: "id", values: { name: "x" } })).resolves.toMatchObject({ schema: "app" });
    expect(sql()).toEqual(['INSERT INTO "app"."users" ("name") VALUES ($1) RETURNING "id"']);
  });

  it("delete_row", async () => {
    const { pg, t, log } = setup();
    pg.tables.get("users")!.push({ id: 7, name: "Ann" });
    expect(await t("delete_row", { table: "users", key: 7 })).toEqual({ deleted: true });
    expect(await t("delete_row", { table: "users", key: 7 })).toEqual({ deleted: false });
    expect(log()[0]).toEqual(['DELETE FROM "users" WHERE "id" = $1', [7]]);
  });

  it("update_row reads the old values in one transaction and returns them", async () => {
    const { pg, t, log } = setup();
    pg.tables.get("users")!.push({ id: 7, name: "Ann", age: 30 });
    const r = await t("update_row", { table: "users", key: 7, set: { name: HOSTILE, age: 31 } });
    expect(r).toMatchObject({ key: 7, key_column: "id", previous: { name: "Ann", age: 30 } });
    expect(log()).toEqual([
      ["BEGIN", []],
      ['SELECT "name","age" FROM "users" WHERE "id" = $1 FOR UPDATE', [7]],
      ['UPDATE "users" SET "name" = $2, "age" = $3 WHERE "id" = $1', [7, HOSTILE, 31]],
      ["COMMIT", []],
    ]);
    expect(pg.tables.get("users")![0]).toMatchObject({ name: HOSTILE, age: 31 });
  });

  it("restore_row sets the saved values back", async () => {
    const { pg, t, log } = setup();
    pg.tables.get("users")!.push({ id: 7, name: "Zed", age: 31 });
    await t("restore_row", { table: "users", key: 7, values: { name: "Ann", age: 30 } });
    expect(log()).toEqual([['UPDATE "users" SET "name" = $2, "age" = $3 WHERE "id" = $1', [7, "Ann", 30]]]);
    await expect(t("restore_row", { table: "users", key: 99, values: { name: "x" } })).rejects.toThrow("no row with that key");
  });

  it("query binds values and runs in a READ ONLY transaction", async () => {
    const { pg, t, log } = setup();
    pg.tables.get("users")!.push({ id: 7, name: "Ann", age: 30 });
    const r = await t("query", { text: "SELECT * FROM users WHERE age > $1;", values: [20] });
    expect(r).toMatchObject({ row_count: 1, truncated: false, rows: [{ id: 7 }] });
    expect(log()).toEqual([
      ["BEGIN READ ONLY", []],
      ["SELECT * FROM users WHERE age > $1", [20]],
      ["ROLLBACK", []],
    ]);
  });

  it("never interpolates a value into SQL text", async () => {
    const { pg, t } = setup();
    pg.tables.get("users")!.push({ id: 7, name: "Ann", age: 30 });
    await t("insert_row", { table: "users", values: { name: HOSTILE } });
    await t("update_row", { table: "users", key: HOSTILE, set: { name: HOSTILE } }).catch(() => undefined);
    await t("delete_row", { table: "users", key: HOSTILE });
    await t("restore_row", { table: "users", key: HOSTILE, values: { name: HOSTILE } }).catch(() => undefined);
    await t("query", { text: "SELECT * FROM users WHERE age > $1", values: [HOSTILE] }).catch(() => undefined);
    expect(pg.calls.length).toBeGreaterThan(8);
    for (const c of pg.calls) {
      expect(c.url).not.toContain("DROP");
      expect(c.url).not.toContain("x'");
    }
    expect(pg.calls.some((c) => c.body.includes("DROP TABLE"))).toBe(true); // it travelled as a parameter
  });
});

describe("postgres validation", () => {
  it("accepts only plain identifiers and quotes them", async () => {
    const { t, pg } = setup();
    for (const bad of ["users; DROP TABLE x", 'us"ers', "1users", "", "a".repeat(64), "us ers", "users--", "üsers"]) {
      await expect(t("insert_row", { table: bad, values: { a: 1 } })).rejects.toThrow(/table|identifier/i);
      await expect(t("insert_row", { table: "users", values: { [bad]: 1 } })).rejects.toThrow(/column|values|must/i);
      await expect(t("delete_row", { table: "users", key_column: bad, key: 1 })).rejects.toThrow(/identifier|key_column/);
      await expect(t("delete_row", { table: "users", schema: bad, key: 1 })).rejects.toThrow(/identifier|schema/);
    }
    expect(pg.calls).toHaveLength(0);
    pg.tables.set("a".repeat(63), []);
    await t("insert_row", { table: "a".repeat(63), values: { _ok1: 1 } });
    expect(pg.calls[0]!.url).toBe(`INSERT INTO "${"a".repeat(63)}" ("_ok1") VALUES ($1) RETURNING "id"`);
  });

  it("rejects bad keys, empty or oversized value sets, unknown arguments and key-column updates", async () => {
    const { t, pg } = setup();
    await expect(t("delete_row", { table: "users", key: {} })).rejects.toThrow("`key`");
    await expect(t("delete_row", { table: "users", key: 1.5 })).rejects.toThrow("`key`");
    await expect(t("insert_row", { table: "users", values: {} })).rejects.toThrow("must not be empty");
    await expect(t("insert_row", { table: "users", values: Object.fromEntries(Array.from({ length: 101 }, (_, i) => [`c${i}`, i])) })).rejects.toThrow("more than 100");
    await expect(t("insert_row", { table: "users", values: { a: Infinity } })).rejects.toThrow("finite");
    await expect(t("insert_row", { table: "users", values: { a: 1 }, extra: 1 })).rejects.toThrow("unknown argument");
    await expect(t("update_row", { table: "users", key: 1, set: { id: 2 } })).rejects.toThrow("key column");
    expect(pg.calls).toHaveLength(0);
  });

  it("query accepts only a single SELECT or WITH statement", async () => {
    const { t, pg } = setup();
    for (const text of ["DELETE FROM users", "UPDATE users SET a = 1", "INSERT INTO users VALUES (1)", "DROP TABLE users", "SELECT 1; DROP TABLE users", "SELECT 1; COMMIT; DELETE FROM users", "", "  --SELECT 1"]) {
      await expect(t("query", { text })).rejects.toThrow();
    }
    expect(pg.calls).toHaveLength(0);
  });

  it("a write hidden in a WITH is stopped by the READ ONLY transaction and rolled back", async () => {
    const { pg, t, sql } = setup();
    pg.tables.get("users")!.push({ id: 7, name: "Ann", age: 30 });
    const err = await t("query", { text: "WITH gone AS (DELETE FROM users RETURNING *) SELECT * FROM gone" }).catch((e) => e);
    expect(err.message).toContain("25006");
    expect(pg.tables.get("users")).toHaveLength(1);
    expect(sql()).toEqual(["BEGIN READ ONLY", "WITH gone AS (DELETE FROM users RETURNING *) SELECT * FROM gone", "ROLLBACK"]);
  });

  it("query caps the rows it returns", async () => {
    const { pg, t } = setup({ maxRows: 2 });
    for (let i = 1; i <= 5; i++) pg.tables.get("users")!.push({ id: i, name: "n", age: 30 });
    const r = (await t("query", { text: "SELECT * FROM users" })) as { rows: unknown[]; row_count: number; truncated: boolean };
    expect(r.rows).toHaveLength(2);
    expect(r).toMatchObject({ row_count: 5, truncated: true });
    expect(((await t("query", { text: "SELECT * FROM users", limit: 1 })) as { rows: unknown[] }).rows).toHaveLength(1);
  });
});

describe("postgres failure handling", () => {
  it("update_row on a missing row rolls back and changes nothing", async () => {
    const { t, sql } = setup();
    await expect(t("update_row", { table: "users", key: 99, set: { name: "x" } })).rejects.toThrow("no row with that key");
    expect(sql()).toEqual(['BEGIN', 'SELECT "name" FROM "users" WHERE "id" = $1 FOR UPDATE', "ROLLBACK"]);
  });

  it("a server error carries its SQLSTATE and the transaction is rolled back", async () => {
    const { pg, t } = setup();
    pg.tables.get("users")!.push({ id: 7, name: "Ann" });
    pg.fault = { kind: "status", status: 403, on: "mutating" };
    const err = await t("update_row", { table: "users", key: 7, set: { name: "x" } }).catch((e) => e);
    expect(err).not.toBeInstanceOf(EffectUncertainError);
    expect(err.message).toContain("42501");
    expect(err.code).toBe("42501");
    expect(pg.calls.at(-1)!.url).toBe("ROLLBACK");
  });

  it("a lost connection after a write was sent is uncertain; before it, a plain error", async () => {
    const a = setup();
    a.pg.tables.get("users")!.push({ id: 7, name: "Ann" });
    a.pg.fault = { kind: "throw", message: `read ECONNRESET ${URL_SECRET}`, on: "mutating" };
    const err = await a.t("update_row", { table: "users", key: 7, set: { name: "x" } }).catch((e) => e);
    expect(err).toBeInstanceOf(EffectUncertainError);
    expect(err.message).not.toContain(PASSWORD);
    expect(err.message).toContain("[redacted]");

    const b = setup();
    b.pg.fault = { kind: "throw", message: "connection refused", on: "any" };
    const e2 = await b.t("insert_row", { table: "users", values: { name: "x" } }).catch((e) => e);
    expect(e2).toBeInstanceOf(EffectUncertainError); // the INSERT itself was attempted
    const c = setup();
    c.pg.fault = { kind: "throw", message: "connection refused", on: "any" };
    const e3 = await c.t("query", { text: "SELECT 1" }).catch((e) => e);
    expect(e3).not.toBeInstanceOf(EffectUncertainError);
  });

  it("uses a pooled client and releases it, dropping it when its state is unknown", async () => {
    const { pg, t, sql } = setup({ connect: true });
    pg.tables.get("users")!.push({ id: 7, name: "Ann", age: 30 });
    await t("update_row", { table: "users", key: 7, set: { age: 31 } });
    expect(pg.released).toEqual([false]);
    pg.fault = { kind: "throw", message: "terminating connection", on: "mutating" };
    await t("delete_row", { table: "users", key: 7 }).catch(() => undefined);
    expect(pg.released).toEqual([false, true]);
    expect(sql()[0]).toBe("BEGIN");
  });

  it("times out a query that never answers", async () => {
    const { pg, t } = setup({ timeoutMs: 30 });
    pg.fault = { kind: "hang", on: "mutating" };
    await expect(t("delete_row", { table: "users", key: 1 })).rejects.toBeInstanceOf(EffectUncertainError);
  });
});

describe("postgres end to end", () => {
  it("rolls back an insert and an update through a real engine", async () => {
    const { pg, connector } = setup();
    pg.tables.get("users")!.push({ id: 7, name: "Ann", age: 30 });
    const before = JSON.stringify(pg.state());
    const { call, run } = engine([connector]);
    await call("postgres.insert_row", { table: "users", values: { name: "Bo", age: 5 } });
    await call("postgres.update_row", { table: "users", key: 7, set: { name: "Zed" } });
    await call("postgres.query", { text: "SELECT * FROM users" });
    expect(JSON.stringify(pg.state())).not.toBe(before);
    const report = await run.rollback({ compensate: compensatorFor([connector]) });
    expect(report.complete).toBe(true);
    expect(JSON.stringify(pg.state())).toBe(before);
  });
});
