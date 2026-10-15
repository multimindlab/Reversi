// Runs only when REVERSI_TEST_PG points at a throwaway PostgreSQL database. Each run works in a new schema.
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Approvals, Ledger, Registry, Reversi, SealedScope, type RunState } from "../src/index.js";
import { MIGRATIONS, PgError, SyncPg, migrate, openPostgresStores } from "../src/postgres.js";

const base = process.env.REVERSI_TEST_PG;

function freshUrl(): string {
  const schema = `rv_test_${randomBytes(6).toString("hex")}`;
  const admin = new SyncPg(base as string);
  admin.query(`CREATE SCHEMA ${schema}`);
  admin.close();
  const u = new URL(base as string);
  u.searchParams.set("options", `-c search_path=${schema}`);
  return u.toString();
}

const MANIFESTS = [
  { tool: "create_order", effect: "reversible", permission: "o:w", compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } } },
  { tool: "cancel_order", effect: "idempotent", permission: "o:w" },
];

const state = (id: string): RunState => ({
  run_id: id,
  actor: "a",
  mode: "enforce",
  scope: { permissions: ["x"], seal: "s", parent_seal: null },
  created_ms: 1,
  steps: [],
});

describe.skipIf(!base)("PostgreSQL stores", () => {
  it("migrates once and is idempotent", () => {
    const pg = new SyncPg(freshUrl());
    expect(migrate(pg)).toEqual(MIGRATIONS.map((m) => m.version));
    expect(migrate(pg)).toEqual([]);
    pg.close();
  });

  it("closes the connection after a timeout, so a late reply can never be mistaken for the next query's", () => {
    const pg = new SyncPg(freshUrl(), 300);
    expect(() => pg.query("SELECT pg_sleep(1.5)")).toThrow(/timed out/);
    expect(() => pg.query("SELECT 1")).toThrow(/closed/);
    pg.close();
  });

  it("surfaces database errors with their code", () => {
    const pg = new SyncPg(freshUrl());
    expect(() => pg.query("SELECT * FROM nope")).toThrow(PgError);
    try {
      pg.query("SELECT * FROM nope");
    } catch (e) {
      expect((e as PgError).code).toBe("42P01");
    }
    pg.close();
  });

  it("round-trips runs and approvals, and the ledger is append-only", () => {
    const s = openPostgresStores(freshUrl());
    s.runs.put(state("r2"));
    s.runs.put({ ...state("r1"), actor: "changed" });
    s.runs.put({ ...state("r1"), actor: "changed2" });
    expect(s.runs.get("r1")?.actor).toBe("changed2");
    expect(s.runs.get("nope")).toBeUndefined();
    expect(s.runs.list()).toEqual(["r1", "r2"]);
    expect(() => s.runs.get("../x")).toThrow(/invalid run id/);

    const a = new Approvals(s.approvals);
    a.add("r1", "call", "refund", 1, "alice");
    expect(a.list({ status: "approved" })).toHaveLength(1);
    const id = a.list()[0]!.id;
    expect(s.approvals.transition(id, "approved", { status: "consumed" })).toBe(true);
    expect(s.approvals.transition(id, "approved", { status: "consumed" })).toBe(false); // already consumed
    expect(a.get(id)?.status).toBe("consumed");

    new Ledger(s.ledger).append({ ts_ms: 1, run_id: "r", actor: "a", tool: "t", reason: "why", event: "run_started" });
    expect(() => s.pg.query("UPDATE ledger SET record = '{}'")).toThrow(/append-only/);
    expect(() => s.pg.query("DELETE FROM ledger")).toThrow(/append-only/);
    s.pg.close();
  });

  it("runs the engine, survives a restart, and two writers cannot fork the chain", async () => {
    const url = freshUrl();
    const one = openPostgresStores(url);
    const rv1 = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(one.ledger), runs: one.runs });
    const run = rv1.startRun({ run_id: "r1", actor: "agent", scope: SealedScope.seal(["o:w"]) });
    await run.call({ tool: "create_order", reason: "x", execute: () => ({ id: 7 }) });

    // A second process sharing the database sees the history and keeps appending to the same chain.
    const two = openPostgresStores(url);
    const rv2 = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(two.ledger), runs: two.runs });
    expect(rv2.ledger.records()).toHaveLength(3);
    const run2 = rv2.openRun("r1");
    const rep = await run2.rollback({ compensate: () => {} });
    expect(rep.complete).toBe(true);

    // The first writer's cache is stale; its next append conflicts, re-reads, and lands after the other's records.
    rv1.startRun({ run_id: "r3", actor: "agent", scope: SealedScope.seal(["o:w"]) });
    const all = new Ledger(openPostgresStores(url).ledger);
    expect(all.verify()).toMatchObject({ ok: true });
    expect(all.records().map((r) => r.seq)).toEqual(all.records().map((_, i) => i));
    expect(all.records().at(-1)?.run_id).toBe("r3");
    one.pg.close();
    two.pg.close();
  });
});
