import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Ledger, Registry, Reversi, SealedScope, type RunState } from "../src/index.js";
import { openSqliteStores } from "../src/sqlite.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});
const dbPath = () => {
  const d = mkdtempSync(join(tmpdir(), "reversi-sqlite-"));
  dirs.push(d);
  return join(d, "nested", "reversi.db");
};

const MANIFESTS = [
  {
    tool: "create_order",
    effect: "reversible",
    permission: "orders:write",
    compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } },
  },
  { tool: "cancel_order", effect: "idempotent", permission: "orders:write" },
];

const state = (id: string): RunState => ({
  run_id: id,
  actor: "a",
  mode: "enforce",
  scope: { permissions: ["x"], seal: "s", parent_seal: null },
  created_ms: 1,
  steps: [],
});

describe("SQLite stores", () => {
  it("round-trips run state and lists runs", () => {
    const { runs, db } = openSqliteStores(dbPath());
    expect(runs.get("r1")).toBeUndefined();
    runs.put(state("r2"));
    runs.put(state("r1"));
    runs.put({ ...state("r1"), actor: "changed" });
    expect(runs.get("r1")?.actor).toBe("changed");
    expect(runs.list()).toEqual(["r1", "r2"]);
    db.close();
  });

  it("rejects run ids that are not valid", () => {
    const { runs, db } = openSqliteStores(dbPath());
    expect(() => runs.get("../x")).toThrow(/invalid run id/);
    expect(() => runs.put(state("a b"))).toThrow(/invalid run id/);
    db.close();
  });

  it("ledger is append-only at the database level", () => {
    const { db, ledger } = openSqliteStores(dbPath());
    new Ledger(ledger).append({ ts_ms: 1, run_id: "r", actor: "a", tool: "t", reason: "why", event: "run_started" });
    expect(() => db.exec("UPDATE ledger SET record = '{}'")).toThrow(/append-only/);
    expect(() => db.exec("DELETE FROM ledger")).toThrow(/append-only/);
    db.close();
  });

  it("a full run survives a restart and still rolls back", async () => {
    const path = dbPath();
    const first = openSqliteStores(path);
    const rv1 = new Reversi({ registry: Registry.from(MANIFESTS), ledger: new Ledger(first.ledger), runs: first.runs });
    const run = rv1.startRun({ run_id: "r1", actor: "agent", scope: SealedScope.seal(["orders:write"]) });
    await run.call({ tool: "create_order", reason: "customer asked", execute: () => ({ id: 7 }) });
    const head = rv1.ledger.head();
    first.db.close();

    const second = openSqliteStores(path);
    const ledger = new Ledger(second.ledger);
    expect(ledger.verify()).toMatchObject({ ok: true, head });
    const rv2 = new Reversi({ registry: Registry.from(MANIFESTS), ledger, runs: second.runs });
    expect(second.runs.list()).toEqual(["r1"]);
    expect(second.runs.get("r1")?.steps[0]?.status).toBe("succeeded");
    expect(rv2.ledger.forRun("r1").map((r) => r.event)).toEqual(["run_started", "intended", "succeeded"]);
    second.db.close();
  });
});
