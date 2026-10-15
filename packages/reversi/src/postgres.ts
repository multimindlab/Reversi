/**
 * PostgreSQL ledger, run and approval stores.
 *
 * The engine's store interfaces are synchronous (a journaled intent must be durable before the tool
 * runs, with no await in between), so queries run on a worker thread that owns the `pg` pool, and
 * the calling thread blocks on an Atomics wait until the worker answers. Every query is one network
 * round trip.
 *
 * Several processes (gateway, server, CLI) can share one database: the ledger's `seq` primary key
 * makes forking the chain impossible, and a losing writer re-reads the tail and retries.
 */
import { createRequire } from "node:module";
import { MessageChannel, Worker, receiveMessageOnPort, type MessagePort } from "node:worker_threads";
import type { ApprovalRecord, ApprovalStore } from "./approvals.js";
import { LedgerConflictError, type LedgerRecord, type LedgerStore } from "./ledger.js";
import { RUN_ID_PATTERN, type RunState, type RunStore } from "./store.js";

const WORKER_SOURCE = `
const { parentPort, workerData } = require("node:worker_threads");
const { Pool } = require(workerData.pgPath);
const flag = new Int32Array(workerData.flag);
const pool = new Pool({ connectionString: workerData.url, max: 2 });
pool.on("error", () => {});
const port = workerData.port;
parentPort.on("message", async (m) => {
  let reply;
  try {
    const r = await pool.query(m.sql, m.params);
    reply = { ok: true, rows: r.rows };
  } catch (e) {
    reply = { ok: false, code: e.code, message: String(e.message) };
  }
  port.postMessage(reply);
  Atomics.store(flag, 0, 1);
  Atomics.notify(flag, 0);
});
Atomics.store(flag, 0, 1);
Atomics.notify(flag, 0);
`;

export class PgError extends Error {
  constructor(
    message: string,
    readonly code?: string,
  ) {
    super(message);
    this.name = "PgError";
  }
}

/** Blocking Postgres access from the main thread. Create one per process and share it. */
export class SyncPg {
  private readonly worker: Worker;
  private readonly flag: Int32Array;
  private readonly port: MessagePort;
  private closed = false;

  constructor(url: string, private readonly timeoutMs = 30_000) {
    const sab = new SharedArrayBuffer(4);
    this.flag = new Int32Array(sab);
    const { port1, port2 } = new MessageChannel();
    this.port = port1;
    const pgPath = createRequire(import.meta.url).resolve("pg");
    this.worker = new Worker(WORKER_SOURCE, { eval: true, workerData: { url, flag: sab, port: port2, pgPath }, transferList: [port2] });
    this.worker.unref();
    // The worker raises the flag once it is running, so the first query's timeout is about the query, not startup.
    if (Atomics.wait(this.flag, 0, 0, 15_000) === "timed-out") {
      void this.worker.terminate();
      throw new PgError("database worker did not start");
    }
  }

  query<T = Record<string, unknown>>(sql: string, params: unknown[] = []): T[] {
    if (this.closed) throw new PgError("connection closed");
    Atomics.store(this.flag, 0, 0);
    this.worker.postMessage({ sql, params });
    const res = Atomics.wait(this.flag, 0, 0, this.timeoutMs);
    if (res === "timed-out") throw new PgError(`query timed out after ${this.timeoutMs}ms`);
    const m = receiveMessageOnPort(this.port)?.message as { ok: boolean; rows?: T[]; code?: string; message?: string } | undefined;
    if (!m) throw new PgError("no reply from the database worker");
    if (!m.ok) throw new PgError(m.message ?? "query failed", m.code);
    return m.rows ?? [];
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    void this.worker.terminate();
    this.port.close();
  }
}

/** Ordered, additive migrations. Applied once each, recorded in `reversi_migrations`. */
export const MIGRATIONS: Array<{ version: number; sql: string }> = [
  {
    version: 1,
    sql: `
      CREATE TABLE ledger (seq BIGINT PRIMARY KEY, record JSONB NOT NULL);
      CREATE FUNCTION reversi_ledger_append_only() RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'ledger is append-only'; END; $$ LANGUAGE plpgsql;
      CREATE TRIGGER ledger_no_update BEFORE UPDATE OR DELETE ON ledger
        FOR EACH ROW EXECUTE FUNCTION reversi_ledger_append_only();
      CREATE TABLE runs (run_id TEXT PRIMARY KEY, state JSONB NOT NULL);
      CREATE TABLE approvals (id TEXT PRIMARY KEY, record JSONB NOT NULL);
    `,
  },
];

export function migrate(pg: SyncPg): number[] {
  pg.query("CREATE TABLE IF NOT EXISTS reversi_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())");
  const applied = new Set(pg.query<{ version: number }>("SELECT version FROM reversi_migrations").map((r) => r.version));
  const done: number[] = [];
  for (const m of MIGRATIONS) {
    if (applied.has(m.version)) continue;
    // One simple-query round trip: the statements and the bookkeeping row commit or roll back together.
    try {
      pg.query(`${m.sql}; INSERT INTO reversi_migrations (version) VALUES (${m.version});`);
      done.push(m.version);
    } catch (e) {
      // Another process may have won the race; if so the version row now exists.
      const now = pg.query("SELECT 1 FROM reversi_migrations WHERE version = $1", [m.version]);
      if (now.length === 0) throw e;
    }
  }
  return done;
}

export class PgLedgerStore implements LedgerStore {
  private readonly items: LedgerRecord[] = [];
  constructor(private readonly pg: SyncPg) {
    this.sync();
  }
  private sync(): void {
    for (const r of this.pg.query<{ record: LedgerRecord }>("SELECT record FROM ledger WHERE seq >= $1 ORDER BY seq", [this.items.length])) {
      this.items.push(r.record);
    }
  }
  all(): readonly LedgerRecord[] {
    this.sync();
    return this.items;
  }
  append(record: LedgerRecord): void {
    try {
      this.pg.query("INSERT INTO ledger (seq, record) VALUES ($1, $2)", [record.seq, JSON.stringify(record)]);
    } catch (e) {
      if (e instanceof PgError && e.code === "23505") throw new LedgerConflictError();
      throw e;
    }
    this.items.push(record);
  }
}

export class PgRunStore implements RunStore {
  constructor(private readonly pg: SyncPg) {}
  private check(id: string): string {
    if (!RUN_ID_PATTERN.test(id)) throw new Error(`invalid run id: ${JSON.stringify(id)}`);
    return id;
  }
  get(run_id: string): RunState | undefined {
    return this.pg.query<{ state: RunState }>("SELECT state FROM runs WHERE run_id = $1", [this.check(run_id)])[0]?.state;
  }
  put(state: RunState): void {
    this.pg.query("INSERT INTO runs (run_id, state) VALUES ($1, $2) ON CONFLICT (run_id) DO UPDATE SET state = EXCLUDED.state", [
      this.check(state.run_id),
      JSON.stringify(state),
    ]);
  }
  list(): string[] {
    return this.pg.query<{ run_id: string }>("SELECT run_id FROM runs ORDER BY run_id").map((r) => r.run_id);
  }
}

export class PgApprovalStore implements ApprovalStore {
  constructor(private readonly pg: SyncPg) {}
  get(id: string): ApprovalRecord | undefined {
    return this.pg.query<{ record: ApprovalRecord }>("SELECT record FROM approvals WHERE id = $1", [id])[0]?.record;
  }
  put(rec: ApprovalRecord): void {
    this.pg.query("INSERT INTO approvals (id, record) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET record = EXCLUDED.record", [rec.id, JSON.stringify(rec)]);
  }
  list(): ApprovalRecord[] {
    return this.pg.query<{ record: ApprovalRecord }>("SELECT record FROM approvals").map((r) => r.record);
  }
}

export function openPostgresStores(url: string): { pg: SyncPg; ledger: PgLedgerStore; runs: PgRunStore; approvals: PgApprovalStore } {
  const pg = new SyncPg(url);
  migrate(pg);
  return { pg, ledger: new PgLedgerStore(pg), runs: new PgRunStore(pg), approvals: new PgApprovalStore(pg) };
}
