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
import type { ApprovalRecord, ApprovalStatus, ApprovalStore } from "./approvals.js";
import type { KvEntry, KvStore } from "./kv.js";
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
    reply = { id: m.id, ok: true, rows: r.rows };
  } catch (e) {
    reply = { id: m.id, ok: false, code: e.code, message: String(e.message) };
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
  private seq = 0;

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
    const id = ++this.seq;
    Atomics.store(this.flag, 0, 0);
    this.worker.postMessage({ id, sql, params });
    const res = Atomics.wait(this.flag, 0, 0, this.timeoutMs);
    if (res === "timed-out") {
      // The worker may still finish this statement and answer later. Never reuse the connection: a stale reply
      // could be mistaken for the next query's, and a journaled intent must not be believed durable when it is not.
      this.close();
      throw new PgError(`query timed out after ${this.timeoutMs}ms; the connection was closed`);
    }
    const m = receiveMessageOnPort(this.port)?.message as { id: number; ok: boolean; rows?: T[]; code?: string; message?: string } | undefined;
    if (!m || m.id !== id) {
      this.close();
      throw new PgError("unexpected reply from the database worker; the connection was closed");
    }
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
  {
    version: 2,
    sql: `CREATE TABLE kv (ns TEXT NOT NULL, key TEXT NOT NULL, value JSONB NOT NULL, version BIGINT NOT NULL, PRIMARY KEY (ns, key));`,
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
  delete(run_id: string): boolean {
    return this.pg.query("DELETE FROM runs WHERE run_id = $1 RETURNING run_id", [this.check(run_id)]).length === 1;
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
  delete(id: string): boolean {
    return this.pg.query("DELETE FROM approvals WHERE id = $1 RETURNING id", [id]).length === 1;
  }
  transition(id: string, from: ApprovalStatus, patch: Partial<ApprovalRecord>, expectCount?: number): boolean {
    const params: unknown[] = [JSON.stringify(patch), id, from];
    let extra = "";
    if (expectCount !== undefined) {
      params.push(expectCount);
      extra = " AND COALESCE((record->>'decision_count')::int, 0) = $4";
    }
    return this.pg.query(`UPDATE approvals SET record = record || $1::jsonb WHERE id = $2 AND record->>'status' = $3${extra} RETURNING id`, params).length === 1;
  }
}

export class PgKvStore implements KvStore {
  constructor(private readonly pg: SyncPg) {}
  get<T>(ns: string, key: string): KvEntry<T> | undefined {
    const r = this.pg.query<{ value: T; version: string }>("SELECT value, version FROM kv WHERE ns = $1 AND key = $2", [ns, key])[0];
    return r ? { key, value: r.value, version: Number(r.version) } : undefined;
  }
  put(ns: string, key: string, value: unknown): void {
    this.pg.query("INSERT INTO kv (ns, key, value, version) VALUES ($1, $2, $3, 1) ON CONFLICT (ns, key) DO UPDATE SET value = EXCLUDED.value, version = kv.version + 1", [ns, key, JSON.stringify(value)]);
  }
  cas(ns: string, key: string, value: unknown, expected: number): boolean {
    if (expected === 0) {
      return this.pg.query("INSERT INTO kv (ns, key, value, version) VALUES ($1, $2, $3, 1) ON CONFLICT (ns, key) DO NOTHING RETURNING key", [ns, key, JSON.stringify(value)]).length === 1;
    }
    return this.pg.query("UPDATE kv SET value = $3, version = version + 1 WHERE ns = $1 AND key = $2 AND version = $4 RETURNING key", [ns, key, JSON.stringify(value), expected]).length === 1;
  }
  delete(ns: string, key: string): boolean {
    return this.pg.query("DELETE FROM kv WHERE ns = $1 AND key = $2 RETURNING key", [ns, key]).length === 1;
  }
  list<T>(ns: string, prefix = ""): KvEntry<T>[] {
    return this.pg
      .query<{ key: string; value: T; version: string }>("SELECT key, value, version FROM kv WHERE ns = $1 AND left(key, $2) = $3 ORDER BY key", [ns, prefix.length, prefix])
      .map((r) => ({ key: r.key, value: r.value, version: Number(r.version) }));
  }
}

export function openPostgresStores(url: string): { pg: SyncPg; ledger: PgLedgerStore; runs: PgRunStore; approvals: PgApprovalStore; kv: PgKvStore } {
  const pg = new SyncPg(url);
  migrate(pg);
  return { pg, ledger: new PgLedgerStore(pg), runs: new PgRunStore(pg), approvals: new PgApprovalStore(pg), kv: new PgKvStore(pg) };
}
