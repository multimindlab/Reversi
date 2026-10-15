/**
 * SQLite-backed ledger and run stores sharing one database file. Uses `node:sqlite` (Node 22.13+).
 * Kept out of the main entry point so the rest of the package loads on older Node 22 releases.
 *
 * The ledger table is append-only: triggers reject UPDATE and DELETE. That is a guard against
 * accidents, not tamper-proofing; the hash chain remains the evidence.
 */
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { ApprovalRecord, ApprovalStore } from "./approvals.js";
import { LedgerConflictError, type LedgerRecord, type LedgerStore } from "./ledger.js";
import { RUN_ID_PATTERN, type RunState, type RunStore } from "./store.js";

export function openDatabase(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS ledger (
      seq INTEGER PRIMARY KEY,
      record TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
      BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
      BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
    CREATE TABLE IF NOT EXISTS runs (
      run_id TEXT PRIMARY KEY,
      state TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS approvals (
      id TEXT PRIMARY KEY,
      record TEXT NOT NULL
    );
  `);
  return db;
}

export class SqliteLedgerStore implements LedgerStore {
  private readonly items: LedgerRecord[] = [];
  constructor(private readonly db: DatabaseSync) {
    this.sync();
  }
  /** Pick up records another process appended since the last call. */
  private sync(): void {
    const rows = this.db.prepare("SELECT record FROM ledger WHERE seq >= ? ORDER BY seq").all(this.items.length) as Array<{ record: string }>;
    for (const r of rows) this.items.push(JSON.parse(r.record) as LedgerRecord);
  }
  all(): readonly LedgerRecord[] {
    this.sync();
    return this.items;
  }
  append(record: LedgerRecord): void {
    try {
      this.db.prepare("INSERT INTO ledger (seq, record) VALUES (?, ?)").run(record.seq, JSON.stringify(record));
    } catch (e) {
      if (/UNIQUE constraint failed|PRIMARY KEY/i.test(e instanceof Error ? e.message : "")) throw new LedgerConflictError();
      throw e;
    }
    this.items.push(record);
  }
}

export class SqliteRunStore implements RunStore {
  constructor(private readonly db: DatabaseSync) {}

  private check(run_id: string): string {
    if (!RUN_ID_PATTERN.test(run_id)) throw new Error(`invalid run id: ${JSON.stringify(run_id)}`);
    return run_id;
  }
  get(run_id: string): RunState | undefined {
    const row = this.db.prepare("SELECT state FROM runs WHERE run_id = ?").get(this.check(run_id)) as
      | { state: string }
      | undefined;
    return row ? (JSON.parse(row.state) as RunState) : undefined;
  }
  put(state: RunState): void {
    this.db
      .prepare("INSERT INTO runs (run_id, state) VALUES (?, ?) ON CONFLICT(run_id) DO UPDATE SET state = excluded.state")
      .run(this.check(state.run_id), JSON.stringify(state));
  }
  list(): string[] {
    return (this.db.prepare("SELECT run_id FROM runs ORDER BY run_id").all() as Array<{ run_id: string }>).map(
      (r) => r.run_id,
    );
  }
}

export class SqliteApprovalStore implements ApprovalStore {
  constructor(private readonly db: DatabaseSync) {}
  get(id: string): ApprovalRecord | undefined {
    const row = this.db.prepare("SELECT record FROM approvals WHERE id = ?").get(id) as { record: string } | undefined;
    return row ? (JSON.parse(row.record) as ApprovalRecord) : undefined;
  }
  put(rec: ApprovalRecord): void {
    this.db
      .prepare("INSERT INTO approvals (id, record) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET record = excluded.record")
      .run(rec.id, JSON.stringify(rec));
  }
  list(): ApprovalRecord[] {
    return (this.db.prepare("SELECT record FROM approvals").all() as Array<{ record: string }>).map((r) => JSON.parse(r.record) as ApprovalRecord);
  }
}

/** Open one database file and return the stores over it. */
export function openSqliteStores(path: string): {
  db: DatabaseSync;
  ledger: SqliteLedgerStore;
  runs: SqliteRunStore;
  approvals: SqliteApprovalStore;
} {
  const db = openDatabase(path);
  return { db, ledger: new SqliteLedgerStore(db), runs: new SqliteRunStore(db), approvals: new SqliteApprovalStore(db) };
}
