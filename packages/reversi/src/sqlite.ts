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
import type { LedgerRecord, LedgerStore } from "./ledger.js";
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
  `);
  return db;
}

export class SqliteLedgerStore implements LedgerStore {
  private readonly items: LedgerRecord[];
  constructor(private readonly db: DatabaseSync) {
    const rows = db.prepare("SELECT record FROM ledger ORDER BY seq").all() as Array<{ record: string }>;
    this.items = rows.map((r) => JSON.parse(r.record) as LedgerRecord);
  }
  all(): readonly LedgerRecord[] {
    return this.items;
  }
  append(record: LedgerRecord): void {
    this.db.prepare("INSERT INTO ledger (seq, record) VALUES (?, ?)").run(record.seq, JSON.stringify(record));
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

/** Open one database file and return both stores over it. */
export function openSqliteStores(path: string): { db: DatabaseSync; ledger: SqliteLedgerStore; runs: SqliteRunStore } {
  const db = openDatabase(path);
  return { db, ledger: new SqliteLedgerStore(db), runs: new SqliteRunStore(db) };
}
