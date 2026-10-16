/**
 * One place that opens the storage backends: JSON files (default), SQLite or PostgreSQL. The SQLite
 * and PostgreSQL modules are loaded only when selected, so the default path needs neither
 * `node:sqlite` (Node 22.13+) nor `pg`.
 */
import { join } from "node:path";
import { FileApprovalStore, type ApprovalStore } from "./approvals.js";
import { FileKvStore, type KvStore } from "./kv.js";
import { JsonlLedgerStore, type LedgerStore } from "./ledger.js";
import { FileRunStore, type RunStore } from "./store.js";

export type StoreKind = "files" | "sqlite" | "postgres";

export interface DataOptions {
  /** Data directory: holds the files layout, or the SQLite database. */
  dir: string;
  store?: StoreKind;
  /** Required for `postgres`. */
  postgres_url?: string;
}

export interface Data {
  kind: StoreKind;
  ledger: LedgerStore;
  runs: RunStore;
  approvals: ApprovalStore;
  /** Settings and state other than the ledger, run state and approvals. */
  kv: KvStore;
  close(): void;
}

export function storeKindFrom(v: string | undefined): StoreKind {
  if (v === undefined || v === "" || v === "files") return "files";
  if (v === "sqlite" || v === "postgres") return v;
  throw new Error(`unknown store \`${v}\`: use files, sqlite or postgres`);
}

/** Options from the environment: REVERSI_DATA, REVERSI_STORE, REVERSI_DATABASE_URL. */
export function dataOptionsFromEnv(env: Record<string, string | undefined> = process.env): DataOptions {
  return { dir: env.REVERSI_DATA ?? "./reversi-data", store: storeKindFrom(env.REVERSI_STORE), postgres_url: env.REVERSI_DATABASE_URL };
}

export async function openData(opts: DataOptions): Promise<Data> {
  const kind = opts.store ?? "files";
  if (kind === "sqlite") {
    const { openSqliteStores } = await import("./sqlite.js");
    const s = openSqliteStores(join(opts.dir, "reversi.db"));
    return { kind, ledger: s.ledger, runs: s.runs, approvals: s.approvals, kv: s.kv, close: () => s.db.close() };
  }
  if (kind === "postgres") {
    if (!opts.postgres_url) throw new Error("the postgres store needs a connection URL (REVERSI_DATABASE_URL or --database-url)");
    const { openPostgresStores } = await import("./postgres.js");
    const s = openPostgresStores(opts.postgres_url);
    return { kind, ledger: s.ledger, runs: s.runs, approvals: s.approvals, kv: s.kv, close: () => s.pg.close() };
  }
  return {
    kind,
    ledger: new JsonlLedgerStore(join(opts.dir, "ledger.jsonl")),
    runs: new FileRunStore(join(opts.dir, "runs")),
    approvals: new FileApprovalStore(join(opts.dir, "approvals.json")),
    kv: new FileKvStore(join(opts.dir, "settings.json")),
    close: () => {},
  };
}
