import { expect } from "vitest";
import { createPostgresConnector, type PgClientLike, type PgLike, type PgResult } from "../../src/index.js";
import type { Backend, Fault, Scenario, Subject } from "../certification.js";
import type { Call } from "../helpers.js";

export const URL_SECRET = "postgres://app:SECRETPGPASSWORD@db.internal:5432/prod";
export const PASSWORD = "SECRETPGPASSWORD";

type Row = Record<string, unknown>;

class PgError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

const STATUS_CODE: Record<number, string> = { 401: "28P01", 403: "42501", 422: "22P02", 500: "XX000", 503: "57P03" };

/** An in-memory Postgres that understands exactly the SQL shapes the connector emits. Every statement is logged. */
export function fakePg() {
  const tables = new Map<string, Row[]>([["users", []]]);
  const seq = new Map<string, number>();
  let txn: { readOnly: boolean; snapshot: string } | null = null;
  const calls: Call[] = [];
  const snapshot = () => JSON.stringify([...tables]);
  const restore = (s: string) => {
    tables.clear();
    for (const [k, v] of JSON.parse(s) as Array<[string, Row[]]>) tables.set(k, v);
  };
  const isMutating = (c: Call) => /^(INSERT|UPDATE|DELETE|COMMIT)/.test(c.url);

  const b: Backend & { tables: typeof tables; pg: PgLike; withConnect: PgLike; released: Array<boolean | Error | undefined> } = {
    fault: null as Fault | null,
    calls,
    supportsFaults: true,
    isMutating,
    state: () => ({ users: tables.get("users") }),
    tables,
    released: [],
    pg: undefined as unknown as PgLike,
    withConnect: undefined as unknown as PgLike,
  };

  const rowsOf = (t: string): Row[] => {
    const r = tables.get(t);
    if (!r) throw new PgError(`relation "${t}" does not exist`, "42P01");
    return r;
  };
  const writable = () => {
    if (txn?.readOnly) throw new PgError("cannot execute a write in a read-only transaction", "25006");
  };

  async function query(text: string, values: unknown[] = []): Promise<PgResult> {
    const call: Call = { url: text, method: "SQL", headers: {}, body: JSON.stringify(values) };
    calls.push(call);
    text = text.replace(/"\w+"\.("\w+")/g, "$1"); // schema-qualified names are matched as plain table names
    const f = b.fault;
    if (f && (f.on !== "mutating" || isMutating(call))) {
      if (f.kind === "throw") throw new Error(f.message);
      if (f.kind === "hang") return new Promise<PgResult>(() => undefined);
      throw new PgError(`fault ${f.status}`, STATUS_CODE[f.status] ?? "XX000");
    }
    let m: RegExpMatchArray | null;
    if (text === "BEGIN" || text === "BEGIN READ ONLY") {
      if (txn) restore(txn.snapshot); // the previous session died mid-transaction
      txn = { readOnly: text !== "BEGIN", snapshot: snapshot() };
      return { rows: [], rowCount: null };
    }
    if (text === "ROLLBACK") {
      if (txn) restore(txn.snapshot);
      txn = null;
      return { rows: [], rowCount: null };
    }
    if (text === "COMMIT") {
      txn = null;
      return { rows: [], rowCount: null };
    }
    if ((m = text.match(/^INSERT INTO "(\w+)" \(([^)]*)\) VALUES \(([^)]*)\) RETURNING "(\w+)"$/))) {
      writable();
      const cols = m[2]!.split(",").map((c) => c.replace(/"/g, ""));
      const n = (seq.get(m[1]!) ?? 0) + 1;
      seq.set(m[1]!, n);
      const row: Row = { id: n };
      cols.forEach((c, i) => (row[c] = values[i]));
      rowsOf(m[1]!).push(row);
      return { rows: [{ [m[4]!]: row[m[4]!] }], rowCount: 1 };
    }
    if ((m = text.match(/^DELETE FROM "(\w+)" WHERE "(\w+)" = \$1$/))) {
      writable();
      const rows = rowsOf(m[1]!);
      const keep = rows.filter((r) => r[m![2]!] !== values[0]);
      const n = rows.length - keep.length;
      tables.set(m[1]!, keep);
      return { rows: [], rowCount: n };
    }
    if ((m = text.match(/^SELECT ((?:"\w+",?)+) FROM "(\w+)" WHERE "(\w+)" = \$1 FOR UPDATE$/))) {
      const cols = m[1]!.split(",").map((c) => c.replace(/"/g, ""));
      const hit = rowsOf(m[2]!).filter((r) => r[m![3]!] === values[0]);
      return { rows: hit.map((r) => Object.fromEntries(cols.map((c) => [c, r[c] ?? null]))), rowCount: hit.length };
    }
    if ((m = text.match(/^UPDATE "(\w+)" SET (.+) WHERE "(\w+)" = \$1$/))) {
      writable();
      const sets = [...m[2]!.matchAll(/"(\w+)" = \$(\d+)/g)].map((x) => [x[1]!, Number(x[2])] as const);
      const hit = rowsOf(m[1]!).filter((r) => r[m![3]!] === values[0]);
      for (const r of hit) for (const [c, i] of sets) r[c] = values[i - 1];
      return { rows: [], rowCount: hit.length };
    }
    if ((m = text.match(/^(?:SELECT|WITH) /i))) {
      if (/\b(DELETE FROM|INSERT INTO|UPDATE )/i.test(text)) writable();
      const rows = rowsOf("users").filter((r) => (values.length ? Number(r.age) > Number(values[0]) : true));
      return { rows: rows.map((r) => ({ ...r })), rowCount: rows.length };
    }
    throw new PgError(`syntax error near "${text.slice(0, 20)}"`, "42601");
  }

  b.pg = { query };
  b.withConnect = {
    query,
    connect: async () => ({ query, release: (d?: boolean | Error) => void b.released.push(d) }) as PgClientLike,
  };
  return b;
}
export type FakePg = ReturnType<typeof fakePg>;
const pg = (b: Backend) => b as FakePg;
const seedUser = (b: Backend) => void pg(b).tables.get("users")!.push({ id: 7, name: "Ann", age: 30, data: null });

export const subject: Subject = {
  name: "postgres",
  secrets: [URL_SECRET, PASSWORD],
  make: (o) => {
    const backend = fakePg();
    return {
      backend,
      connector: createPostgresConnector({ pool: backend.pg, secrets: [URL_SECRET, PASSWORD], timeoutMs: o?.timeoutMs }),
    };
  },
  statusPattern: (s) => new RegExp(STATUS_CODE[s] ?? String(s)),
  faultBody: undefined,
};

export const scenarios: Scenario[] = [
  {
    tool: "query",
    args: { text: "SELECT * FROM users WHERE age > $1", values: [20] },
    setup: seedUser,
    expect: (r) => expect(r).toMatchObject({ rows: [{ id: 7, name: "Ann" }], row_count: 1, truncated: false }),
  },
  { tool: "insert_row", args: { table: "users", values: { name: "Bo", age: 41 } }, expect: (r) => expect(r).toMatchObject({ table: "users", schema: null, key_column: "id", key: 1 }) },
  { tool: "delete_row", args: { table: "users", key: 7 }, setup: seedUser },
  {
    tool: "update_row",
    args: { table: "users", key: 7, set: { name: "Zed", age: 31 } },
    setup: seedUser,
    expect: (r) => expect(r).toMatchObject({ key: 7, previous: { name: "Ann", age: 30 } }),
  },
  {
    tool: "restore_row",
    args: { table: "users", key: 7, values: { name: "Ann", age: 30 } },
    setup: (b) => void pg(b).tables.get("users")!.push({ id: 7, name: "Zed", age: 31, data: null }),
  },
];
