import { EffectUncertainError } from "@multimindlab/reversi";
import { defineConnector, matches, optMatches, optPosInt, redact, str, type Connector } from "./common.js";

export interface PgResult {
  rows: Record<string, unknown>[];
  rowCount: number | null;
}
export interface PgClientLike {
  query(text: string, values?: unknown[]): Promise<PgResult>;
  /** A `pg` pool client: pass `true` to drop a connection whose state is unknown. */
  release?(destroy?: boolean | Error): void;
}
/** What the connector needs from a `pg` Pool. Without `connect`, `query` is assumed to be one session. */
export interface PgLike {
  query(text: string, values?: unknown[]): Promise<PgResult>;
  connect?(): Promise<PgClientLike>;
}

export interface PostgresConfig {
  pool: PgLike;
  /** Text to scrub from error messages, such as the connection string and password. */
  secrets?: string[];
  timeoutMs?: number;
  /** Most rows `query` returns. Default 1000. */
  maxRows?: number;
}

/** A `pg` Pool for a connection string. `pg` is loaded on demand. */
export async function createPgPool(connectionString: string): Promise<PgLike & { end(): Promise<void> }> {
  const name: string = "pg";
  const mod = (await import(name)) as { default?: { Pool: new (o: object) => unknown }; Pool?: new (o: object) => unknown };
  const Pool = mod.Pool ?? mod.default?.Pool;
  if (!Pool) throw new Error("the `pg` package is not installed");
  return new Pool({ connectionString }) as PgLike & { end(): Promise<void> };
}

export const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const MAX_COLUMNS = 100;

/** An application-level failure inside a session: the transaction is rolled back and the error surfaces as is. */
class ToolError extends Error {}
class TimedOut extends Error {}

type Scalar = string | number | boolean | null;
type Q = (text: string, values?: unknown[], mutation?: boolean) => Promise<PgResult>;

const quote = (id: string) => `"${id}"`;

function ident(args: Record<string, unknown>, key: string): string {
  return matches(args, key, IDENT, "SQL identifier (letters, digits, underscore; max 63)");
}

/** An optional identifier; `null` (as produced by a `$result` reference) counts as absent. */
function optIdent(args: Record<string, unknown>, key: string): string | undefined {
  if (args[key] === null) return undefined;
  return optMatches(args, key, IDENT, "SQL identifier (letters, digits, underscore; max 63)");
}

function table(args: Record<string, unknown>): string {
  const schema = optIdent(args, "schema");
  const t = ident(args, "table");
  return schema ? `${quote(schema)}.${quote(t)}` : quote(t);
}

/** A bindable parameter: scalars as is, objects and arrays as JSON text (for json/jsonb columns). */
function bindable(v: unknown, what: string): unknown {
  if (v === null || typeof v === "string" || typeof v === "boolean") return v;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error(`${what} must be a finite number`);
    return v;
  }
  if (v instanceof Date) return v.toISOString();
  if (typeof v === "object") {
    if (Buffer.isBuffer(v)) throw new Error(`${what} is binary, which this connector does not handle`);
    return JSON.stringify(v);
  }
  throw new Error(`${what} has an unsupported type`);
}

function keyValue(args: Record<string, unknown>): string | number {
  const v = args.key;
  if (typeof v === "string" && v.length > 0 && v.length <= 512) return v;
  if (typeof v === "number" && Number.isSafeInteger(v)) return v;
  throw new Error("`key` must be a non-empty string or an integer");
}

function columnValues(args: Record<string, unknown>, field: string): Array<[string, unknown]> {
  const v = args[field];
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error(`\`${field}\` must be an object of column values`);
  const entries = Object.entries(v);
  if (entries.length === 0) throw new Error(`\`${field}\` must not be empty`);
  if (entries.length > MAX_COLUMNS) throw new Error(`\`${field}\` has more than ${MAX_COLUMNS} columns`);
  return entries.map(([c, val]) => {
    if (!IDENT.test(c)) throw new Error(`\`${field}\` has an invalid column name \`${c.slice(0, 64)}\``);
    return [c, bindable(val, `\`${field}.${c}\``)];
  });
}

/** JSON-safe copy of a row: dates as ISO text, bigints as strings, binary as hex. */
function jsonSafe(v: unknown): unknown {
  if (v instanceof Date) return v.toISOString();
  if (typeof v === "bigint") return v.toString();
  if (Buffer.isBuffer(v)) return `\\x${v.toString("hex")}`;
  if (Array.isArray(v)) return v.map(jsonSafe);
  if (typeof v === "object" && v !== null) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, jsonSafe(x)]));
  }
  return v;
}

function sqlState(e: unknown): string | undefined {
  const c = typeof e === "object" && e !== null && "code" in e ? (e as { code: unknown }).code : undefined;
  return typeof c === "string" && /^[0-9A-Z]{5}$/.test(c) ? c : undefined;
}

/** Only SELECT and WITH, and a single statement; the READ ONLY transaction is the real guard. */
function readOnlySql(text: string): string {
  const t = text.trim().replace(/;+\s*$/, "");
  if (!/^(select|with)\b/i.test(t)) throw new Error("`text` must be a SELECT (or WITH ... SELECT) statement");
  if (t.includes(";")) throw new Error("`text` must be a single statement without `;`");
  if (t.includes("\0")) throw new Error("`text` contains a NUL byte");
  return t;
}

export function createPostgresConnector(cfg: PostgresConfig): Connector {
  if (!cfg.pool || typeof cfg.pool.query !== "function") throw new Error("postgres connector needs a `pool`");
  const secrets = cfg.secrets ?? [];
  const timeoutMs = cfg.timeoutMs ?? 30000;
  const maxRows = cfg.maxRows ?? 1000;

  function race<T>(p: Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const t = setTimeout(() => reject(new TimedOut(`no response within ${timeoutMs} ms`)), timeoutMs);
      p.then(
        (v) => {
          clearTimeout(t);
          resolve(v);
        },
        (e: unknown) => {
          clearTimeout(t);
          reject(e);
        },
      );
    });
  }

  /**
   * Run `fn` on one session. A driver error with an SQLSTATE means the server rejected the statement, so nothing
   * was applied. A failure without one (connection lost, timeout) after a write was sent leaves the outcome unknown.
   */
  async function session<T>(label: string, mutating: boolean, fn: (q: Q) => Promise<T>): Promise<T> {
    let client: PgClientLike | undefined;
    let mutationSent = false;
    let drop = false;
    const q: Q = (text, values, mutation = false) => {
      if (mutation) mutationSent = true;
      return (client ?? cfg.pool).query(text, values);
    };
    try {
      return await race(
        (async () => {
          if (cfg.pool.connect) client = await cfg.pool.connect();
          return fn(q);
        })(),
      );
    } catch (e) {
      const code = sqlState(e);
      if (e instanceof ToolError || code) {
        await (client ?? cfg.pool).query("ROLLBACK").catch(() => undefined);
        if (e instanceof ToolError) throw new Error(`${label}: ${redact(e.message, secrets)}`);
        const err = new Error(`${label}: Postgres error ${code}: ${redact((e as Error).message, secrets)}`);
        (err as Error & { code?: string }).code = code;
        throw err;
      }
      drop = true;
      const msg = redact(e instanceof Error ? e.message : String(e), secrets);
      if (mutating && mutationSent) {
        throw new EffectUncertainError(`${label}: connection failed (${msg}); the effect may have happened`);
      }
      throw new Error(`${label}: connection failed (${msg})`);
    } finally {
      client?.release?.(drop);
    }
  }

  const tableProps = {
    table: { type: "string", description: "Table name (letters, digits, underscore)" },
    schema: { type: ["string", "null"], description: "Optional schema name" },
  };
  const keyProps = {
    key_column: { type: "string", description: "Primary key column; default id" },
    key: { description: "Primary key value (string or integer)" },
  };

  return defineConnector("postgres", [
    {
      name: "query",
      description:
        "Run one SELECT with bound parameters ($1, $2, ...). It runs in a READ ONLY transaction, so it cannot change data.",
      effect: "read_only",
      permission: "postgres:rows:read",
      properties: {
        text: { type: "string", description: "A single SELECT statement using $1, $2, ... placeholders" },
        values: { type: "array", items: {}, description: "Parameter values, bound and never interpolated" },
        limit: { type: "integer", minimum: 1, description: `At most this many rows (cap ${maxRows})` },
      },
      required: ["text"],
      handler: async (args) => {
        const text = readOnlySql(str(args, "text", { max: 100000 }));
        const raw = args.values ?? [];
        if (!Array.isArray(raw) || raw.length > 200) throw new Error("`values` must be an array of at most 200 items");
        const values = raw.map((v, i) => bindable(v, `\`values[${i}]\``));
        const limit = Math.min(optPosInt(args, "limit") ?? maxRows, maxRows);
        return session("Postgres query", false, async (q) => {
          await q("BEGIN READ ONLY");
          const r = await q(text, values);
          await q("ROLLBACK");
          return {
            rows: r.rows.slice(0, limit).map(jsonSafe),
            row_count: r.rows.length,
            truncated: r.rows.length > limit,
          };
        });
      },
    },
    {
      name: "insert_row",
      description:
        "Insert one row with bound values and return its primary key (INSERT ... RETURNING). Rollback deletes the row by that key.",
      effect: "reversible",
      permission: "postgres:rows:write",
      compensation: {
        tool: "delete_row",
        argument_map: {
          table: "$result.table",
          schema: "$result.schema",
          key_column: "$result.key_column",
          key: "$result.key",
        },
      },
      properties: {
        ...tableProps,
        key_column: keyProps.key_column,
        values: { type: "object", description: "Column name to value" },
      },
      required: ["table", "values"],
      handler: async (args) => {
        const t = table(args);
        const keyColumn = optMatches(args, "key_column", IDENT, "SQL identifier") ?? "id";
        const cols = columnValues(args, "values");
        const text = `INSERT INTO ${t} (${cols.map(([c]) => quote(c)).join(",")}) VALUES (${cols
          .map((_, i) => `$${i + 1}`)
          .join(",")}) RETURNING ${quote(keyColumn)}`;
        const r = await session("Postgres insert_row", true, (q) =>
          q(
            text,
            cols.map(([, v]) => v),
            true,
          ),
        );
        const key = jsonSafe(r.rows[0]?.[keyColumn]);
        if (typeof key !== "string" && typeof key !== "number") throw new Error("Postgres did not return a usable primary key");
        return {
          table: str(args, "table"),
          schema: optIdent(args, "schema") ?? null,
          key_column: keyColumn,
          key,
        };
      },
    },
    {
      name: "delete_row",
      description:
        "Delete one row by primary key. A row that is already gone counts as success. Used to undo insert_row; the data cannot be recovered, so withhold this permission from agents.",
      effect: "idempotent",
      permission: "postgres:rows:delete",
      properties: { ...tableProps, ...keyProps },
      required: ["table", "key"],
      handler: async (args) => {
        const t = table(args);
        const keyColumn = optMatches(args, "key_column", IDENT, "SQL identifier") ?? "id";
        const key = keyValue(args);
        const r = await session("Postgres delete_row", true, (q) =>
          q(`DELETE FROM ${t} WHERE ${quote(keyColumn)} = $1`, [key], true),
        );
        return { deleted: (r.rowCount ?? 0) > 0 };
      },
    },
    {
      name: "update_row",
      description:
        "Set columns of one row by primary key. In one transaction it locks the row, reads the old values of exactly those columns, updates, and returns the old values so rollback can set them back.",
      effect: "reversible",
      permission: "postgres:rows:write",
      compensation: {
        tool: "restore_row",
        argument_map: {
          table: "$result.table",
          schema: "$result.schema",
          key_column: "$result.key_column",
          key: "$result.key",
          values: "$result.previous",
        },
      },
      properties: { ...tableProps, ...keyProps, set: { type: "object", description: "Column name to new value" } },
      required: ["table", "key", "set"],
      handler: async (args) => {
        const t = table(args);
        const keyColumn = optMatches(args, "key_column", IDENT, "SQL identifier") ?? "id";
        const key = keyValue(args);
        const cols = columnValues(args, "set");
        if (cols.some(([c]) => c === keyColumn)) throw new Error("`set` must not change the key column");
        const names = cols.map(([c]) => c);
        const prev = await session("Postgres update_row", true, async (q) => {
          await q("BEGIN");
          const sel = await q(`SELECT ${names.map(quote).join(",")} FROM ${t} WHERE ${quote(keyColumn)} = $1 FOR UPDATE`, [key]);
          if (sel.rows.length !== 1) throw new ToolError("no row with that key");
          const upd = await q(
            `UPDATE ${t} SET ${cols.map(([c], i) => `${quote(c)} = $${i + 2}`).join(", ")} WHERE ${quote(keyColumn)} = $1`,
            [key, ...cols.map(([, v]) => v)],
            true,
          );
          if (upd.rowCount !== 1) throw new ToolError(`expected to update 1 row, updated ${upd.rowCount ?? 0}`);
          await q("COMMIT", undefined, true);
          return sel.rows[0] as Record<string, unknown>;
        });
        return {
          table: str(args, "table"),
          schema: optIdent(args, "schema") ?? null,
          key_column: keyColumn,
          key,
          previous: jsonSafe(prev),
        };
      },
    },
    {
      name: "restore_row",
      description:
        "Set columns of one row back to saved values. Safe to repeat; fails if the row no longer exists. Used to undo update_row.",
      effect: "idempotent",
      permission: "postgres:rows:write",
      properties: { ...tableProps, ...keyProps, values: { type: "object", description: "Column name to saved value" } },
      required: ["table", "key", "values"],
      handler: async (args) => {
        const t = table(args);
        const keyColumn = optMatches(args, "key_column", IDENT, "SQL identifier") ?? "id";
        const key = keyValue(args);
        const cols = columnValues(args, "values");
        const r = await session("Postgres restore_row", true, (q) =>
          q(
            `UPDATE ${t} SET ${cols.map(([c], i) => `${quote(c)} = $${i + 2}`).join(", ")} WHERE ${quote(keyColumn)} = $1`,
            [key, ...cols.map(([, v]) => v)],
            true,
          ),
        );
        if ((r.rowCount ?? 0) === 0) throw new Error("Postgres restore_row: no row with that key");
        return { restored: cols.map(([c]) => c) };
      },
    },
  ]);
}
