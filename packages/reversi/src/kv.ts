/**
 * A small versioned key-value store for the settings and state that are not the ledger, run state or
 * approvals: halts, delegations, legal holds, budgets, capture records, alert state, tenants.
 *
 * Every backend offers compare-and-set, so several processes can update the same key without losing writes.
 */
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { dirname } from "node:path";

export interface KvEntry<T = unknown> {
  key: string;
  value: T;
  /** Starts at 1 and increases with every write. */
  version: number;
}

export interface KvStore {
  get<T = unknown>(ns: string, key: string): KvEntry<T> | undefined;
  /** Unconditional write. */
  put(ns: string, key: string, value: unknown): void;
  /** Write only if the stored version equals `expected` (0 means the key must not exist). */
  cas(ns: string, key: string, value: unknown, expected: number): boolean;
  delete(ns: string, key: string): boolean;
  list<T = unknown>(ns: string, prefix?: string): KvEntry<T>[];
}

const clone = <T>(v: T): T => (v === undefined ? v : (JSON.parse(JSON.stringify(v)) as T));

export class KvConflictError extends Error {
  constructor(ns: string, key: string) {
    super(`could not update ${ns}/${key}: too many concurrent writers`);
    this.name = "KvConflictError";
  }
}

/** Read-modify-write with retries: `fn` gets the current value (undefined if absent) and returns the new one. */
export function kvUpdate<T>(kv: KvStore, ns: string, key: string, fn: (current: T | undefined) => T, tries = 25): T {
  for (let i = 0; i < tries; i++) {
    const cur = kv.get<T>(ns, key);
    const next = fn(cur ? clone(cur.value) : undefined);
    if (kv.cas(ns, key, next, cur?.version ?? 0)) return next;
  }
  throw new KvConflictError(ns, key);
}

export class MemoryKvStore implements KvStore {
  private readonly m = new Map<string, KvEntry>();
  private id = (ns: string, key: string) => `${ns}\u0000${key}`;
  get<T>(ns: string, key: string) {
    const e = this.m.get(this.id(ns, key));
    return e ? ({ key, value: clone(e.value), version: e.version } as KvEntry<T>) : undefined;
  }
  put(ns: string, key: string, value: unknown) {
    const e = this.m.get(this.id(ns, key));
    this.m.set(this.id(ns, key), { key, value: clone(value), version: (e?.version ?? 0) + 1 });
  }
  cas(ns: string, key: string, value: unknown, expected: number) {
    const e = this.m.get(this.id(ns, key));
    if ((e?.version ?? 0) !== expected) return false;
    this.m.set(this.id(ns, key), { key, value: clone(value), version: expected + 1 });
    return true;
  }
  delete(ns: string, key: string) {
    return this.m.delete(this.id(ns, key));
  }
  list<T>(ns: string, prefix = "") {
    const out: KvEntry<T>[] = [];
    for (const [id, e] of this.m) if (id.startsWith(`${ns}\u0000${prefix}`)) out.push({ key: e.key, value: clone(e.value) as T, version: e.version });
    return out.sort((a, b) => a.key.localeCompare(b.key));
  }
}

/** One JSON file, rewritten atomically under a lock file. Fine for processes on one host. */
export class FileKvStore implements KvStore {
  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
  }
  private read(): Record<string, Record<string, KvEntry>> {
    return existsSync(this.path) ? (JSON.parse(readFileSync(this.path, "utf8")) as Record<string, Record<string, KvEntry>>) : {};
  }
  private locked<T>(fn: (all: Record<string, Record<string, KvEntry>>) => { out: T; write?: boolean }): T {
    const lock = `${this.path}.lock`;
    const deadline = Date.now() + 10_000;
    for (;;) {
      try {
        closeSync(openSync(lock, "wx"));
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        try {
          if (Date.now() - statSync(lock).mtimeMs > 30_000) unlinkSync(lock);
        } catch {
          /* released meanwhile */
        }
        if (Date.now() > deadline) throw new Error("could not lock the settings file");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
      }
    }
    try {
      const all = this.read();
      const r = fn(all);
      if (r.write) {
        const tmp = `${this.path}.${process.pid}.tmp`;
        const fd = openSync(tmp, "w");
        try {
          writeSync(fd, JSON.stringify(all));
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
        renameSync(tmp, this.path);
      }
      return r.out;
    } finally {
      try {
        unlinkSync(lock);
      } catch {
        /* gone */
      }
    }
  }
  get<T>(ns: string, key: string) {
    const e = this.read()[ns]?.[key];
    return e ? ({ key, value: e.value, version: e.version } as KvEntry<T>) : undefined;
  }
  put(ns: string, key: string, value: unknown) {
    this.locked((all) => {
      const bucket = (all[ns] ??= {});
      bucket[key] = { key, value: clone(value), version: (bucket[key]?.version ?? 0) + 1 };
      return { out: undefined, write: true };
    });
  }
  cas(ns: string, key: string, value: unknown, expected: number) {
    return this.locked((all) => {
      const bucket = (all[ns] ??= {});
      if ((bucket[key]?.version ?? 0) !== expected) return { out: false };
      bucket[key] = { key, value: clone(value), version: expected + 1 };
      return { out: true, write: true };
    });
  }
  delete(ns: string, key: string) {
    return this.locked((all) => {
      if (!all[ns]?.[key]) return { out: false };
      delete (all[ns] as Record<string, KvEntry>)[key];
      return { out: true, write: true };
    });
  }
  list<T>(ns: string, prefix = "") {
    return Object.values(this.read()[ns] ?? {})
      .filter((e) => e.key.startsWith(prefix))
      .map((e) => ({ key: e.key, value: e.value as T, version: e.version }))
      .sort((a, b) => a.key.localeCompare(b.key));
  }
}
