/**
 * Append-only, hash-chained ledger of everything that happens in a run.
 *
 * Each record carries the SHA-256 of its predecessor, so editing, reordering or deleting a record
 * breaks verification from that point on. SHA-256 is used (not BLAKE3) so any auditor can verify
 * with stock tools, including `sha256sum` and Python's `hashlib`.
 *
 * This detects tampering; it does not prevent a writer who controls the whole file from forging a
 * consistent chain. Anchor `head()` somewhere the writer cannot reach for stronger guarantees.
 */
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { canonicalize, hashPayload, sha256Hex } from "./canonical.js";
import { redactSecrets } from "./redact.js";

export const GENESIS_HASH = "0".repeat(64);

export type LedgerEvent =
  | "run_started"
  | "intended"
  | "approved"
  | "blocked"
  | "would_block"
  | "succeeded"
  | "failed"
  | "uncertain"
  | "compensating"
  | "compensated"
  | "compensation_failed"
  | "unrecoverable"
  | "deferred";

export interface LedgerRecord {
  seq: number;
  ts_ms: number;
  run_id: string;
  /** Step within the run this event concerns, or null for run-level and blocked events. */
  step: number | null;
  actor: string;
  tool: string;
  /** SHA-256 of the canonical JSON of the payload the event concerns. The payload itself is never stored. */
  payload_hash: string;
  /** Why. Required and non-empty. */
  reason: string;
  event: LedgerEvent;
  detail: string;
  prev_hash: string;
  hash: string;
}

export class LedgerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LedgerError";
  }
}

/** A store refused an append because another writer took that sequence number. The ledger retries. */
export class LedgerConflictError extends LedgerError {
  constructor(message = "another writer appended first") {
    super(message);
    this.name = "LedgerConflictError";
  }
}

export type VerifyResult = { ok: true; records: number; head: string } | { ok: false; seq: number; error: string };

const RECORD_FIELDS: Array<[keyof LedgerRecord, "string" | "number" | "number|null"]> = [
  ["seq", "number"],
  ["ts_ms", "number"],
  ["run_id", "string"],
  ["step", "number|null"],
  ["actor", "string"],
  ["tool", "string"],
  ["payload_hash", "string"],
  ["reason", "string"],
  ["event", "string"],
  ["detail", "string"],
  ["prev_hash", "string"],
  ["hash", "string"],
];

function hashOf(r: Omit<LedgerRecord, "hash">): string {
  return sha256Hex(canonicalize(r));
}

/** Verify a sequence of records. Pure: usable on records read from a file, the API, or memory. */
export function verifyRecords(records: readonly LedgerRecord[]): VerifyResult {
  let prev = GENESIS_HASH;
  for (let i = 0; i < records.length; i++) {
    const r = records[i] as unknown as Record<string, unknown>;
    if (typeof r !== "object" || r === null) return { ok: false, seq: i, error: "record is not an object" };
    for (const [field, kind] of RECORD_FIELDS) {
      const v = r[field];
      const good =
        kind === "number|null" ? v === null || typeof v === "number" : typeof v === kind;
      if (!good) return { ok: false, seq: i, error: `field \`${field}\` is missing or has the wrong type` };
    }
    const rec = r as unknown as LedgerRecord;
    if (rec.seq !== i) return { ok: false, seq: rec.seq, error: "sequence number out of order" };
    if (rec.prev_hash !== prev) {
      return { ok: false, seq: rec.seq, error: "prev_hash does not match the previous record" };
    }
    const { hash, ...body } = rec;
    if (hashOf(body) !== hash) {
      return { ok: false, seq: rec.seq, error: "stored hash does not match the record's contents" };
    }
    prev = hash;
  }
  return { ok: true, records: records.length, head: prev };
}

export interface LedgerStore {
  /** Every record, oldest first. Shared stores refresh from the backend on each call. */
  all(): readonly LedgerRecord[];
  /** Must throw {@link LedgerConflictError} if `record.seq` is already taken. */
  append(record: LedgerRecord): void;
}

export class MemoryLedgerStore implements LedgerStore {
  private readonly items: LedgerRecord[] = [];
  all(): readonly LedgerRecord[] {
    return this.items;
  }
  append(record: LedgerRecord): void {
    this.items.push(record);
  }
}

export function parseJsonl(text: string): LedgerRecord[] {
  const out: LedgerRecord[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as LedgerRecord);
    } catch {
      throw new LedgerError(`line ${i + 1}: not valid JSON`);
    }
  }
  return out;
}

export function toJsonl(records: readonly LedgerRecord[]): string {
  return records.map((r) => JSON.stringify(r) + "\n").join("");
}

/**
 * JSONL file store. Every append is fsynced so a journaled intent survives a crash.
 * Single writer: two processes appending to one file will fork the chain.
 */
export class JsonlLedgerStore implements LedgerStore {
  private readonly items: LedgerRecord[];
  constructor(private readonly path: string) {
    this.items = existsSync(path) ? parseJsonl(readFileSync(path, "utf8")) : [];
  }
  all(): readonly LedgerRecord[] {
    return this.items;
  }
  append(record: LedgerRecord): void {
    const fd = openSync(this.path, "a");
    try {
      writeSync(fd, JSON.stringify(record) + "\n");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    this.items.push(record);
  }
}

export interface AppendInput {
  ts_ms: number;
  run_id: string;
  step?: number | null;
  actor: string;
  tool: string;
  /** Hashed, never stored. */
  payload?: unknown;
  reason: string;
  event: LedgerEvent;
  detail?: string;
}

export class Ledger {
  constructor(private readonly store: LedgerStore = new MemoryLedgerStore()) {
    const v = verifyRecords(store.all());
    if (!v.ok) {
      throw new LedgerError(`refusing to open a corrupt ledger: record ${v.seq}: ${v.error}`);
    }
  }

  append(input: AppendInput): LedgerRecord {
    if (!input.reason || !input.reason.trim()) {
      throw new LedgerError("every ledger record needs a non-empty reason");
    }
    for (let attempt = 1; ; attempt++) {
      const all = this.store.all();
      const last = all[all.length - 1];
      const body: Omit<LedgerRecord, "hash"> = {
        seq: all.length,
        ts_ms: input.ts_ms,
        run_id: input.run_id,
        step: input.step ?? null,
        actor: input.actor,
        tool: input.tool,
        payload_hash: hashPayload(input.payload),
        reason: redactSecrets(input.reason),
        event: input.event,
        detail: redactSecrets(input.detail ?? ""),
        prev_hash: last ? last.hash : GENESIS_HASH,
      };
      const record: LedgerRecord = { ...body, hash: hashOf(body) };
      try {
        this.store.append(record);
        return record;
      } catch (e) {
        if (e instanceof LedgerConflictError && attempt < 8) continue; // re-read the tail and try again
        throw e;
      }
    }
  }

  records(): readonly LedgerRecord[] {
    return this.store.all();
  }

  forRun(run_id: string): LedgerRecord[] {
    return this.store.all().filter((r) => r.run_id === run_id);
  }

  head(): string {
    const all = this.store.all();
    const last = all[all.length - 1];
    return last ? last.hash : GENESIS_HASH;
  }

  verify(): VerifyResult {
    return verifyRecords(this.store.all());
  }
}
