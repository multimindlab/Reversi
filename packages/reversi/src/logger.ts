/** Structured JSON logging with redaction: credentials never reach a log line, whatever field they arrive in. */
import { redactSecrets } from "./redact.js";

export type Level = "debug" | "info" | "warn" | "error";
const RANK: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const SENSITIVE_KEY = /pass(word|wd)?|secret|token|authorization|api[_-]?key|cookie|credential|private[_-]?key|signature/i;

export interface Logger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
  child(fields: Record<string, unknown>): Logger;
}

export function redactFields(v: unknown, depth = 0): unknown {
  if (depth > 6) return "[too deep]";
  if (typeof v === "string") return redactSecrets(v);
  if (v instanceof Error) return { name: v.name, message: redactSecrets(v.message) };
  if (Array.isArray(v)) return v.slice(0, 50).map((x) => redactFields(x, depth + 1));
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, SENSITIVE_KEY.test(k) ? "[REDACTED]" : redactFields(x, depth + 1)]));
  return v;
}

export function createLogger(o: { level?: Level; write?: (line: string) => void; base?: Record<string, unknown>; now?: () => Date } = {}): Logger {
  const min = RANK[o.level ?? "info"];
  const write = o.write ?? ((l: string) => process.stdout.write(l + "\n"));
  const now = o.now ?? (() => new Date());
  const make = (base: Record<string, unknown>): Logger => {
    const log = (level: Level) => (msg: string, fields: Record<string, unknown> = {}) => {
      if (RANK[level] < min) return;
      write(JSON.stringify({ level, time: now().toISOString(), msg: redactSecrets(msg), ...(redactFields({ ...base, ...fields }) as object) }));
    };
    return { debug: log("debug"), info: log("info"), warn: log("warn"), error: log("error"), child: (f) => make({ ...base, ...f }) };
  };
  return make(o.base ?? {});
}
