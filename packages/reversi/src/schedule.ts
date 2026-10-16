/** Time-window conditions for policy rules (business hours, maintenance windows) and freeze periods. */

const DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"] as const;
export type Day = (typeof DAYS)[number];

export interface Window {
  /** Days of the week the window covers. Default: every day. */
  days?: Day[];
  /** `HH:MM-HH:MM` in `timezone`; may wrap midnight (`22:00-06:00`). Default: all day. */
  between?: string;
  /** IANA time zone, default UTC. */
  timezone?: string;
  /** Invert: the window matches when the time is *outside* the described span. */
  outside?: boolean;
}

export interface Freeze {
  id: string;
  /** ISO timestamps. */
  from: string;
  to: string;
  reason: string;
  /** Which calls are frozen. Default: every call that is not read_only. */
  match?: { tool?: string | string[]; effect?: string | string[]; environment?: string | string[] };
}

const HHMM = /^([01]?\d|2[0-3]):([0-5]\d)-([01]?\d|2[0-3]):([0-5]\d)$/;

export function parseWindow(raw: unknown, where: string, errors: string[]): Window | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    errors.push(`${where}: window must be an object`);
    return undefined;
  }
  const w = raw as Record<string, unknown>;
  for (const k of Object.keys(w)) if (!["days", "between", "timezone", "outside"].includes(k)) errors.push(`${where}: unknown window field \`${k}\``);
  if (w.days !== undefined && (!Array.isArray(w.days) || w.days.some((d) => !DAYS.includes(d as Day)))) errors.push(`${where}: window.days must be a list of ${DAYS.join(", ")}`);
  if (w.between !== undefined && (typeof w.between !== "string" || !HHMM.test(w.between))) errors.push(`${where}: window.between must look like 09:00-17:00`);
  if (w.timezone !== undefined) {
    try {
      new Intl.DateTimeFormat("en-US", { timeZone: String(w.timezone) });
    } catch {
      errors.push(`${where}: window.timezone is not a valid IANA time zone`);
    }
  }
  if (w.outside !== undefined && typeof w.outside !== "boolean") errors.push(`${where}: window.outside must be a boolean`);
  return w as Window;
}

/** True when `nowMs` falls in the window (or outside it, for `outside: true`). */
export function inWindow(w: Window, nowMs: number): boolean {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: w.timezone ?? "UTC", weekday: "short", hour: "2-digit", minute: "2-digit", hour12: false }).formatToParts(new Date(nowMs));
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
  const day = get("weekday").slice(0, 3).toLowerCase() as Day;
  const minutes = (Number(get("hour")) % 24) * 60 + Number(get("minute"));
  let inside = !w.days || w.days.includes(day);
  if (inside && w.between) {
    const m = HHMM.exec(w.between) as RegExpExecArray;
    const from = Number(m[1]) * 60 + Number(m[2]);
    const to = Number(m[3]) * 60 + Number(m[4]);
    inside = from <= to ? minutes >= from && minutes < to : minutes >= from || minutes < to;
  }
  return w.outside ? !inside : inside;
}

export function parseFreeze(raw: unknown, where: string, errors: string[]): Freeze | undefined {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    errors.push(`${where}: must be an object`);
    return undefined;
  }
  const f = raw as Record<string, unknown>;
  for (const k of Object.keys(f)) if (!["id", "from", "to", "reason", "match"].includes(k)) errors.push(`${where}: unknown field \`${k}\``);
  if (typeof f.id !== "string" || !f.id) errors.push(`${where}: id is required`);
  const from = Date.parse(String(f.from));
  const to = Date.parse(String(f.to));
  if (!Number.isFinite(from) || !Number.isFinite(to)) errors.push(`${where}: from and to must be ISO timestamps`);
  else if (to <= from) errors.push(`${where}: to must be after from`);
  if (typeof f.reason !== "string" || !f.reason) errors.push(`${where}: a freeze needs a reason`);
  return f as unknown as Freeze;
}

export const frozenAt = (f: Freeze, nowMs: number): boolean => nowMs >= Date.parse(f.from) && nowMs < Date.parse(f.to);
