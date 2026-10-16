/**
 * Sliding-window counters for rate limits and budgets. With a {@link KvStore} the windows are shared by every
 * process using the same data store; without one they live in memory.
 */
import { kvUpdate, type KvStore } from "./kv.js";

type Events = Array<[number, number]>; // [timestamp ms, amount]
const NS = "windows";
const MAX_EVENTS = 20_000;

export class WindowCounters {
  private readonly mem = new Map<string, Events>();
  constructor(
    private readonly kv: KvStore | undefined,
    private readonly clock: () => number = Date.now,
  ) {}

  private read(key: string): Events {
    return this.kv ? ((this.kv.get<Events>(NS, key)?.value) ?? []) : (this.mem.get(key) ?? []);
  }

  /** Calls and summed amount inside the last `windowMs`. */
  total(key: string, windowMs: number): { count: number; sum: number } {
    const horizon = this.clock() - windowMs;
    let count = 0;
    let sum = 0;
    for (const [t, a] of this.read(key)) {
      if (t > horizon) {
        count++;
        sum += a;
      }
    }
    return { count, sum };
  }

  add(key: string, amount: number, windowMs: number): void {
    const now = this.clock();
    const trim = (ev: Events | undefined) => [...(ev ?? []).filter(([t]) => t > now - windowMs), [now, amount] as [number, number]].slice(-MAX_EVENTS);
    if (this.kv) kvUpdate<Events>(this.kv, NS, key, trim);
    else this.mem.set(key, trim(this.mem.get(key)));
  }
}
