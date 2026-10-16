/**
 * Delegation: an approver hands their approval authority to someone else for a while (leave, rotation). The delegate
 * approves as themselves, "on behalf of" the delegator, who may not also approve the same request; every use is
 * recorded in the decision.
 */
import { randomUUID } from "node:crypto";
import type { KvStore } from "./kv.js";

export interface Delegation {
  id: string;
  from: string;
  to: string;
  /** Groups delegated. Empty: all of the delegator's groups. */
  groups: string[];
  reason: string;
  created_ms: number;
  until_ms: number;
  revoked?: boolean;
}

const NS = "delegations";

export class Delegations {
  constructor(
    private readonly kv: KvStore,
    private readonly now: () => number = Date.now,
  ) {}

  grant(d: { from: string; to: string; until_ms: number; groups?: string[]; reason: string }): Delegation {
    if (!d.from || !d.to) throw new Error("a delegation needs from and to");
    if (d.from === d.to) throw new Error("you cannot delegate to yourself");
    if (!(d.until_ms > this.now())) throw new Error("a delegation must end in the future");
    if (d.until_ms - this.now() > 90 * 86_400_000) throw new Error("a delegation can last at most 90 days");
    if (!d.reason.trim()) throw new Error("a delegation needs a reason");
    const rec: Delegation = { id: `dlg_${randomUUID()}`, from: d.from, to: d.to, groups: d.groups ?? [], reason: d.reason, created_ms: this.now(), until_ms: d.until_ms };
    this.kv.put(NS, rec.id, rec);
    return rec;
  }

  revoke(id: string): boolean {
    const e = this.kv.get<Delegation>(NS, id);
    if (!e) return false;
    this.kv.put(NS, id, { ...e.value, revoked: true });
    return true;
  }

  list(): Delegation[] {
    return this.kv.list<Delegation>(NS).map((e) => e.value);
  }

  /** Delegations in force that let `to` act for someone else. */
  activeFor(to: string): Delegation[] {
    return this.list().filter((d) => d.to === to && !d.revoked && d.until_ms > this.now());
  }
}
