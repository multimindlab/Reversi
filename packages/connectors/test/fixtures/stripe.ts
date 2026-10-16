import { expect } from "vitest";
import { createStripeConnector } from "../../src/index.js";
import { httpBackend, type Backend, type Scenario, type Subject } from "../certification.js";
import type { Call, FakeReply } from "../helpers.js";

export const KEY = "sk_test_SUPERSECRETKEY999";

/** A tiny Stripe, including the Idempotency-Key replay behaviour that makes retried writes safe. */
export function fakeStripe() {
  const customers = new Set<string>();
  const intents = new Map<string, string>();
  const refunds: string[] = [];
  const replay = new Map<string, FakeReply>();
  let n = 0;
  const route = (c: Call): FakeReply => {
    const p = new URL(c.url).pathname;
    const form = new URLSearchParams(c.body);
    let m: RegExpMatchArray | null;
    if (c.method === "POST" && p === "/v1/customers") {
      const id = `cus_${++n}`;
      customers.add(id);
      return { json: { id, email: form.get("email"), name: form.get("name") } };
    }
    if (c.method === "DELETE" && (m = p.match(/^\/v1\/customers\/(.+)$/))) {
      return customers.delete(m[1]!) ? { json: { id: m[1], deleted: true } } : { status: 404, json: { error: { code: "resource_missing", message: "No such customer" } } };
    }
    if (c.method === "POST" && p === "/v1/payment_intents") {
      const id = `pi_${++n}`;
      intents.set(id, "requires_payment_method");
      return { json: { id, status: "requires_payment_method", amount: Number(form.get("amount")), currency: form.get("currency") } };
    }
    if (c.method === "POST" && (m = p.match(/^\/v1\/payment_intents\/(.+)\/cancel$/))) {
      const st = intents.get(m[1]!);
      if (st === undefined) return { status: 404, json: { error: { code: "resource_missing" } } };
      if (st === "canceled" || st === "succeeded") return { status: 400, json: { error: { code: "payment_intent_unexpected_state", message: "bad state" } } };
      intents.set(m[1]!, "canceled");
      return { json: { id: m[1], status: "canceled" } };
    }
    if (c.method === "GET" && (m = p.match(/^\/v1\/payment_intents\/(.+)$/))) return { json: { id: m[1], status: intents.get(m[1]!) } };
    if (c.method === "POST" && p === "/v1/refunds") {
      refunds.push(`re_${++n}`);
      return { json: { id: refunds.at(-1), status: "succeeded", amount: Number(form.get("amount") ?? 1000), currency: "usd" } };
    }
    if (c.method === "GET" && (m = p.match(/^\/v1\/charges\/(.+)$/))) {
      return { json: { id: m[1], amount: 1000, amount_refunded: 0, currency: "usd", status: "succeeded", paid: true, refunded: false } };
    }
    return { status: 500, json: { error: { message: "unexpected" } } };
  };
  const b = httpBackend({
    state: () => ({ customers: [...customers].sort(), intents: [...intents], refunds }),
    handle: (c) => {
      const key = c.headers["idempotency-key"];
      if (c.method === "POST" && key && replay.has(key)) return replay.get(key)!;
      const r = route(c);
      if (c.method === "POST" && key && (r.status ?? 200) < 500) replay.set(key, r);
      return r;
    },
  });
  return Object.assign(b, { customers, intents, refunds });
}
type FakeStripe = ReturnType<typeof fakeStripe>;
const st = (b: Backend) => b as FakeStripe;
const hasKey = (c: Call, key: string) => c.headers["idempotency-key"] === key;

export const subject: Subject = {
  name: "stripe",
  secrets: [KEY],
  make: (o) => {
    const backend = fakeStripe();
    return { backend, connector: createStripeConnector({ secretKey: KEY, fetch: backend.fetch, timeoutMs: o?.timeoutMs }) };
  },
  faultBody: (_s, secret) => ({ json: { error: { message: `Invalid API Key provided: ${secret}` } } }),
};

export const scenarios: Scenario[] = [
  { tool: "retrieve_charge", args: { charge_id: "ch_123" }, expect: (r) => expect(r).toMatchObject({ amount: 1000, paid: true }) },
  { tool: "create_customer", args: { email: "a@example.com", name: "Ann", metadata: { plan: "pro" } }, usesKey: hasKey, expect: (r) => expect(r).toMatchObject({ customer_id: "cus_1" }) },
  { tool: "delete_customer", args: { customer_id: "cus_7" }, setup: (b) => void st(b).customers.add("cus_7") },
  { tool: "create_payment_intent", args: { amount: 1500, currency: "EUR" }, usesKey: hasKey,
    expect: (r) => expect(r).toMatchObject({ payment_intent_id: "pi_1", currency: "eur" }),
    // a canceled intent stays on the account, in its final state
    restored: (_b, after) => expect((after as { intents: Array<[string, string]> }).intents.map((i) => i[1])).toEqual(["canceled"]),
  },
  { tool: "cancel_payment_intent", args: { payment_intent_id: "pi_7" }, usesKey: hasKey, setup: (b) => void st(b).intents.set("pi_7", "requires_payment_method") },
  { tool: "create_refund", args: { charge: "ch_123", amount: 500 }, usesKey: hasKey, expect: (r) => expect(r).toMatchObject({ status: "succeeded" }) },
];
