import { EffectUncertainError, Registry, idempotencyKey } from "@multimindlab/reversi";
import { describe, expect, it } from "vitest";
import { HttpError, compensatorFor, createStripeConnector } from "../src/index.js";
import { engine, failingFetch, fakeFetch, type Call, type FakeReply } from "./helpers.js";

const KEY = "sk_test_SUPERSECRETKEY999";

function fakeStripe() {
  const customers = new Set<string>();
  const intents = new Map<string, string>();
  let n = 0;
  const h = (c: Call): FakeReply => {
    const u = new URL(c.url);
    const p = u.pathname;
    const form = new URLSearchParams(c.body);
    let m: RegExpMatchArray | null;
    if (c.method === "POST" && p === "/v1/customers") {
      const id = `cus_${++n}`;
      customers.add(id);
      return { json: { id, email: form.get("email"), name: form.get("name") } };
    }
    if (c.method === "DELETE" && (m = p.match(/^\/v1\/customers\/(.+)$/))) {
      return customers.delete(m[1]!)
        ? { json: { id: m[1], deleted: true } }
        : { status: 404, json: { error: { code: "resource_missing", message: "No such customer" } } };
    }
    if (c.method === "POST" && p === "/v1/payment_intents") {
      const id = `pi_${++n}`;
      intents.set(id, "requires_payment_method");
      return { json: { id, status: "requires_payment_method", amount: Number(form.get("amount")), currency: form.get("currency") } };
    }
    if (c.method === "POST" && (m = p.match(/^\/v1\/payment_intents\/(.+)\/cancel$/))) {
      const st = intents.get(m[1]!);
      if (st === undefined) return { status: 404, json: { error: { code: "resource_missing" } } };
      if (st === "canceled" || st === "succeeded") {
        return { status: 400, json: { error: { code: "payment_intent_unexpected_state", message: "bad state" } } };
      }
      intents.set(m[1]!, "canceled");
      return { json: { id: m[1], status: "canceled" } };
    }
    if (c.method === "GET" && (m = p.match(/^\/v1\/payment_intents\/(.+)$/))) {
      return { json: { id: m[1], status: intents.get(m[1]!) } };
    }
    if (c.method === "POST" && p === "/v1/refunds") {
      return { json: { id: "re_1", status: "succeeded", amount: Number(form.get("amount") ?? 1000), currency: "usd" } };
    }
    if (c.method === "GET" && (m = p.match(/^\/v1\/charges\/(.+)$/))) {
      return { json: { id: m[1], amount: 1000, amount_refunded: 0, currency: "usd", status: "succeeded", paid: true, refunded: false } };
    }
    return { status: 500, json: { error: { message: "unexpected" } } };
  };
  return { customers, intents, h };
}

function setup(handler?: (c: Call, n: number) => FakeReply) {
  const st = fakeStripe();
  const f = fakeFetch(handler ?? ((c) => st.h(c)));
  const connector = createStripeConnector({ secretKey: KEY, fetch: f.fetch });
  return { st, f, connector, t: (n: string, a: Record<string, unknown>, ctx = {}) => connector.tools[`stripe.${n}`]!(a, ctx) };
}

describe("stripe manifests", () => {
  it("validate and cross-reference", () => {
    const { connector } = setup();
    const reg = Registry.from(connector.manifests);
    expect(reg.size).toBe(6);
    expect(reg.get("stripe.create_refund")).toMatchObject({
      effect: "irreversible",
      approval: "always",
      permission: "stripe:refund:write",
    });
    expect(reg.get("stripe.create_customer")?.compensation?.tool).toBe("stripe.delete_customer");
    expect(Object.keys(connector.tools).sort()).toEqual(reg.list().map((m) => m.tool).sort());
  });
});

describe("stripe tools", () => {
  it("sends form-encoded bodies, bearer auth and a generated Idempotency-Key", async () => {
    const { t, f } = setup();
    await t("create_customer", { email: "a@b.co", metadata: { order: 7 } });
    const c = f.calls[0]!;
    expect(c.url).toBe("https://api.stripe.com/v1/customers");
    expect(c.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(c.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(c.headers["idempotency-key"]).toMatch(/^[0-9a-f]{64}$/);
    const form = new URLSearchParams(c.body);
    expect(form.get("email")).toBe("a@b.co");
    expect(form.get("metadata[order]")).toBe("7");
  });

  it("uses ctx.idempotency_key when given and different keys for repeated forward calls", async () => {
    const { t, f } = setup();
    await t("create_customer", { email: "a@b.co" }, { idempotency_key: "fixed-key" });
    expect(f.calls[0]!.headers["idempotency-key"]).toBe("fixed-key");
    await t("create_customer", { email: "a@b.co" });
    await t("create_customer", { email: "a@b.co" });
    expect(f.calls[1]!.headers["idempotency-key"]).not.toBe(f.calls[2]!.headers["idempotency-key"]);
  });

  it("validates arguments strictly", async () => {
    const { t, f } = setup();
    await expect(t("create_payment_intent", { amount: 10.5, currency: "usd" })).rejects.toThrow("positive integer");
    await expect(t("create_payment_intent", { amount: 100, currency: "dollars" })).rejects.toThrow("currency");
    await expect(t("delete_customer", { customer_id: "../v1/charges/x" })).rejects.toThrow("not a valid customer id");
    await expect(t("create_refund", {})).rejects.toThrow("exactly one");
    await expect(t("create_refund", { charge: "ch_1", payment_intent: "pi_1" })).rejects.toThrow("exactly one");
    await expect(t("create_refund", { charge: "ch_1", reason: "bored" })).rejects.toThrow("reason");
    await expect(t("create_customer", { metadata: { a: { b: 1 } } })).rejects.toThrow("string, number or boolean");
    await expect(t("create_customer", { bogus: 1 })).rejects.toThrow("unknown argument");
    expect(f.calls).toHaveLength(0);
  });

  it("maps errors with status and never leaks the key", async () => {
    const { t } = setup(() => ({ status: 401, json: { error: { message: `Invalid API Key provided: ${KEY}` } } }));
    const err = await t("create_customer", {}).catch((e) => e);
    expect(err).toBeInstanceOf(HttpError);
    expect(err.status).toBe(401);
    expect(err.message).not.toContain(KEY);
  });

  it("network failure on a write is uncertain", async () => {
    const c = createStripeConnector({ secretKey: KEY, fetch: failingFetch(`reset ${KEY}`) });
    const err = await c.tools["stripe.create_refund"]!({ charge: "ch_1" }, {}).catch((e) => e);
    expect(err).toBeInstanceOf(EffectUncertainError);
    expect(err.message).not.toContain(KEY);
  });

  it("delete_customer and cancel_payment_intent are idempotent", async () => {
    const { t } = setup();
    const cu = (await t("create_customer", {})) as { customer_id: string };
    expect(await t("delete_customer", { customer_id: cu.customer_id })).toMatchObject({ deleted: true });
    expect(await t("delete_customer", { customer_id: cu.customer_id })).toMatchObject({ deleted: false });
    const pi = (await t("create_payment_intent", { amount: 500, currency: "USD" })) as { payment_intent_id: string };
    expect(await t("cancel_payment_intent", { payment_intent_id: pi.payment_intent_id })).toMatchObject({ canceled: true });
    expect(await t("cancel_payment_intent", { payment_intent_id: pi.payment_intent_id })).toMatchObject({
      status: "canceled",
      canceled: false,
    });
  });

  it("a 404 that is not resource_missing is not swallowed; an uncancelable intent fails", async () => {
    const a = setup(() => ({ status: 404, json: { error: { message: "route not found" } } }));
    await expect(a.t("delete_customer", { customer_id: "cus_1" })).rejects.toThrow("404");
    const b = setup((c) =>
      c.method === "GET"
        ? { json: { status: "succeeded" } }
        : { status: 400, json: { error: { code: "payment_intent_unexpected_state", message: "already succeeded" } } },
    );
    await expect(b.t("cancel_payment_intent", { payment_intent_id: "pi_1" })).rejects.toThrow("400");
  });

  it("creates a refund and reads a charge", async () => {
    const { t, f } = setup();
    expect(await t("create_refund", { charge: "ch_9", amount: 250, reason: "duplicate" })).toMatchObject({ refund_id: "re_1" });
    const form = new URLSearchParams(f.calls[0]!.body);
    expect(form.get("charge")).toBe("ch_9");
    expect(form.get("amount")).toBe("250");
    expect(await t("retrieve_charge", { charge_id: "ch_9" })).toMatchObject({ amount: 1000, paid: true });
    expect(f.calls[1]!.headers["idempotency-key"]).toBeUndefined();
  });
});

describe("stripe end to end", () => {
  it("rolls back customers and payment intents, sending the engine's idempotency key", async () => {
    const { connector, st, f } = setup();
    const { call, run } = engine([connector]);
    await call("stripe.create_customer", { email: "x@y.z" });
    await call("stripe.create_payment_intent", { amount: 1500, currency: "usd" });

    const report = await run.rollback({ compensate: compensatorFor([connector]) });
    expect(report.complete).toBe(true);
    expect(st.customers.size).toBe(0);
    expect([...st.intents.values()]).toEqual(["canceled"]);

    const cancel = f.calls.find((c) => c.url.endsWith("/cancel"))!;
    expect(cancel.headers["idempotency-key"]).toBe(idempotencyKey(run.run_id, 1, "stripe.create_payment_intent"));
    expect(cancel.url).toContain("/v1/payment_intents/pi_2/");
    const del = f.calls.find((c) => c.method === "DELETE")!;
    expect(del.url).toBe("https://api.stripe.com/v1/customers/cus_1");
  });

  it("running the whole rollback again is a no-op", async () => {
    const { connector, f } = setup();
    const { call, run } = engine([connector]);
    await call("stripe.create_customer", {});
    await run.rollback({ compensate: compensatorFor([connector]) });
    const n = f.calls.length;
    expect((await run.rollback({ compensate: compensatorFor([connector]) })).complete).toBe(true);
    expect(f.calls.length).toBe(n);
  });

  it("refunds are reported as unrecoverable and are not undone", async () => {
    const { connector, f } = setup();
    const { call, run } = engine([connector]);
    await call("stripe.create_refund", { charge: "ch_1" });
    const report = await run.rollback({ compensate: compensatorFor([connector]) });
    expect(report.unrecoverable).toEqual([0]);
    expect(report.complete).toBe(false);
    expect(f.calls).toHaveLength(1); // only the refund itself
  });

  it("a 500 during compensation fails the step with the same key on retry", async () => {
    const st = fakeStripe();
    let broken = true;
    const f = fakeFetch((c) => (broken && c.method === "DELETE" ? { status: 500, json: { error: { message: "oops" } } } : st.h(c)));
    const connector = createStripeConnector({ secretKey: KEY, fetch: f.fetch });
    const { call, run } = engine([connector]);
    await call("stripe.create_customer", {});
    const comp = compensatorFor([connector]);
    const r1 = await run.rollback({ compensate: comp });
    expect(r1.failed[0]?.error).toContain("500");
    expect(r1.failed[0]?.error).not.toContain(KEY);
    broken = false;
    expect((await run.rollback({ compensate: comp })).complete).toBe(true);
    expect(st.customers.size).toBe(0);
  });
});
