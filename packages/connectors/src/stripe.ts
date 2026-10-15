import { createHash, randomUUID } from "node:crypto";
import { canonicalize } from "@multimindlab/reversi";
import {
  HttpError,
  asRecord,
  defineConnector,
  matches,
  optMatches,
  optPosInt,
  optStr,
  optStringMap,
  posInt,
  send,
  snippet,
  type Connector,
  type Fetch,
  type Sent,
  type ToolContext,
} from "./common.js";

export interface StripeConfig {
  secretKey: string;
  fetch?: Fetch;
  baseUrl?: string;
  timeoutMs?: number;
}

const CUSTOMER = /^cus_[A-Za-z0-9]{1,64}$/;
const INTENT = /^pi_[A-Za-z0-9]{1,64}$/;
const CHARGE = /^(ch|py)_[A-Za-z0-9]{1,64}$/;

function form(data: Record<string, unknown>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(data)) {
    if (v === undefined) continue;
    if (typeof v === "object" && v !== null) {
      for (const [mk, mv] of Object.entries(v as Record<string, string>)) p.set(`${k}[${mk}]`, mv);
    } else {
      p.set(k, String(v));
    }
  }
  return p.toString();
}

export function createStripeConnector(cfg: StripeConfig): Connector {
  if (!cfg.secretKey) throw new Error("stripe connector needs a `secretKey`");
  const f = cfg.fetch ?? fetch;
  const base = (cfg.baseUrl ?? "https://api.stripe.com").replace(/\/+$/, "");
  const secrets = [cfg.secretKey];
  const timeoutMs = cfg.timeoutMs ?? 30000;

  async function api(
    tool: string,
    method: "GET" | "POST" | "DELETE",
    p: string,
    o: { data?: Record<string, unknown>; ctx?: ToolContext; args?: unknown; tolerate?: number[] } = {},
  ): Promise<Sent> {
    const label = `Stripe ${method} ${p}`;
    const headers: Record<string, string> = { Authorization: `Bearer ${cfg.secretKey}` };
    if (method === "POST") {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      // A random component keeps two identical, deliberate calls from being deduplicated by Stripe.
      headers["Idempotency-Key"] =
        o.ctx?.idempotency_key ??
        createHash("sha256")
          .update(canonicalize([tool, o.args ?? {}, randomUUID()]))
          .digest("hex");
    }
    const res = await send(
      f,
      base + p,
      { method, headers, body: method === "POST" ? form(o.data ?? {}) : undefined },
      { label, mutating: method !== "GET", secrets, timeoutMs },
    );
    if (!res.ok && !(o.tolerate ?? []).includes(res.status)) {
      throw new HttpError(`${label} failed with status ${res.status}: ${snippet(res, secrets)}`, res.status);
    }
    return res;
  }

  const errCode = (r: Sent): string | undefined => {
    const c = asRecord(asRecord(r.json).error).code;
    return typeof c === "string" ? c : undefined;
  };

  const meta = { type: "object", additionalProperties: { type: "string" } };

  return defineConnector("stripe", [
    {
      name: "retrieve_charge",
      description: "Read a charge.",
      effect: "read_only",
      permission: "stripe:charges:read",
      properties: { charge_id: { type: "string" } },
      required: ["charge_id"],
      handler: async (args) => {
        const id = matches(args, "charge_id", CHARGE, "charge id");
        const j = asRecord((await api("retrieve_charge", "GET", `/v1/charges/${id}`)).json);
        return {
          charge_id: j.id,
          amount: j.amount,
          amount_refunded: j.amount_refunded,
          currency: j.currency,
          status: j.status,
          paid: j.paid,
          refunded: j.refunded,
        };
      },
    },
    {
      name: "create_customer",
      description: "Create a customer. Rollback deletes it.",
      effect: "reversible",
      permission: "stripe:customers:write",
      compensation: { tool: "delete_customer", argument_map: { customer_id: "$result.customer_id" } },
      properties: {
        email: { type: "string" },
        name: { type: "string" },
        description: { type: "string" },
        metadata: meta,
      },
      handler: async (args, ctx) => {
        const data = {
          email: optStr(args, "email", { max: 512 }),
          name: optStr(args, "name", { max: 512 }),
          description: optStr(args, "description", { max: 1000 }),
          metadata: optStringMap(args, "metadata"),
        };
        const j = asRecord((await api("create_customer", "POST", "/v1/customers", { data, ctx, args })).json);
        if (typeof j.id !== "string") throw new Error("Stripe response had no customer id");
        return { customer_id: j.id, email: j.email ?? null, name: j.name ?? null };
      },
    },
    {
      name: "delete_customer",
      description: "Delete a customer. A customer that is already gone counts as success.",
      effect: "idempotent",
      permission: "stripe:customers:write",
      properties: { customer_id: { type: "string" } },
      required: ["customer_id"],
      handler: async (args, ctx) => {
        const id = matches(args, "customer_id", CUSTOMER, "customer id");
        const r = await api("delete_customer", "DELETE", `/v1/customers/${id}`, { ctx, tolerate: [404] });
        if (r.status === 404 && errCode(r) !== "resource_missing") {
          throw new HttpError(`Stripe DELETE /v1/customers/${id} failed with status 404: ${snippet(r, secrets)}`, 404);
        }
        return { customer_id: id, deleted: r.status !== 404 };
      },
    },
    {
      name: "create_payment_intent",
      description: "Create a payment intent (not confirmed). Rollback cancels it.",
      effect: "reversible",
      permission: "stripe:payments:write",
      compensation: {
        tool: "cancel_payment_intent",
        argument_map: { payment_intent_id: "$result.payment_intent_id" },
      },
      properties: {
        amount: { type: "integer", minimum: 1, description: "Smallest currency unit" },
        currency: { type: "string", description: "Three-letter ISO code" },
        customer: { type: "string" },
        description: { type: "string" },
        metadata: meta,
      },
      required: ["amount", "currency"],
      handler: async (args, ctx) => {
        const data = {
          amount: posInt(args, "amount"),
          currency: matches(args, "currency", /^[A-Za-z]{3}$/, "currency code").toLowerCase(),
          customer: optMatches(args, "customer", CUSTOMER, "customer id"),
          description: optStr(args, "description", { max: 1000 }),
          metadata: optStringMap(args, "metadata"),
        };
        const j = asRecord(
          (await api("create_payment_intent", "POST", "/v1/payment_intents", { data, ctx, args })).json,
        );
        if (typeof j.id !== "string") throw new Error("Stripe response had no payment intent id");
        return { payment_intent_id: j.id, status: j.status, amount: j.amount, currency: j.currency };
      },
    },
    {
      name: "cancel_payment_intent",
      description: "Cancel a payment intent. An intent that is already canceled counts as success.",
      effect: "idempotent",
      permission: "stripe:payments:write",
      properties: { payment_intent_id: { type: "string" } },
      required: ["payment_intent_id"],
      handler: async (args, ctx) => {
        const id = matches(args, "payment_intent_id", INTENT, "payment intent id");
        const p = `/v1/payment_intents/${id}`;
        const r = await api("cancel_payment_intent", "POST", `${p}/cancel`, { ctx, tolerate: [400] });
        if (r.status === 400) {
          if (errCode(r) === "payment_intent_unexpected_state") {
            const now = asRecord((await api("cancel_payment_intent", "GET", p)).json);
            if (now.status === "canceled") return { payment_intent_id: id, status: "canceled", canceled: false };
          }
          throw new HttpError(`Stripe POST ${p}/cancel failed with status 400: ${snippet(r, secrets)}`, 400);
        }
        return { payment_intent_id: id, status: asRecord(r.json).status ?? "canceled", canceled: true };
      },
    },
    {
      name: "create_refund",
      description:
        "Refund a charge or payment intent. Money movement cannot be recalled, so this is irreversible and always needs approval.",
      effect: "irreversible",
      permission: "stripe:refund:write",
      approval: "always",
      properties: {
        charge: { type: "string" },
        payment_intent: { type: "string" },
        amount: { type: "integer", minimum: 1, description: "Smallest currency unit; default is the full amount" },
        reason: { type: "string", enum: ["duplicate", "fraudulent", "requested_by_customer"] },
      },
      handler: async (args, ctx) => {
        const charge = optMatches(args, "charge", CHARGE, "charge id");
        const intent = optMatches(args, "payment_intent", INTENT, "payment intent id");
        if ((charge === undefined) === (intent === undefined)) {
          throw new Error("provide exactly one of `charge` or `payment_intent`");
        }
        const reason = optStr(args, "reason", { max: 40 });
        if (reason !== undefined && !["duplicate", "fraudulent", "requested_by_customer"].includes(reason)) {
          throw new Error("`reason` must be duplicate, fraudulent or requested_by_customer");
        }
        const data = { charge, payment_intent: intent, amount: optPosInt(args, "amount"), reason };
        const j = asRecord((await api("create_refund", "POST", "/v1/refunds", { data, ctx, args })).json);
        if (typeof j.id !== "string") throw new Error("Stripe response had no refund id");
        return { refund_id: j.id, status: j.status, amount: j.amount, currency: j.currency };
      },
    },
  ]);
}
