// A tiny "agent" placing an order through Reversi, then getting rolled back.
// Run from the repo root:  npm run example
import { mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SealedScope, loadRegistry, openLocal } from "../../packages/reversi/dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "out");
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// Fake downstream systems. In real use these are your actual tools (MCP servers, REST calls, ...).
const shop = {
  orders: new Map(),
  charges: new Map(),
  create_order: ({ sku }) => {
    const order_id = `ord_${shop.orders.size + 1}`;
    shop.orders.set(order_id, { sku, status: "open" });
    return { order_id };
  },
  cancel_order: ({ order_id }) => void (shop.orders.get(order_id).status = "cancelled"),
  charge_card: ({ amount }) => {
    const charge_id = `ch_${shop.charges.size + 1}`;
    shop.charges.set(charge_id, { amount, status: "captured" });
    return { charge_id };
  },
  refund: ({ charge_id }) => void (shop.charges.get(charge_id).status = "refunded"),
};

// The operator approves the irreversible email in this demo. Rollback and approval are operator decisions, never the agent's.
const reversi = openLocal(out, loadRegistry(join(here, "manifests")), (req) => req.tool === "send_confirmation_email");

// The agent's scope: it may take orders and payments and send mail. It may NOT administer customers.
const run = reversi.startRun({
  run_id: "demo-order-1",
  actor: "order-agent",
  scope: SealedScope.seal(["customers:read", "orders:write", "payments:write", "mail:send"]),
  reason: "customer chat session #4821",
});

const say = (s) => console.log(s);
say("== agent run ==");
await run.call({ tool: "lookup_customer", args: { id: "c_77" }, reason: "identify the customer", execute: () => ({ name: "Ada" }) });
const order = await run.call({ tool: "create_order", args: { sku: "BOOK-1" }, reason: "customer asked to order BOOK-1", execute: shop.create_order });
say(`created ${order.result.order_id}`);
const charge = await run.call({ tool: "charge_card", args: { amount: 25 }, reason: "pay for the order", execute: shop.charge_card });
say(`charged ${charge.result.charge_id}`);
await run.call({ tool: "send_confirmation_email", args: { to: "ada@example.com" }, reason: "send the receipt", execute: () => "sent" });
say("sent confirmation email (irreversible)");

const attempt = await run.call({ tool: "delete_customer", args: { id: "c_77" }, reason: "agent got creative", execute: () => { throw new Error("must never run"); } });
say(`delete_customer -> ${attempt.status}: ${attempt.reasons?.join("; ")}`);

say("\n== operator reviews the plan ==");
const plan = run.plan();
for (const a of plan.actions) say(`  step ${a.step} ${a.tool}: ${a.kind}${a.compensation_tool ? " via " + a.compensation_tool : ""}${a.note ? " (" + a.note + ")" : ""}`);

say("\n== operator rolls the run back ==");
const report = await run.rollback({
  actor: "operator-darsh",
  compensate: (c) => shop[c.tool](c.args),
});
say(`compensated steps: ${report.compensated.join(", ")}`);
say(`cannot be undone:  ${report.unrecoverable.join(", ")}  <- Reversi will not pretend otherwise`);
say(`complete: ${report.complete}`);
say(`order: ${shop.orders.get("ord_1").status}, charge: ${shop.charges.get("ch_1").status}`);

const v = reversi.ledger.verify();
say(`\nledger: ${v.records} records, chain ${v.ok ? "intact" : "BROKEN"}`);
say(`written to ${join("examples", "order-agent", "out", "ledger.jsonl")}  (open viewer/index.html to explore it)`);
