// Generates the cross-language conformance fixtures from the TypeScript implementation.
// `node scripts/gen-fixtures.mjs`          writes conformance/*.json
// `node scripts/gen-fixtures.mjs --check`  fails if the committed files differ (drift guard)
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ledger, Registry, Reversi, SealedScope, hashPayload, toJsonl, validateManifest } from "../packages/reversi/dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "conformance");
const comp = (tool, extra = {}) => ({ tool, argument_map: {}, ...extra });

const manifestInputs = [
  { tool: "read_order", effect: "read_only", permission: "orders:read" },
  { tool: "put_flag", effect: "idempotent", permission: "flags:write" },
  { tool: "charge_card", effect: "compensable", permission: "pay:write", compensation: comp("refund", { argument_map: { charge_id: "$result.charge_id", amt: "$args.amount" } }) },
  { tool: "create_draft", effect: "reversible", permission: "docs:write", compensation: comp("delete_draft") },
  { tool: "send_email", effect: "irreversible", permission: "mail:send" },
  { tool: "send_email", effect: "irreversible", permission: "mail:send", approval: "always" },
  { tool: "b", effect: "read_only", permission: "p", requires: ["a"] },
  { tool: "x", effect: "compensable", permission: "p" },
  { tool: "x", effect: "reversible", permission: "p" },
  { tool: "x", effect: "read_only", permission: "p", compensation: comp("y") },
  { tool: "x", effect: "irreversible", permission: "p", approval: "never" },
  { tool: "x", effect: "magic", permission: "p" },
  { tool: "x", effect: "read_only" },
  { tool: "", effect: "read_only", permission: "p" },
  { tool: "x", effect: "read_only", permission: "a b" },
  { tool: "x", effect: "read_only", permission: "p", colour: "red" },
  { tool: "x", effect: "compensable", permission: "p", compensation: comp("y", { argument_map: { a: "args.id" } }) },
  { tool: "x", effect: "compensable", permission: "p", compensation: comp("y", { argument_map: { a: "$args" } }) },
  { tool: "x", effect: "read_only", permission: "p", requires: ["a", "a"] },
  { tool: "x", effect: "read_only", permission: "p", approval: "sometimes" },
  { tool: "a", effect: "reversible", permission: "p", compensation: comp("a") },
  { tool: "a", effect: "read_only", permission: "p", requires: ["a"] },
  { tool: "charge", effect: "compensable", permission: "pay:write", compensation: { tool: "refund" } },
  { tool: "x", effect: "read_only", permission: "p", description: 5 },
  [],
  "tool",
  null,
];
const manifestCases = manifestInputs.map((input) => {
  const r = validateManifest(input);
  return r.ok ? { input, valid: true, normalized: r.manifest } : { input, valid: false };
});

const hashInputs = [
  null, true, false, 0, -1, 42, 1.5, 0.1, 100, "", "abc", "héllo ✓ 😀", 'quote " back \\ nl \n tab \t ctl \u0001',
  [], {}, [1, "a", null], { b: 1, a: { d: [3, { z: 1, y: 2 }], c: "x" } }, { "ключ": 1, "a": 2 }, { "😀": 1, "￿": 2 },
];
const hashVectors = hashInputs.map((value) => ({ value, hash: hashPayload(value) }));

// A ledger written by the engine with a fixed clock.
let t = 1_700_000_000_000;
const registry = Registry.from([
  { tool: "create_order", effect: "reversible", permission: "orders:write", compensation: { tool: "cancel_order", argument_map: { id: "$result.id" } } },
  { tool: "cancel_order", effect: "idempotent", permission: "orders:write" },
  { tool: "send_email", effect: "irreversible", permission: "mail:send" },
]);
const ledger = new Ledger();
const rv = new Reversi({ registry, ledger, now: () => t++, approver: () => true });
const run = rv.startRun({ run_id: "golden-1", actor: "agent-é", scope: SealedScope.seal(["orders:write", "mail:send"]), reason: "démarrage ✓" });
await run.call({ tool: "create_order", args: { sku: "A1" }, reason: "customer asked", execute: () => ({ id: 7 }) });
await run.call({ tool: "send_email", args: { to: "x@example.com" }, reason: "confirmation", execute: () => "sent" });
await run.call({ tool: "unknown_tool", reason: "should be blocked", execute: () => 1 });
await run.rollback({ compensate: () => {} });
const ledgerJsonl = toJsonl(ledger.records());

const files = {
  "manifest-cases.json": JSON.stringify(manifestCases, null, 2) + "\n",
  "hash-vectors.json": JSON.stringify(hashVectors, null, 2) + "\n",
  "ledger.jsonl": ledgerJsonl,
};

const check = process.argv.includes("--check");
let drift = false;
for (const [name, text] of Object.entries(files)) {
  const p = join(root, name);
  if (check) {
    if (!existsSync(p) || readFileSync(p, "utf8") !== text) {
      console.error(`drift: conformance/${name} differs from the TypeScript implementation`);
      drift = true;
    }
  } else writeFileSync(p, text);
}
if (check && drift) process.exit(1);
if (!check) console.log(`wrote ${Object.keys(files).length} fixtures to conformance/`);
