#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { serve } from "@hono/node-server";
import { Ledger, JsonlLedgerStore, FileRunStore, Reversi, dataDirPaths, loadRegistry } from "@multimindlab/reversi";
import { Grants, createApp, type ApiKey } from "./app.js";

function need(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`missing ${name}. Required: REVERSI_MANIFESTS (file or dir), REVERSI_KEYS (JSON file of API keys). Optional: REVERSI_DATA (default ./reversi-data), PORT (7421), HOST (127.0.0.1).`);
    process.exit(64);
  }
  return v;
}

const registry = loadRegistry(need("REVERSI_MANIFESTS"));
const keys = JSON.parse(readFileSync(need("REVERSI_KEYS"), "utf8")) as ApiKey[];
const p = dataDirPaths(process.env.REVERSI_DATA ?? "./reversi-data");
const grants = new Grants();
const reversi = new Reversi({
  registry,
  ledger: new Ledger(new JsonlLedgerStore(p.ledgerPath)),
  runs: new FileRunStore(p.runsDir),
  approver: grants.asApprover(),
});
const app = createApp({ reversi, keys, grants });
const port = Number(process.env.PORT ?? 7421);
const hostname = process.env.HOST ?? "127.0.0.1";
serve({ fetch: app.fetch, port, hostname }, (i) => console.log(`reversi-server listening on http://${hostname}:${i.port} (${registry.size} tools)`));
