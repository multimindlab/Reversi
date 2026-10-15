#!/usr/bin/env node
// Prints every POST it receives. Use it as REVERSI_APPROVAL_WEBHOOK to see approval notifications:
//   node examples/webhook-sink.mjs            # http://127.0.0.1:9100
import { createServer } from "node:http";
const PORT = Number(process.env.PORT ?? 9100);
createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    try {
      console.log(`\n[${new Date().toISOString()}] ${req.method} ${req.url}\n${JSON.stringify(JSON.parse(body), null, 2).slice(0, 1500)}`);
    } catch {
      console.log(`\n[${new Date().toISOString()}] ${req.method} ${req.url}\n${body.slice(0, 500)}`);
    }
    res.writeHead(200).end("ok");
  });
}).listen(PORT, "127.0.0.1", () => console.error(`webhook sink on http://127.0.0.1:${PORT}`));
