import type { CompensationCall } from "@multimindlab/reversi";
import type { Connector } from "./common.js";

/** A Reversi compensator that runs the compensation tool in the matching connector. */
export function compensatorFor(connectors: Connector[]): (call: CompensationCall) => Promise<void> {
  const handlers = new Map<string, Connector["tools"][string]>();
  for (const c of connectors) for (const [name, h] of Object.entries(c.tools)) handlers.set(name, h);
  return async (call) => {
    const handler = handlers.get(call.tool);
    if (!handler) throw new Error(`no connector provides compensation tool \`${call.tool}\``);
    await handler(call.args, { idempotency_key: call.idempotency_key });
  };
}
