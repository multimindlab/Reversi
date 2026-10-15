/**
 * Approval notifications: POST a JSON message to a webhook when a request is queued. The body has a
 * Slack/Teams-compatible `text` field plus the structured request, so an incoming-webhook URL works
 * as is. Delivery is best effort with a short timeout and never affects the decision.
 */
import type { ApprovalRecord } from "./approvals.js";

export interface WebhookOptions {
  url: string;
  /** Public console URL, to link the request in the message. */
  console_url?: string;
  fetch?: typeof fetch;
  timeout_ms?: number;
  /** Called when delivery fails (default: stderr). */
  on_error?: (e: Error) => void;
}

export function approvalMessage(rec: ApprovalRecord, console_url?: string): { text: string; approval: ApprovalRecord } {
  const where = console_url ? ` Decide: ${console_url.replace(/\/$/, "")}/console/approvals` : "";
  const args = rec.arg_keys.length ? ` (arguments: ${rec.arg_keys.join(", ")})` : "";
  return {
    text: `Reversi approval needed: ${rec.kind} \`${rec.tool}\` in run ${rec.run_id}${args}. Why: ${rec.triggers.join("; ") || "approval required"}.${where}`,
    approval: rec,
  };
}

export function webhookNotifier(o: WebhookOptions): (rec: ApprovalRecord) => void {
  const f = o.fetch ?? fetch;
  const url = new URL(o.url);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("approval webhook must be http(s)");
  return (rec) => {
    void (async () => {
      try {
        const res = await f(o.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(approvalMessage(rec, o.console_url)),
          signal: AbortSignal.timeout(o.timeout_ms ?? 5000),
        });
        if (!res.ok) throw new Error(`webhook answered ${res.status}`);
      } catch (e) {
        (o.on_error ?? ((err) => console.error(`approval webhook failed: ${err.message}`)))(e instanceof Error ? e : new Error(String(e)));
      }
    })();
  };
}
