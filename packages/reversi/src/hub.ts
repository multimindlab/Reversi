/** Turns ledger records and approval events into notifications. */
import type { Approvals, ApprovalRecord } from "./approvals.js";
import type { Reversi } from "./engine.js";
import type { LedgerRecord } from "./ledger.js";
import { approvalMessage } from "./notify.js";
import type { Notifier, NotifyMessage } from "./channels.js";

const link = (base: string | undefined, path: string) => (base ? `${base.replace(/\/$/, "")}${path}` : undefined);

/** What a ledger record means to a human, or null if it is routine. */
export function describeRecord(r: LedgerRecord, rv: Reversi, consoleUrl?: string): NotifyMessage | null {
  const run = link(consoleUrl, `/console/runs/${encodeURIComponent(r.run_id)}`);
  const data = { run_id: r.run_id, step: r.step, tool: r.tool, actor: r.actor, seq: r.seq };
  switch (r.event) {
    case "compensation_failed":
      return { event: "rollback_failed", severity: "critical", title: `Rollback failed: ${r.tool} in ${r.run_id}`, text: `Undoing step ${r.step} failed: ${r.detail || "no detail"}. The run is not fully rolled back.`, dedup_key: `comp:${r.run_id}:${r.step}`, link: run, data };
    case "verification_failed":
      return { event: "verification_failed", severity: "critical", title: `Undo not verified: ${r.tool} in ${r.run_id}`, text: r.detail, dedup_key: `verify:${r.run_id}:${r.step}`, link: run, data };
    case "unverified":
      return { event: "rollback_unverified", severity: "warning", title: `Undo ran but could not be verified: ${r.run_id}`, text: r.detail, link: run, data };
    case "escalated":
      return { event: "approval_escalated", severity: "warning", title: `Approval escalated: ${r.tool}`, text: `${r.reason}. ${r.detail}`, link: link(consoleUrl, "/console/approvals"), data };
    case "succeeded": {
      const effect = rv.registry.get(r.tool)?.effect;
      if (effect === "irreversible") return { event: "irreversible_executed", severity: "warning", title: `Irreversible action executed: ${r.tool}`, text: `${r.actor} ran an irreversible tool in run ${r.run_id}. It cannot be undone.`, link: run, data };
      return null;
    }
    case "approved":
      if (r.detail.startsWith("BREAK-GLASS")) return { event: "break_glass", severity: "critical", title: `Break-glass approval for ${r.tool}`, text: `${r.actor}: ${r.reason}. ${r.detail}`, link: link(consoleUrl, "/console/approvals"), data };
      return null;
    case "blocked":
    case "would_block":
      if (/no manifest registered/.test(r.detail) && rv.registry.get(r.tool) === undefined) return { event: "unclassified_mutation", severity: "warning", title: `Call to an unclassified tool: ${r.tool}`, text: `${r.actor} called ${r.tool}, which has no manifest (${r.event === "blocked" ? "blocked" : "allowed in a non-enforcing mode"}).`, dedup_key: `unclassified:${r.tool}`, link: run, data };
      return null;
    case "purged":
      return { event: "retention_purged", severity: "info", title: `Run data purged: ${r.run_id}`, text: r.detail, data };
    default:
      return null;
  }
}

export function approvalNotification(rec: ApprovalRecord, kind: "requested" | "decided" | "escalated" | "progress", consoleUrl?: string): NotifyMessage {
  const m = approvalMessage(rec, consoleUrl);
  const approval = { id: rec.id, run_id: rec.run_id, tool: rec.tool };
  const data = { approval_id: rec.id, run_id: rec.run_id, tool: rec.tool, status: rec.status, quorum: rec.quorum ?? 1, arg_keys: rec.arg_keys };
  if (kind === "requested") return { event: "approval_requested", severity: "warning", title: `Approval needed: ${rec.tool}`, text: m.text, dedup_key: `approval:${rec.id}`, link: link(consoleUrl, "/console/approvals"), data, approval };
  if (kind === "escalated") return { event: "approval_escalated", severity: "warning", title: `Approval escalated: ${rec.tool}`, text: `${m.text} Nobody answered in time, so it now needs ${(rec.required_roles ?? []).join(" or ") || "an approver"}.`, dedup_key: `approval:${rec.id}`, link: link(consoleUrl, "/console/approvals"), data, approval };
  if (kind === "progress") return { event: "approval_progress", severity: "info", title: `Approval progress: ${rec.tool}`, text: `${(rec.decisions ?? []).filter((d) => d.decision === "approve").length} of ${rec.quorum ?? 1} approvals so far.`, data };
  return { event: "approval_decided", severity: "info", title: `Approval ${rec.status}: ${rec.tool}`, text: `${rec.decided_by ?? "someone"} ${rec.status === "approved" ? "approved" : "denied"} the request${rec.decision_note ? `: ${rec.decision_note}` : ""}.`, resolve: true, dedup_key: `approval:${rec.id}`, link: link(consoleUrl, "/console/approvals"), data };
}

/**
 * Wire an engine and its approvals to a notifier. Ledger-derived events are sent as they are journaled by this process;
 * approval events come from the approvals object (so create it with {@link Approvals} options that call these).
 */
export function attachNotifications(o: { reversi: Reversi; notifier: Notifier; console_url?: string }): () => void {
  return o.reversi.ledger.onAppend((r) => {
    const m = describeRecord(r, o.reversi, o.console_url);
    if (m) o.notifier.notifyLater(m);
  });
}
