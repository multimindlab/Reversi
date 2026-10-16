import { canonicalize, sha256Hex } from "@multimindlab/reversi";
import type { Connector } from "./common.js";

/**
 * The connector certification suite: the twelve checks every connector must pass (or declare not applicable with a
 * reason). The checks are run against fake backends by `test/certification.ts`; this module holds the shared
 * vocabulary and the manifest drift detector that the gateway and CLI can use at runtime.
 */

export const CHECK_IDS = [
  "forward_success",
  "forward_failure",
  "duplicate_call",
  "retry",
  "compensation_success",
  "compensation_failure",
  "verification_failure",
  "permission_denial",
  "timeout",
  "redaction",
  "dependency_block",
  "manifest_drift",
] as const;
export type CheckId = (typeof CHECK_IDS)[number];

export type CheckStatus = "pass" | "fail" | "not_applicable";

export interface CheckResult {
  check: CheckId;
  status: CheckStatus;
  /** Required for `not_applicable`; for `fail`, what went wrong. */
  reason?: string;
  /** Tools the check ran against. */
  tools: string[];
}

export interface Certification {
  connector: string;
  results: CheckResult[];
}

export const CHECKS: Array<{ id: CheckId; title: string; verifies: string }> = [
  { id: "forward_success", title: "Forward success", verifies: "every tool does its job against the fake backend, and read-only tools change nothing" },
  { id: "forward_failure", title: "Forward failure", verifies: "a rejected call surfaces as an error naming the status, changes nothing, and does not contain the credential" },
  { id: "duplicate_call", title: "Duplicate call", verifies: "the same call with the same idempotency key a second time has no further effect" },
  { id: "retry", title: "Retry", verifies: "a transport failure or 5xx on a write is reported as uncertain (EffectUncertainError) or an HTTP error, and running the call again succeeds" },
  { id: "compensation_success", title: "Compensation success", verifies: "a real engine rolls the step back and the fake backend is back in its prior state" },
  { id: "compensation_failure", title: "Compensation failure", verifies: "a backend error during the undo leaves the step compensation_failed and the rollback incomplete; a retry then completes" },
  { id: "verification_failure", title: "Verification failure", verifies: "a failing verify callback makes the rollback report the step as failed, never compensated" },
  { id: "permission_denial", title: "Permission denial", verifies: "a 401 or 403 surfaces as an error naming the status, without the credential" },
  { id: "timeout", title: "Timeout", verifies: "a backend that never answers ends in EffectUncertainError for writes and a plain error for reads" },
  { id: "redaction", title: "Redaction", verifies: "the credential appears in no error message, no returned JSON and no request URL or body" },
  { id: "dependency_block", title: "Dependency block", verifies: "with a `requires` edge, rolling back while the later step stands defers the earlier one" },
  { id: "manifest_drift", title: "Manifest drift", verifies: "a changed, added or removed tool input schema is detected against the stored hashes" },
];

/** Hash of every tool's input schema, keyed by tool name. Store this as the baseline. */
export function connectorSchemaHashes(connector: Pick<Connector, "inputSchemas">): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [tool, schema] of Object.entries(connector.inputSchemas)) out[tool] = sha256Hex(canonicalize(schema));
  return out;
}

export interface ManifestDrift {
  added: string[];
  removed: string[];
  changed: string[];
}

/**
 * Compare the current tools with a stored `schema_hash` map (tool name to hash, as made by
 * {@link connectorSchemaHashes}). Without an explicit map, a `schema_hash` field on each manifest object is used;
 * with neither, every tool counts as added.
 */
export function detectManifestDrift(
  manifests: unknown[],
  inputSchemas: Record<string, object>,
  stored?: Record<string, string>,
): ManifestDrift {
  const names = new Set<string>(Object.keys(inputSchemas));
  const fromManifests: Record<string, string> = {};
  for (const m of manifests) {
    if (typeof m !== "object" || m === null) continue;
    const r = m as { tool?: unknown; schema_hash?: unknown };
    if (typeof r.tool !== "string") continue;
    names.add(r.tool);
    if (typeof r.schema_hash === "string") fromManifests[r.tool] = r.schema_hash;
  }
  const baseline = stored ?? fromManifests;
  const current = connectorSchemaHashes({ inputSchemas });
  const drift: ManifestDrift = { added: [], removed: [], changed: [] };
  for (const tool of [...names].sort()) {
    const have = current[tool];
    const want = baseline[tool];
    if (want === undefined) drift.added.push(tool);
    else if (have === undefined || have !== want) drift.changed.push(tool);
  }
  for (const tool of Object.keys(baseline).sort()) if (!names.has(tool)) drift.removed.push(tool);
  return drift;
}

export function certificationFailures(c: Certification): string[] {
  return c.results.filter((r) => r.status === "fail").map((r) => `${c.connector}: ${r.check}: ${r.reason ?? "failed"}`);
}

/** A markdown table of connectors by checks: `pass` or `n/a`. Fails render as `FAIL`. */
export function renderCertificationMatrix(certs: Certification[]): string {
  const head = ["Connector", ...CHECKS.map((c) => c.title)];
  const rows = certs.map((c) => [
    c.connector,
    ...CHECK_IDS.map((id) => {
      const r = c.results.find((x) => x.check === id);
      return !r ? "missing" : r.status === "pass" ? "pass" : r.status === "fail" ? "FAIL" : "n/a";
    }),
  ]);
  const line = (cells: string[]) => `| ${cells.join(" | ")} |`;
  return [line(head), line(head.map(() => "---")), ...rows.map(line)].join("\n");
}
