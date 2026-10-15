/**
 * Signed evidence bundles and an auditor-readable report.
 *
 * A bundle holds ledger records (the whole ledger, or one run), the ledger head at export time and
 * an Ed25519 signature over a canonical summary. Verification recomputes every record hash, checks
 * the chain where records are consecutive, and checks the signature against a public key the
 * verifier already trusts. Without a trusted key the signature only proves self-consistency.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { canonicalize, sha256Hex } from "./canonical.js";
import { verifyRecords, type LedgerRecord } from "./ledger.js";
import type { RunState } from "./store.js";

export interface SigningKey {
  private_pem: string;
  public_pem: string;
}

export function generateSigningKey(): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    private_pem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    public_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function keyId(publicPem: string): string {
  const der = createPublicKey(publicPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}

export interface EvidenceBundle {
  format: "reversi-evidence";
  version: 1;
  created_ms: number;
  /** null for the whole ledger. */
  run_id: string | null;
  /** Hash of the ledger's last record when exported. */
  ledger_head: string;
  record_count: number;
  records: LedgerRecord[];
  records_sha256: string;
  signature: { alg: "ed25519"; key_id: string; public_key_pem: string; value: string };
}

function summary(b: Omit<EvidenceBundle, "signature">): string {
  return canonicalize({
    format: b.format,
    version: b.version,
    created_ms: b.created_ms,
    run_id: b.run_id,
    ledger_head: b.ledger_head,
    record_count: b.record_count,
    records_sha256: b.records_sha256,
  });
}

export function createBundle(opts: {
  records: readonly LedgerRecord[];
  ledger_head: string;
  run_id?: string | null;
  key: SigningKey;
  now?: number;
}): EvidenceBundle {
  const records = [...opts.records];
  const body: Omit<EvidenceBundle, "signature"> = {
    format: "reversi-evidence",
    version: 1,
    created_ms: opts.now ?? Date.now(),
    run_id: opts.run_id ?? null,
    ledger_head: opts.ledger_head,
    record_count: records.length,
    records,
    records_sha256: sha256Hex(canonicalize(records)),
  };
  const value = sign(null, Buffer.from(summary(body)), createPrivateKey(opts.key.private_pem)).toString("base64");
  return { ...body, signature: { alg: "ed25519", key_id: keyId(opts.key.public_pem), public_key_pem: opts.key.public_pem, value } };
}

export type BundleVerification =
  | { ok: true; records: number; chain: "full" | "per-record"; key_id: string; trusted_key: boolean }
  | { ok: false; error: string };

export function verifyBundle(b: EvidenceBundle, opts: { trusted_public_pem?: string } = {}): BundleVerification {
  if (b?.format !== "reversi-evidence" || b.version !== 1 || !Array.isArray(b.records) || !b.signature) {
    return { ok: false, error: "not a Reversi evidence bundle" };
  }
  if (b.record_count !== b.records.length) return { ok: false, error: "record_count does not match the records" };
  if (sha256Hex(canonicalize(b.records)) !== b.records_sha256) return { ok: false, error: "records were modified after signing" };
  const pem = opts.trusted_public_pem ?? b.signature.public_key_pem;
  let good = false;
  try {
    const { signature: _s, ...body } = b;
    good = verify(null, Buffer.from(summary(body)), createPublicKey(pem), Buffer.from(b.signature.value, "base64"));
  } catch {
    good = false;
  }
  if (!good) return { ok: false, error: opts.trusted_public_pem ? "signature does not match the trusted key" : "signature is invalid" };

  // A whole-ledger export must verify as a chain from genesis to the recorded head.
  if (b.run_id === null) {
    const v = verifyRecords(b.records);
    if (!v.ok) return { ok: false, error: `hash chain broken at record ${v.seq}: ${v.error}` };
    if (v.head !== b.ledger_head) {
      return { ok: false, error: "chain head does not match the ledger head in the bundle" };
    }
    return { ok: true, records: b.records.length, chain: "full", key_id: b.signature.key_id, trusted_key: !!opts.trusted_public_pem };
  }
  // A per-run export is a subset, so only each record's own hash and link to its stated prev_hash can be checked.
  for (const r of b.records) {
    const { hash, ...body } = r;
    if (sha256Hex(canonicalize(body)) !== hash) return { ok: false, error: `record ${r.seq} hash does not match its contents` };
  }
  for (let i = 1; i < b.records.length; i++) {
    const prev = b.records[i - 1] as LedgerRecord;
    const cur = b.records[i] as LedgerRecord;
    if (cur.seq === prev.seq + 1 && cur.prev_hash !== prev.hash) return { ok: false, error: `record ${cur.seq} does not link to record ${prev.seq}` };
  }
  return { ok: true, records: b.records.length, chain: "per-record", key_id: b.signature.key_id, trusted_key: !!opts.trusted_public_pem };
}

const esc = (s: unknown) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

/** A self-contained HTML report: what a run did, what stands, and the full event trail. */
export function renderReport(opts: {
  run: RunState;
  records: readonly LedgerRecord[];
  plan?: { fully_reversible: boolean; actions: Array<{ step: number; tool: string; kind: string; note?: string }> };
  ledger_head?: string;
  generated_ms?: number;
}): string {
  const { run, records } = opts;
  const t = (ms: number) => new Date(ms).toISOString();
  const rows = records
    .map(
      (r) =>
        `<tr><td>${r.seq}</td><td>${esc(t(r.ts_ms))}</td><td>${r.step ?? ""}</td><td>${esc(r.event)}</td><td>${esc(r.tool)}</td><td>${esc(r.actor)}</td><td>${esc(r.reason)}</td><td>${esc(r.detail)}</td><td class="h">${esc(r.hash.slice(0, 12))}</td></tr>`,
    )
    .join("\n");
  const steps = run.steps
    .map((s) => `<tr><td>${s.step}</td><td>${esc(s.tool)}</td><td>${esc(s.effect ?? "no manifest")}</td><td>${esc(s.status)}</td><td>${esc(s.error ?? "")}</td></tr>`)
    .join("\n");
  const plan = opts.plan
    ? `<h2>Rollback outlook</h2><p>${opts.plan.fully_reversible ? "Every standing step can be undone, assuming each compensation succeeds." : "<strong>Not fully reversible.</strong> See the items below."}</p><ul>${opts.plan.actions.map((a) => `<li>step ${a.step} <code>${esc(a.tool)}</code>: ${esc(a.kind)}${a.note ? ` &ndash; ${esc(a.note)}` : ""}</li>`).join("")}</ul>`
    : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Reversi report: ${esc(run.run_id)}</title>
<style>body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top}th{background:#f3f3f3}.h{font-family:monospace}code{background:#f3f3f3;padding:0 3px}</style></head><body>
<h1>Run ${esc(run.run_id)}</h1>
<p>Actor <strong>${esc(run.actor)}</strong> &middot; mode <strong>${esc(run.mode)}</strong> &middot; started ${esc(t(run.created_ms))} &middot; scope seal <code>${esc(run.scope.seal.slice(0, 16))}</code></p>
<p>Permissions: ${run.scope.permissions.map((p) => `<code>${esc(p)}</code>`).join(" ")}</p>
<h2>Steps</h2><table><tr><th>#</th><th>Tool</th><th>Effect</th><th>Status</th><th>Error</th></tr>${steps}</table>
${plan}
<h2>Event trail</h2><table><tr><th>seq</th><th>time</th><th>step</th><th>event</th><th>tool</th><th>actor</th><th>reason</th><th>detail</th><th>hash</th></tr>${rows}</table>
<p>Ledger head at generation: <code>${esc(opts.ledger_head ?? "n/a")}</code>. Arguments and results are never stored; each record carries only their hash.</p>
<p>Generated ${esc(t(opts.generated_ms ?? Date.now()))}.</p></body></html>`;
}
