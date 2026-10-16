/**
 * External anchoring: periodically publish the ledger head somewhere the operator cannot quietly rewrite (an append-only
 * file on other storage, a webhook into a system you do not control), optionally signed. Later, `verifyAnchor` proves the
 * ledger still contains the anchored head, so truncation or a rewrite of history is caught.
 */
import { createHmac, createPublicKey, sign, verify } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { canonicalize } from "./canonical.js";
import { guardedFetch, type EgressConfig } from "./egress.js";
import { keyId, type SigningKey } from "./evidence.js";
import type { Ledger } from "./ledger.js";

export type AnchorSink = { type: "file"; path: string } | { type: "webhook"; url: string; secret?: string };

export interface AnchorRecord {
  format: "reversi-anchor";
  version: 1;
  ts_ms: number;
  /** Hash of the last record when anchored. */
  head: string;
  /** How many records the ledger had. */
  records: number;
  region?: string;
  key_id?: string;
  signature?: string;
}

const body = (a: AnchorRecord) => canonicalize({ format: a.format, version: a.version, ts_ms: a.ts_ms, head: a.head, records: a.records, region: a.region ?? null });

export async function anchorLedger(
  ledger: Ledger,
  sinks: AnchorSink[],
  o: { key?: SigningKey; egress?: EgressConfig; fetch?: typeof fetch; now?: number } = {},
): Promise<{ anchor: AnchorRecord; delivered: string[]; errors: string[] }> {
  const records = ledger.records().length;
  const anchor: AnchorRecord = { format: "reversi-anchor", version: 1, ts_ms: o.now ?? Date.now(), head: ledger.head(), records, ...(o.egress?.region ? { region: o.egress.region } : {}) };
  if (o.key) {
    anchor.key_id = keyId(o.key.public_pem);
    anchor.signature = sign(null, Buffer.from(body(anchor)), (await import("node:crypto")).createPrivateKey(o.key.private_pem)).toString("base64");
  }
  const delivered: string[] = [];
  const errors: string[] = [];
  const f = guardedFetch(o.egress, o.fetch);
  for (const s of sinks) {
    try {
      if (s.type === "file") {
        appendFileSync(s.path, JSON.stringify(anchor) + "\n");
        delivered.push(`file:${s.path}`);
      } else {
        const text = JSON.stringify(anchor);
        const headers: Record<string, string> = { "content-type": "application/json" };
        if (s.secret) headers["x-reversi-signature"] = `sha256=${createHmac("sha256", s.secret).update(text).digest("hex")}`;
        const res = await f(s.url, { method: "POST", headers, body: text, signal: AbortSignal.timeout(10_000) });
        if (!res.ok) throw new Error(`answered ${res.status}`);
        delivered.push(`webhook:${new URL(s.url).host}`);
      }
    } catch (e) {
      errors.push(`${s.type === "file" ? s.path : s.url}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { anchor, delivered, errors };
}

export function readAnchors(path: string): AnchorRecord[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l) as AnchorRecord);
}

export type AnchorCheck = { ok: true; records: number; signed: boolean } | { ok: false; error: string };

/** Does the ledger still contain this anchor's head at the position it claims? */
export function verifyAnchor(ledger: Ledger, a: AnchorRecord, trusted_public_pem?: string): AnchorCheck {
  if (a?.format !== "reversi-anchor") return { ok: false, error: "not a Reversi anchor" };
  const v = ledger.verify();
  if (!v.ok) return { ok: false, error: `the ledger itself is broken at record ${v.seq}: ${v.error}` };
  let signed = false;
  if (a.signature) {
    if (!trusted_public_pem) {
      signed = false; // present but nothing to check it against
    } else {
      try {
        signed = verify(null, Buffer.from(body(a)), createPublicKey(trusted_public_pem), Buffer.from(a.signature, "base64"));
      } catch {
        signed = false;
      }
      if (!signed) return { ok: false, error: "the anchor's signature does not match the trusted key" };
    }
  } else if (trusted_public_pem) return { ok: false, error: "the anchor is unsigned but a trusted key was required" };
  const recs = ledger.records();
  if (a.records > recs.length) return { ok: false, error: `the ledger has ${recs.length} records but was anchored at ${a.records}: it has been truncated` };
  const at = recs[a.records - 1];
  if (a.records === 0 ? false : at?.hash !== a.head) return { ok: false, error: `record ${a.records - 1} no longer has the anchored hash: history was rewritten` };
  return { ok: true, records: a.records, signed };
}
