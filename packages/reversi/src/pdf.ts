/**
 * A small, dependency-free PDF writer for the auditor report: monospaced text on A4 pages. It writes a valid PDF 1.4
 * file (cross-reference table included) that any viewer opens, and that text extractors can read.
 */
import type { LedgerRecord } from "./ledger.js";
import type { RunState } from "./store.js";

const PAGE_W = 595;
const PAGE_H = 842;
const MARGIN = 40;
const SIZE = 9;
const LEAD = 12;
const CHAR_W = 0.6 * SIZE; // Courier is monospaced at 600/1000 em
const COLS = Math.floor((PAGE_W - 2 * MARGIN) / CHAR_W);
const ROWS = Math.floor((PAGE_H - 2 * MARGIN) / LEAD);

/** Latin-1 safe text for a PDF string literal. */
function pdfText(s: string): string {
  return s
    .replace(/[^\x20-\x7e\xa0-\xff]/g, "?")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function wrap(line: string): string[] {
  if (line.length <= COLS) return [line];
  const out: string[] = [];
  let rest = line;
  while (rest.length > COLS) {
    let cut = rest.lastIndexOf(" ", COLS);
    if (cut < COLS / 2) cut = COLS;
    out.push(rest.slice(0, cut));
    rest = "  " + rest.slice(cut).trimStart();
  }
  out.push(rest);
  return out;
}

/** Lay lines out on pages. A line starting with `#` is a heading (bold). */
export function renderPdf(lines: string[], title: string): Buffer {
  const rows = lines.flatMap((l) => (l.startsWith("# ") ? [l] : wrap(l)));
  const pages: string[][] = [];
  for (let i = 0; i < rows.length; i += ROWS) pages.push(rows.slice(i, i + ROWS));
  if (pages.length === 0) pages.push([""]);

  const objs: string[] = [];
  const add = (s: string) => objs.push(s);
  // 1 catalog, 2 pages, 3 font, 4 bold font, then per page: content, page
  add("<< /Type /Catalog /Pages 2 0 R >>");
  const kids = pages.map((_, i) => `${7 + i * 2} 0 R`).join(" ");
  add(`<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>`);
  add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>");
  add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>");
  add(`<< /Title (${pdfText(title)}) /Producer (Reversi) >>`); // 5 info
  pages.forEach((rowsOnPage, i) => {
    let y = PAGE_H - MARGIN - SIZE;
    const ops: string[] = [];
    for (const r of rowsOnPage) {
      const heading = r.startsWith("# ");
      ops.push(`BT /${heading ? "F2" : "F1"} ${heading ? SIZE + 3 : SIZE} Tf ${MARGIN} ${y} Td (${pdfText(heading ? r.slice(2) : r)}) Tj ET`);
      y -= LEAD;
    }
    const stream = ops.join("\n");
    add(`<< /Length ${Buffer.byteLength(stream, "latin1")} >>\nstream\n${stream}\nendstream`);
    add(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Contents ${5 + i * 2 + 1} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>`);
  });

  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objs.forEach((body, i) => {
    offsets.push(Buffer.byteLength(out, "latin1"));
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = Buffer.byteLength(out, "latin1");
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) out += `${String(o).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R /Info 5 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}

const t = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 19) + "Z";

/** The auditor report as a PDF: the same facts as the HTML report. */
export function renderReportPdf(o: {
  run: RunState;
  records: readonly LedgerRecord[];
  plan?: { fully_reversible: boolean; actions: Array<{ step: number; tool: string; kind: string; note?: string; residue?: string[] }> };
  ledger_head?: string;
  region?: string;
  generated_ms?: number;
}): Buffer {
  const { run, records } = o;
  const L: string[] = [];
  L.push(`# Reversi report: run ${run.run_id}`, "");
  L.push(`Actor: ${run.actor}   Mode: ${run.mode}   Tenant: ${run.tenant ?? "-"}`);
  L.push(`Started: ${t(run.created_ms)}   Scope seal: ${run.scope.seal.slice(0, 16)}`);
  L.push(`Permissions: ${run.scope.permissions.join(" ")}`);
  if (o.region) L.push(`Data region: ${o.region}`);
  L.push("", "# Steps");
  for (const s of run.steps) L.push(`${String(s.step).padStart(3)}  ${s.tool}  [${s.effect ?? "no manifest"}]  ${s.status}${s.error ? `  error: ${s.error}` : ""}`);
  if (!run.steps.length) L.push("(no steps)");
  if (o.plan) {
    L.push("", "# Rollback outlook", o.plan.fully_reversible ? "Every standing step can be undone, assuming each compensation succeeds." : "NOT fully reversible. See below.");
    for (const a of o.plan.actions) L.push(`step ${a.step} ${a.tool}: ${a.kind}${a.note ? ` - ${a.note}` : ""}${a.residue?.length ? ` (residue: ${a.residue.join("; ")})` : ""}`);
  }
  L.push("", "# Event trail");
  for (const r of records) L.push(`${String(r.seq).padStart(5)} ${t(r.ts_ms)} ${r.event.padEnd(19)} ${r.tool} by ${r.actor}${r.step !== null ? ` step ${r.step}` : ""}`, `        why: ${r.reason}${r.detail ? `   detail: ${r.detail}` : ""}   hash ${r.hash.slice(0, 12)}`);
  L.push("", `Ledger head at generation: ${o.ledger_head ?? "n/a"}`, "Arguments and results are never stored; each record carries only their hash.", `Generated ${t(o.generated_ms ?? Date.now())}.`);
  return renderPdf(L, `Reversi report ${run.run_id}`);
}
