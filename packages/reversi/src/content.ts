/**
 * Content checks on tool-call arguments: credentials, encoded payloads (base64, hex, percent and
 * \u escapes, decoded up to three layers deep), prompt-injection phrasing, and cumulative intent
 * (a run that read sensitive data and is now calling an egress tool).
 *
 * These are heuristics. They raise the cost of obvious abuse and give operators a reason to look;
 * they do not prove a call is safe.
 */
import { globAny } from "./glob.js";
import { detectPii } from "./pii.js";
import { findSecrets } from "./redact.js";

export type CheckAction = "flag" | "require_approval" | "deny";

export interface ContentConfig {
  /** Personal data (emails, phone numbers, card numbers, SSNs, IBANs) in arguments. Off unless set. */
  pii?: CheckAction;
  secrets: CheckAction;
  encoded_payloads: CheckAction;
  injection: CheckAction;
  cumulative: Array<{
    id: string;
    /** Tools whose success marks the run as having touched sensitive data. */
    sources: string[];
    /** Tools that send data out. */
    egress: string[];
    action: CheckAction;
  }>;
  /** Strings longer than this are scanned only up to the limit. */
  max_string_bytes: number;
}

export const DEFAULT_CONTENT: ContentConfig = {
  secrets: "flag",
  encoded_payloads: "require_approval",
  injection: "require_approval",
  cumulative: [],
  max_string_bytes: 100_000,
};

export interface Finding {
  kind: "secret" | "encoded_payload" | "injection" | "cumulative" | "pii";
  action: CheckAction;
  detail: string;
}

const INJECTION: RegExp[] = [
  /ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) (?:instructions|prompts?|rules)/i,
  /disregard (?:all |any )?(?:the )?(?:previous|prior|above|system) (?:instructions|prompts?|rules|message)/i,
  /(?:reveal|print|show|repeat) (?:your |the )?system prompt/i,
  /you are now (?:in )?(?:developer|dan|jailbreak|unrestricted)/i,
  /<\|(?:im_start|im_end|system|endoftext)\|>/i,
  /\bexfiltrate\b/i,
];

const MAX_DEPTH = 3;
const MAX_STRINGS = 5000;
const MAX_DEPTH_NEST = 16;

function printable(s: string): boolean {
  if (s.length < 8) return false;
  let ok = 0;
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c > 160) ok++;
  }
  return ok / s.length > 0.95;
}

/** Candidate decodings of one string. Only results that are printable text are returned. */
function decodings(s: string): Array<{ via: string; text: string }> {
  const out: Array<{ via: string; text: string }> = [];
  for (const m of s.match(/[A-Za-z0-9+/_-]{24,}={0,2}/g) ?? []) {
    try {
      const t = Buffer.from(m.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
      if (printable(t)) out.push({ via: "base64", text: t });
    } catch {
      /* not base64 */
    }
  }
  for (const m of s.match(/(?:[0-9a-fA-F]{2}){12,}/g) ?? []) {
    const t = Buffer.from(m, "hex").toString("utf8");
    if (printable(t)) out.push({ via: "hex", text: t });
  }
  if (/%[0-9a-fA-F]{2}/.test(s)) {
    try {
      const t = decodeURIComponent(s);
      if (t !== s) out.push({ via: "percent-encoding", text: t });
    } catch {
      /* malformed escape */
    }
  }
  if (/\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/.test(s)) {
    const t = s.replace(/\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g, (_m, u: string, x: string) => String.fromCharCode(parseInt(u ?? x, 16)));
    if (t !== s) out.push({ via: "escape sequences", text: t });
  }
  return out;
}

function direct(text: string): Array<{ kind: "secret" | "injection"; what: string }> {
  const hits: Array<{ kind: "secret" | "injection"; what: string }> = [];
  for (const s of findSecrets(text)) hits.push({ kind: "secret", what: s });
  if (INJECTION.some((re) => re.test(text))) hits.push({ kind: "injection", what: "instruction-override phrasing" });
  return hits;
}

/** Returns true if anything was left unscanned (too many strings, too deep). */
function collectStrings(v: unknown, out: string[], depth = 0): boolean {
  if (out.length >= MAX_STRINGS || depth > MAX_DEPTH_NEST) return true;
  let skipped = false;
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) skipped = collectStrings(x, out, depth + 1) || skipped;
  else if (typeof v === "object" && v !== null) {
    for (const [k, x] of Object.entries(v)) {
      out.push(k);
      skipped = collectStrings(x, out, depth + 1) || skipped;
    }
  }
  return skipped;
}

export class ContentChecker {
  readonly config: ContentConfig;
  constructor(config: Partial<ContentConfig> = {}) {
    this.config = { ...DEFAULT_CONTENT, ...config };
  }

  /** Check call arguments (or a result) for credentials, encoded payloads and injection phrasing. */
  inspect(value: unknown): Finding[] {
    const strings: string[] = [];
    const incomplete = collectStrings(value, strings);
    const findings = new Map<string, Finding>();
    const add = (f: Finding) => {
      const key = `${f.kind}:${f.detail}`;
      if (!findings.has(key)) findings.set(key, f);
    };
    // Padding an argument until the scanner gives up must not be a way past it: say so, with the encoded-payload action.
    if (incomplete || strings.some((s) => s.length > this.config.max_string_bytes)) {
      add({ kind: "encoded_payload", action: this.config.encoded_payloads, detail: "arguments too large or deeply nested to inspect fully" });
    }
    for (const raw of strings) {
      const s = raw.length > this.config.max_string_bytes ? raw.slice(0, this.config.max_string_bytes) : raw;
      for (const h of direct(s)) {
        add({ kind: h.kind, action: this.config[h.kind === "secret" ? "secrets" : "injection"], detail: h.what });
      }
      if (this.config.pii) {
        const kinds = detectPii(s);
        if (kinds.length) add({ kind: "pii", action: this.config.pii, detail: `personal data (${kinds.join(", ")})` });
      }
      let layer = [{ via: "", text: s }];
      for (let depth = 1; depth <= MAX_DEPTH; depth++) {
        const next: Array<{ via: string; text: string }> = [];
        for (const l of layer) {
          for (const d of decodings(l.text)) {
            const via = l.via ? `${l.via} > ${d.via}` : d.via;
            next.push({ via, text: d.text });
            for (const h of direct(d.text)) {
              add({
                kind: "encoded_payload",
                action: this.config.encoded_payloads,
                detail: `${h.kind === "secret" ? `credential (${h.what})` : h.what} hidden in ${via}`,
              });
            }
          }
        }
        if (next.length === 0 || next.length > 50) break;
        layer = next;
      }
    }
    return [...findings.values()];
  }

  /** Cumulative-intent rules, given the tools that already succeeded in this run. */
  cumulative(tool: string, succeededTools: readonly string[]): Finding[] {
    const out: Finding[] = [];
    for (const c of this.config.cumulative) {
      if (!globAny(c.egress, tool)) continue;
      const source = succeededTools.find((t) => globAny(c.sources, t));
      if (source) {
        out.push({ kind: "cumulative", action: c.action, detail: `\`${c.id}\`: \`${tool}\` sends data out after this run read \`${source}\`` });
      }
    }
    return out;
  }
}
