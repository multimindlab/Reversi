/**
 * Detection and masking of personal data in free text. Patterns are deliberately conservative (a number has to pass its
 * checksum to count as a card or IBAN) so that masking and flagging stay trustworthy.
 */

export type PiiKind = "email" | "phone" | "credit_card" | "ssn" | "iban";

const EMAIL = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b/g;
const PHONE = /(?<![\w.]|\d[\s.-])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{2,4}[\s.-])\d{3,4}[\s.-]?\d{3,4}(?![\w.]|[\s.-]\d)/g;
const CARD = /\b(?:\d[ -]?){12,18}\d\b/g;
const SSN = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
const IBAN = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g;

function luhn(digits: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function ibanOk(raw: string): boolean {
  const s = raw.replace(/ /g, "");
  if (s.length < 15 || s.length > 34) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const v = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of v) rem = (rem * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

interface Hit {
  kind: PiiKind;
  start: number;
  end: number;
}

function scan(text: string): Hit[] {
  const hits: Hit[] = [];
  const run = (re: RegExp, kind: PiiKind, ok: (m: string) => boolean = () => true) => {
    re.lastIndex = 0;
    for (let m = re.exec(text); m; m = re.exec(text)) if (ok(m[0])) hits.push({ kind, start: m.index, end: m.index + m[0].length });
  };
  run(EMAIL, "email");
  run(CARD, "credit_card", (m) => {
    const d = m.replace(/[ -]/g, "");
    return d.length >= 13 && d.length <= 19 && luhn(d);
  });
  run(IBAN, "iban", ibanOk);
  run(SSN, "ssn");
  run(PHONE, "phone", (m) => m.replace(/\D/g, "").length >= 9 && m.replace(/\D/g, "").length <= 15 && !hits.some((h) => h.start <= text.indexOf(m) && h.end >= text.indexOf(m) + m.length));
  // A span claimed by a stronger kind (a card number also looks like a phone number) is not counted twice.
  return hits.filter((h, i) => !hits.some((o, j) => j !== i && o.start <= h.start && o.end >= h.end && (o.end - o.start > h.end - h.start || (o.end - o.start === h.end - h.start && j < i))));
}

/** Which kinds of personal data appear in the text. */
export function detectPii(text: string): PiiKind[] {
  return [...new Set(scan(text).map((h) => h.kind))];
}

/** Replace personal data with `[PII:kind]`. */
export function maskPii(text: string): string {
  const hits = scan(text).sort((a, b) => b.start - a.start);
  let out = text;
  for (const h of hits) out = out.slice(0, h.start) + `[PII:${h.kind}]` + out.slice(h.end);
  return out;
}
