/** A small line diff (longest common subsequence) for comparing manifest and policy versions. */

export interface DiffLine {
  op: " " | "+" | "-";
  text: string;
}

export function diffLines(a: string, b: string): DiffLine[] {
  const x = a.split("\n");
  const y = b.split("\n");
  const n = x.length;
  const m = y.length;
  // lcs[i][j] = length of the longest common subsequence of x[i..] and y[j..]
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) lcs[i]![j] = x[i] === y[j] ? (lcs[i + 1]![j + 1] as number) + 1 : Math.max(lcs[i + 1]![j] as number, lcs[i]![j + 1] as number);
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ op: " ", text: x[i] as string });
      i++;
      j++;
    } else if ((lcs[i + 1]![j] as number) >= (lcs[i]![j + 1] as number)) out.push({ op: "-", text: x[i++] as string });
    else out.push({ op: "+", text: y[j++] as string });
  }
  while (i < n) out.push({ op: "-", text: x[i++] as string });
  while (j < m) out.push({ op: "+", text: y[j++] as string });
  return out;
}

/** The changed lines with `context` lines around them, in unified-diff style (without hunk headers). */
export function renderDiff(a: string, b: string, context = 2): string {
  const d = diffLines(a, b);
  const keep = new Set<number>();
  d.forEach((l, i) => {
    if (l.op !== " ") for (let k = Math.max(0, i - context); k <= Math.min(d.length - 1, i + context); k++) keep.add(k);
  });
  const out: string[] = [];
  let gap = false;
  d.forEach((l, i) => {
    if (!keep.has(i)) {
      gap = true;
      return;
    }
    if (gap && out.length) out.push("...");
    gap = false;
    out.push(`${l.op}${l.text}`);
  });
  return out.join("\n");
}

export const hasChanges = (a: string, b: string) => a !== b;
