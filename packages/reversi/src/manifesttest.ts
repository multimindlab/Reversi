/**
 * Contract tests for manifests, run without touching any system: given a fake call and a fake result, does the manifest
 * produce the compensation arguments you expect, the verification you expect, the right plan, and the right behaviour
 * on failure, duplicates and missing prerequisites?
 */
import { expectMismatch } from "./engine.js";
import type { Registry } from "./manifest.js";
import { Sandbox, type SandboxContext } from "./simulate.js";

export interface ManifestTestCase {
  name?: string;
  tool: string;
  args?: unknown;
  /** The fake result of a successful call. */
  result?: unknown;
  /** Make the call fail with this message instead. */
  fail?: string;
  /** Run these tools first (with synthesized results) so `requires` is satisfied. Default: the manifest's `requires`. */
  after?: string[];
  /** Compensation arguments the plan must contain. */
  expect_handle?: Record<string, unknown>;
  /** The plan action kind expected for this step: compensate | skip | unrecoverable. */
  expect_plan?: string;
  /** Substring a block reason must contain (the call is expected to be refused). */
  expect_blocked?: string;
  /** Verification arguments the manifest must resolve to. */
  expect_verification?: Record<string, unknown>;
  /** What the read-back would return, and whether the manifest's `expect` should accept it. */
  verify_with?: unknown;
  expect_verified?: boolean;
  /** Run the same call a second time and expect it to be refused as a duplicate. */
  expect_duplicate?: boolean;
}

export interface ManifestTestResult {
  name: string;
  tool: string;
  ok: boolean;
  problems: string[];
}

export async function runManifestTests(reg: Registry, cases: ManifestTestCase[], ctx: Omit<SandboxContext, "registry"> = {}): Promise<{ results: ManifestTestResult[]; untested: string[] }> {
  const results: ManifestTestResult[] = [];
  for (const [i, c] of cases.entries()) {
    const problems: string[] = [];
    const name = c.name ?? `${c.tool} #${i + 1}`;
    const m = reg.get(c.tool);
    if (!m) {
      results.push({ name, tool: c.tool, ok: false, problems: [`no manifest for \`${c.tool}\``] });
      continue;
    }
    const sb = new Sandbox({ ...ctx, registry: reg }, { assume_approved: true });
    for (const pre of c.after ?? m.requires) await sb.seed({ run: "t", tool: pre });
    const judge = new Sandbox({ ...ctx, registry: reg });
    for (const pre of c.after ?? m.requires) await judge.seed({ run: "t", tool: pre });
    const verdict = await judge.call({ run: "t", tool: c.tool, args: c.args });
    if (c.expect_blocked !== undefined) {
      if (verdict.verdict === "allow") problems.push(`expected the call to be refused (${c.expect_blocked}) but it was allowed`);
      else if (!verdict.reasons.some((r) => r.includes(c.expect_blocked as string))) problems.push(`refused, but not for "${c.expect_blocked}": ${verdict.reasons.join("; ")}`);
      results.push({ name, tool: c.tool, ok: problems.length === 0, problems });
      continue;
    }
    if (verdict.verdict === "block") problems.push(`the call was refused: ${verdict.reasons.join("; ")}`);
    const step = await sb.call({ run: "t", tool: c.tool, args: c.args, result: c.result, outcome: c.fail ? "failed" : "succeeded" });
    if (step.verdict === "block") problems.push(`the call was refused: ${step.reasons.join("; ")}`);
    const plan = sb.plan("t");
    const action = plan?.actions.find((a) => a.tool === c.tool);
    if (c.fail) {
      if (action) problems.push(`a failed call should leave nothing to undo, but the plan has ${action.kind}`);
    } else {
      if (c.expect_plan && (action?.kind ?? "skip") !== c.expect_plan) problems.push(`expected plan kind ${c.expect_plan}, got ${action?.kind ?? "none"}${action?.note ? ` (${action.note})` : ""}`);
      if (c.expect_handle) {
        const got = action?.args ?? {};
        for (const [k, v] of Object.entries(c.expect_handle)) if (JSON.stringify(got[k]) !== JSON.stringify(v)) problems.push(`compensation argument \`${k}\` is ${JSON.stringify(got[k])}, expected ${JSON.stringify(v)}`);
      }
      const ver = sb.reversi.openRun([...sb.reversi.runIds()][0] as string).state().steps.find((s) => s.tool === c.tool)?.verification;
      if (c.expect_verification) {
        if (!ver) problems.push("expected a verification but the manifest declares none");
        else for (const [k, v] of Object.entries(c.expect_verification)) if (JSON.stringify(ver.args[k]) !== JSON.stringify(v)) problems.push(`verification argument \`${k}\` is ${JSON.stringify(ver.args[k])}, expected ${JSON.stringify(v)}`);
      }
      if (c.verify_with !== undefined) {
        if (!ver) problems.push("verify_with given but the manifest declares no verification");
        else {
          const mismatch = expectMismatch(c.verify_with, ver.expect);
          const accepted = mismatch === null;
          if (c.expect_verified !== undefined && accepted !== c.expect_verified) problems.push(accepted ? "the read-back was accepted but should have been rejected" : `the read-back was rejected (${mismatch}) but should have been accepted`);
        }
      }
    }
    if (c.expect_duplicate) {
      const again = await sb.call({ run: "t", tool: c.tool, args: c.args, result: c.result });
      if (again.verdict === "allow") problems.push("a second identical call was allowed; expected it to be refused as a duplicate");
      else if (!again.reasons.some((r) => r.includes("duplicate"))) problems.push(`the second call was refused, but not as a duplicate: ${again.reasons.join("; ")}`);
    }
    results.push({ name, tool: c.tool, ok: problems.length === 0, problems });
  }
  const tested = new Set(cases.map((c) => c.tool));
  return { results, untested: reg.list().filter((m) => m.effect !== "read_only" && !tested.has(m.tool)).map((m) => m.tool) };
}
