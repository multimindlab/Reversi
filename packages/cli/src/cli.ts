import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Command, CommanderError } from "commander";
import {
  Ledger,
  JsonlLedgerStore,
  ManifestError,
  dataDirPaths,
  loadRegistry,
  openLocal,
  parseJsonl,
  toJsonl,
  verifyRecords,
  type CompensationCall,
  type RollbackPlan,
} from "@multimindlab/reversi";

export interface IO {
  out: (s: string) => void;
  err: (s: string) => void;
}

const DEFAULT_IO: IO = {
  out: (s) => process.stdout.write(s + "\n"),
  err: (s) => process.stderr.write(s + "\n"),
};

class Fail extends Error {}

/** Run a shell command with the compensation call as JSON on stdin. Exit 0 means the undo succeeded. */
function runCompensator(cmd: string, call: CompensationCall, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, { shell: true, stdio: ["pipe", "pipe", "pipe"], timeout: timeoutMs });
    let stderr = "";
    child.stderr.on("data", (d) => {
      if (stderr.length < 500) stderr += String(d);
    });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`compensator ${signal ? `killed by ${signal}` : `exited ${code}`}${stderr ? `: ${stderr.trim()}` : ""}`));
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(call));
  });
}

function formatPlan(p: RollbackPlan): string[] {
  const lines = [`rollback plan for ${p.run_id}`];
  if (p.actions.length === 0) lines.push("  nothing to undo");
  for (const a of p.actions) {
    const extra =
      a.kind === "compensate"
        ? `-> ${a.compensation_tool}${a.needs_approval ? " (needs approval)" : ""}`
        : a.kind === "defer"
          ? `waits for step ${a.blocked_by?.join(", ")}`
          : (a.note ?? "");
    lines.push(`  step ${a.step}  ${a.tool}  ${a.kind}  ${extra}`.trimEnd());
  }
  lines.push(p.fully_reversible ? "fully reversible (assuming each compensation succeeds)" : "NOT fully reversible: see above");
  return lines;
}

export async function main(argv: string[], io: IO = DEFAULT_IO): Promise<number> {
  const program = new Command();
  let code = 0;
  program
    .name("reversi")
    .description("Reversibility, approvals and tamper-evident evidence for AI agent tool calls")
    .exitOverride()
    .configureOutput({ writeOut: (s) => io.out(s.replace(/\n$/, "")), writeErr: (s) => io.err(s.replace(/\n$/, "")) });

  const dataOpts = (c: Command) =>
    c
      .requiredOption("-m, --manifests <path>", "manifest file or directory (.json, .yaml)")
      .option("-d, --data <dir>", "data directory holding ledger.jsonl and runs/", "./reversi-data");

  const engine = (o: { manifests: string; data: string }) => {
    if (!existsSync(o.data)) throw new Fail(`data directory not found: ${o.data}`);
    return openLocal(o.data, loadRegistry(o.manifests));
  };

  program
    .command("validate <path>")
    .description("check manifests, including that every compensation and required tool exists")
    .action((path: string) => {
      const reg = loadRegistry(path);
      io.out(`ok: ${reg.size} tool manifest${reg.size === 1 ? "" : "s"} valid`);
    });

  program
    .command("verify <ledger>")
    .description("verify the hash chain of a ledger file (JSON Lines)")
    .action((file: string) => {
      if (!existsSync(file)) throw new Fail(`ledger not found: ${file}`);
      const v = verifyRecords(parseJsonl(readFileSync(file, "utf8")));
      if (v.ok) io.out(`ok: ${v.records} records, head ${v.head}`);
      else {
        io.err(`TAMPERED or corrupt at record ${v.seq}: ${v.error}`);
        code = 1;
      }
    });

  dataOpts(program.command("runs").description("list runs and their step counts")).action((o) => {
    const rv = engine(o);
    for (const id of rv.runIds()) {
      const s = rv.openRun(id).state();
      const un = rv.openRun(id).unresolved();
      io.out(`${id}  actor=${s.actor}  mode=${s.mode}  steps=${s.steps.length}${un.length ? `  UNRESOLVED=${un.join(",")}` : ""}`);
    }
  });

  dataOpts(program.command("plan <run_id>").description("show what a rollback would do; executes nothing"))
    .option("--json", "machine-readable output")
    .action((run_id: string, o) => {
      const p = engine(o).openRun(run_id).plan();
      if (o.json) io.out(JSON.stringify(p, null, 2));
      else for (const l of formatPlan(p)) io.out(l);
      if (!p.fully_reversible) code = 2;
    });

  dataOpts(program.command("rollback <run_id>").description("undo a run with an operator-supplied compensator command"))
    .requiredOption(
      "--compensator-cmd <cmd>",
      "shell command; receives the compensation call as JSON on stdin; exit 0 = undone",
    )
    .option("--approve-compensations", "approve compensations that require approval (operator decision)")
    .option("--timeout-ms <n>", "per-compensation timeout", "30000")
    .option("--json", "machine-readable report")
    .action(async (run_id: string, o) => {
      const reg = loadRegistry(o.manifests);
      if (!existsSync(o.data)) throw new Fail(`data directory not found: ${o.data}`);
      const rv = openLocal(o.data, reg, o.approveCompensations ? () => true : undefined);
      const timeout = Number(o.timeoutMs);
      if (!Number.isFinite(timeout) || timeout <= 0) throw new Fail("--timeout-ms must be a positive number");
      const report = await rv.openRun(run_id).rollback({
        actor: "cli",
        compensate: (c) => runCompensator(o.compensatorCmd, c, timeout),
      });
      if (o.json) io.out(JSON.stringify(report, null, 2));
      else {
        io.out(`compensated: ${report.compensated.join(", ") || "-"}`);
        io.out(`skipped (no undo needed): ${report.skipped.join(", ") || "-"}`);
        for (const f of report.failed) io.out(`FAILED step ${f.step}: ${f.error}`);
        if (report.unrecoverable.length) io.out(`cannot be undone: ${report.unrecoverable.join(", ")}`);
        if (report.unresolved.length) io.out(`outcome unknown, reconcile manually: ${report.unresolved.join(", ")}`);
        if (report.unmanifested.length) io.out(`no manifest: ${report.unmanifested.join(", ")}`);
        for (const d of report.deferred) io.out(`deferred step ${d.step}: waits for ${d.blocked_by.join(", ")}`);
        if (report.awaiting_approval.length) io.out(`awaiting approval: ${report.awaiting_approval.join(", ")}`);
        io.out(report.complete ? "rollback complete" : "rollback INCOMPLETE");
      }
      if (!report.complete) code = 2;
    });

  program
    .command("export")
    .description("print ledger records as JSON Lines (optionally one run)")
    .option("-d, --data <dir>", "data directory", "./reversi-data")
    .option("--run <run_id>", "only this run")
    .action((o) => {
      const { ledgerPath } = dataDirPaths(o.data);
      if (!existsSync(ledgerPath)) throw new Fail(`ledger not found: ${join(o.data, "ledger.jsonl")}`);
      const ledger = new Ledger(new JsonlLedgerStore(ledgerPath));
      const recs = o.run ? ledger.forRun(o.run) : ledger.records();
      const text = toJsonl(recs);
      if (text) io.out(text.replace(/\n$/, ""));
    });

  try {
    await program.parseAsync(argv, { from: "user" });
    return code;
  } catch (e) {
    if (e instanceof CommanderError) return e.exitCode === 0 ? 0 : 64;
    if (e instanceof ManifestError) {
      for (const m of e.errors) io.err(`error: ${m}`);
      return 1;
    }
    io.err(`error: ${e instanceof Error ? e.message : String(e)}`);
    return 1;
  }
}
